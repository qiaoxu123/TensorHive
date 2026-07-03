#!/usr/bin/env python3
"""机器资源池 · 伴生管理后端 (:8091)

在 TensorHive 之上提供 AutoDL 式的管理能力：读机器硬件属性、探测服务
(TensorBoard/Jupyter)、一键 SSH、首次使用建工作目录、停止服务等。

设计要点：
- 复用 TensorHive 自己的 SSH 通道 (tensorhive.core.ssh)，同一把 Ed25519 key、
  同一份 hosts_config 连所有节点，无需在目标机安装任何东西。
- 鉴权：校验 TensorHive 签发的 JWT (HS256, secret=jwt-some-secret)。
- 授权：机器级写操作要求该用户对该机器有“活跃预约”(已认领) 或为 admin。
只做安全的用户态操作；整机 reboot / 系统级配置留后续（需 sudo）。
"""
import os
import re
import time
import socket
import sqlite3
import functools

import jwt  # PyJWT (随 flask-jwt-extended 一起装)
import requests
from flask import Flask, request, jsonify, g
from flask_cors import CORS

from tensorhive.core import ssh
from tensorhive.config import SSH

# ----------------------------------------------------------------------------
JWT_SECRET = "jwt-some-secret"          # 与 TensorHive main_config 现用值一致
TH_API = "http://localhost:1111/api"    # 本机后端调 TensorHive 用 localhost
DB_PATH = os.path.expanduser("~/.config/TensorHive/database.sqlite")
HWINFO_TTL = 60                          # 硬件信息缓存秒数
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,32}$")

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}},
     allow_headers=["Authorization", "Content-Type"], methods=["GET", "POST", "OPTIONS"])

_hw_cache = {}   # host -> (ts, data)


# ---------- 工具 ----------
def primary_ip():
    """本机主 LAN IP（用于把 localhost 节点变成可从外部 SSH 的地址）。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostname()


def node_address(host):
    """localhost 节点对外要给一个用户可达的地址：优先用用户访问 UI 时用的
    Host 头（浏览器实际访问的地址），退回到本机主 IP。"""
    if host not in ("localhost", "127.0.0.1"):
        return host
    try:
        from flask import has_request_context
        if has_request_context():
            h = request.host.split(":")[0]
            if h and h not in ("localhost", "127.0.0.1"):
                return h
    except Exception:
        pass
    return primary_ip()


class ApiError(Exception):
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg


def ssh_run(host, command):
    """在指定节点执行命令，返回 stdout 字符串。host 必须是已配置节点。"""
    if host not in SSH.AVAILABLE_NODES:
        raise ApiError(404, "未知的机器: %s" % host)
    user = SSH.AVAILABLE_NODES[host]["user"]
    try:
        cfg, pcfg = ssh.build_dedicated_config_for(host, user)
        client = ssh.get_client(cfg, pcfg)
        out = ssh.run_command(client, command)
        return ssh.get_stdout(host, out) or ""
    except ApiError:
        raise
    except Exception as e:
        raise ApiError(502, "无法连接机器 %s: %s" % (host, e))


# ---------- 鉴权 / 授权 ----------
def auth_user():
    """从 Authorization 头解析并校验 JWT，返回 {id, roles, username, token}。"""
    hdr = request.headers.get("Authorization", "")
    if not hdr.startswith("Bearer "):
        raise ApiError(401, "缺少登录凭证")
    token = hdr[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise ApiError(401, "登录已过期")
    except Exception:
        raise ApiError(401, "无效的登录凭证")
    uid = payload.get("identity")
    roles = (payload.get("user_claims") or {}).get("roles", [])
    username = None
    try:
        con = sqlite3.connect(DB_PATH)
        row = con.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
        con.close()
        if row:
            username = row[0]
    except Exception:
        pass
    return {"id": uid, "roles": roles, "username": username or ("user%s" % uid), "token": token}


def th_get(path, token):
    r = requests.get(TH_API + path, headers={"Authorization": "Bearer " + token}, timeout=8)
    if r.status_code == 401:
        raise ApiError(401, "登录已过期")
    if not r.ok:
        raise ApiError(502, "TensorHive API 错误: %s" % r.status_code)
    return r.json()


def has_claim(user, host):
    """该用户是否对 host 有活跃预约（已认领），admin 直接放行。"""
    if "admin" in user["roles"]:
        return True
    resources = th_get("/resources", user["token"])
    res_host = {r["id"]: r["hostname"] for r in resources}
    reservations = th_get("/reservations", user["token"])
    now = time.time()

    def ts(v):
        # ISO UTC -> epoch
        v = v.replace("Z", "+00:00")
        try:
            import datetime
            return datetime.datetime.fromisoformat(v).timestamp()
        except Exception:
            return 0

    for r in reservations:
        if r.get("isCancelled"):
            continue
        if r.get("userId") != user["id"]:
            continue
        if res_host.get(r.get("resourceId")) != host:
            continue
        if ts(r["start"]) <= now <= ts(r["end"]):
            return True
    return False


def require_auth(fn):
    @functools.wraps(fn)
    def wrap(*a, **k):
        try:
            g.user = auth_user()
            return fn(*a, **k)
        except ApiError as e:
            return jsonify({"msg": e.msg}), e.code
    return wrap


# ---------- 解析器 ----------
def parse_hwinfo(raw):
    sec = {}
    cur = None
    for line in raw.splitlines():
        if line.startswith("@@"):
            cur = line[2:]
            sec[cur] = []
        elif cur is not None:
            sec[cur].append(line)

    def grep(section, key):
        for ln in sec.get(section, []):
            if ln.strip().startswith(key):
                return ln.split(":", 1)[1].strip()
        return None

    cpu_model = grep("CPU", "Model name") or "未知 CPU"
    cpu_cores = grep("CPU", "CPU(s)")
    mem_total = None
    if sec.get("MEM"):
        try:
            mem_total = int(sec["MEM"][0].strip())
        except Exception:
            mem_total = None
    # 磁盘：source size used target，去重 source
    disks, seen, dsize, dused = [], set(), 0, 0
    for ln in sec.get("DISK", []):
        parts = ln.split()
        if len(parts) >= 4 and parts[1].isdigit() and parts[2].isdigit():
            src, size, used, mount = parts[0], int(parts[1]), int(parts[2]), parts[3]
            # 过滤伪文件系统/小分区（efivars、/boot 等）
            if size < 5 * 1024**3 or mount.startswith(("/sys", "/boot", "/run", "/dev")):
                continue
            if src in seen:
                continue
            seen.add(src)
            disks.append({"mount": mount, "size": size, "used": used})
            dsize += size
            dused += used
    os_name = (sec.get("OS", [""])[0] or "").strip() or "Linux"
    kernel = (sec.get("KERNEL", [""])[0] or "").strip()
    gpus = []
    for ln in sec.get("GPU", []):
        if "," in ln:
            name, mem = [x.strip() for x in ln.split(",", 1)]
            gpus.append({"name": name, "memory": mem})
    return {
        "cpu_model": cpu_model, "cpu_cores": cpu_cores,
        "mem_total": mem_total, "disk_total": dsize, "disk_used": dused,
        "disks": disks, "os": os_name, "kernel": kernel, "gpus": gpus,
    }


def parse_services(raw, host):
    addr = node_address(host)
    services = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln or "grep" in ln.split()[:3]:
            continue
        m = re.match(r"^(\d+)\s+(\S+)\s+(.*)$", ln)
        if not m:
            continue
        pid, user, args = m.group(1), m.group(2), m.group(3)
        low = args.lower()
        if "tensorboard" in low:
            name = "TensorBoard"
            default = 6006
        elif "jupyter" in low:
            name = "Jupyter"
            default = 8888
        else:
            continue
        pm = re.search(r"--port[= ](\d+)", args)
        port = int(pm.group(1)) if pm else default
        services.append({
            "name": name, "pid": int(pid), "owner": user, "port": port,
            "url": "http://%s:%d" % (addr, port),
        })
    return services


# ---------- 路由 ----------
@app.route("/ctl/health")
def health():
    return jsonify({"ok": True, "nodes": list(SSH.AVAILABLE_NODES.keys())})


@app.route("/ctl/machines/<host>/hwinfo")
@require_auth
def hwinfo(host):
    if host not in SSH.AVAILABLE_NODES:
        return jsonify({"msg": "未知的机器"}), 404
    now = time.time()
    if host in _hw_cache and now - _hw_cache[host][0] < HWINFO_TTL:
        return jsonify(_hw_cache[host][1])
    cmd = ("echo '@@CPU'; lscpu; "
           "echo '@@MEM'; free -b | awk 'NR==2{print $2}'; "
           "echo '@@DISK'; df -B1 -x tmpfs -x devtmpfs -x overlay -x squashfs "
           "--output=source,size,used,target 2>/dev/null | tail -n +2; "
           "echo '@@OS'; . /etc/os-release 2>/dev/null; echo \"$PRETTY_NAME\"; "
           "echo '@@KERNEL'; uname -r; "
           "echo '@@GPU'; nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null")
    try:
        data = parse_hwinfo(ssh_run(host, cmd))
    except ApiError as e:
        return jsonify({"msg": e.msg}), e.code
    _hw_cache[host] = (now, data)
    return jsonify(data)


@app.route("/ctl/machines/<host>/services")
@require_auth
def services(host):
    cmd = ("ps -eo pid,user:32,args 2>/dev/null | "
           "grep -E 'tensorboard|jupyter' | grep -v grep")
    try:
        data = parse_services(ssh_run(host, cmd), host)
    except ApiError as e:
        return jsonify({"msg": e.msg}), e.code
    return jsonify(data)


@app.route("/ctl/machines/<host>/ssh")
@require_auth
def ssh_cmd(host):
    if host not in SSH.AVAILABLE_NODES:
        return jsonify({"msg": "未知的机器"}), 404
    node = SSH.AVAILABLE_NODES[host]
    user, port, addr = node["user"], node.get("port", 22), node_address(host)
    cmd = "ssh %s@%s%s" % (user, addr, ("" if port == 22 else " -p %d" % port))
    return jsonify({"command": cmd, "user": user, "host": addr, "port": port})


@app.route("/ctl/machines/<host>/workspace/ensure", methods=["POST"])
@require_auth
def workspace_ensure(host):
    user = g.user
    if not USERNAME_RE.match(user["username"]):
        return jsonify({"msg": "非法用户名"}), 400
    if not has_claim(user, host):
        return jsonify({"msg": "请先预约(认领)该机器后再使用"}), 403
    path = "~/workspace/%s" % user["username"]
    try:
        out = ssh_run(host, "mkdir -p %s && chmod 700 %s && echo OK:$(cd %s && pwd)"
                      % (path, path, path))
    except ApiError as e:
        return jsonify({"msg": e.msg}), e.code
    real = out.strip().split("OK:", 1)[-1].strip() if "OK:" in out else path
    return jsonify({"ok": True, "path": real})


@app.route("/ctl/machines/<host>/services/<int:pid>/stop", methods=["POST"])
@require_auth
def service_stop(host, pid):
    user = g.user
    if not has_claim(user, host):
        return jsonify({"msg": "请先预约(认领)该机器后再操作"}), 403
    # 只允许停止我们探测到的 tensorboard/jupyter 服务
    detected = parse_services(ssh_run(
        host, "ps -eo pid,user:32,args 2>/dev/null | grep -E 'tensorboard|jupyter' | grep -v grep"), host)
    if pid not in [s["pid"] for s in detected]:
        return jsonify({"msg": "该 PID 不是可管理的服务"}), 400
    try:
        ssh_run(host, "kill %d" % pid)
    except ApiError as e:
        return jsonify({"msg": e.msg}), e.code
    return jsonify({"ok": True})


if __name__ == "__main__":
    print("[机器资源池] 管理后端: http://0.0.0.0:8091  nodes=%s" % list(SSH.AVAILABLE_NODES.keys()))
    app.run(host="0.0.0.0", port=8091, threaded=True)
