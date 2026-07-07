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
import datetime
import psycopg2
import psycopg2.extras
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
def get_db():
    """PostgreSQL connection (Docker env or local defaults)."""
    return psycopg2.connect(
        host=os.environ.get('TH_DB_HOST', '127.0.0.1'),
        port=os.environ.get('TH_DB_PORT', '5432'),
        dbname=os.environ.get('TH_DB_NAME', 'tensorhive_db'),
        user=os.environ.get('TH_DB_USER', 'tensorhive_app'),
        password=os.environ.get('TH_DB_PASSWORD', ''),
    )
HWINFO_TTL = 60                          # 硬件信息缓存秒数
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,32}$")

def db_fetch(sql, params=None):
    """Run a SELECT and return all rows."""
    con = get_db()
    cur = con.cursor()
    cur.execute(sql, params or ())
    rows = cur.fetchall()
    con.close()
    return rows

def db_fetch_one(sql, params=None):
    """Run a SELECT and return first row or None."""
    rows = db_fetch(sql, params)
    return rows[0] if rows else None

def db_exec(sql, params=None):
    """Run INSERT/UPDATE/DELETE, commit, close."""
    con = get_db()
    cur = con.cursor()
    cur.execute(sql, params or ())
    con.commit()
    con.close()

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
    node = SSH.AVAILABLE_NODES[host]
    user = node["user"]
    port = node.get("port", 22)
    real_host = node.get("host", host)  # Actual IP to connect to
    key = str(SSH.KEY_FILE).replace("~", os.path.expanduser("~"))
    # Try parallel-ssh first, fall back to OpenSSH CLI
    try:
        cfg, pcfg = ssh.build_dedicated_config_for(host, user)
        client = ssh.get_client(cfg, pcfg)
        out = ssh.run_command(client, command)
        return ssh.get_stdout(host, out) or ""
    except ApiError:
        raise
    except Exception:
        pass  # Fall through to CLI
    # Fallback: use ssh command-line (handles non-standard SSH servers)
    import subprocess
    try:
        result = subprocess.run(
            ["ssh", "-i", key, "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15",
             "-p", str(port), f"{user}@{real_host}", command],
            capture_output=True, text=True, timeout=20)
        if result.returncode == 0:
            return result.stdout.strip()
        raise ApiError(502, "SSH 执行失败: %s" % result.stderr.strip()[:200])
    except subprocess.TimeoutExpired:
        raise ApiError(502, "SSH 连接超时")
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
        row = db_fetch_one("SELECT username FROM users WHERE id=%s", (uid,))
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
# ── 密码验证（兼容 TensorHive 和 Discourse 两种 pbkdf2-sha256 格式） ──
def verify_pw(password, stored_hash):
    """Verify password against pbkdf2-sha256 hash (supports both TH and Discourse formats)."""
    from passlib.hash import pbkdf2_sha256 as sha256
    import hashlib, base64
    try:
        # Try passlib native format first ($pbkdf2-sha256$29000$salt$hash)
        return sha256.verify(password, stored_hash)
    except ValueError:
        pass
    # Fallback: Discourse format $pbkdf2-sha256$i=600000,l=32$salt$hash
    try:
        parts = stored_hash.split('$')
        if len(parts) >= 5 and parts[1] == 'pbkdf2-sha256':
            # Parse params from part[2]: i=600000,l=32
            params = {}
            for p in parts[2].split(','):
                k, v = p.split('=')
                params[k] = int(v)
            salt = base64.b64decode(parts[3])
            expected = bytes.fromhex(parts[4])
            dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt,
                                     params.get('i', 600000), dklen=params.get('l', 32))
            return dk == expected
    except Exception:
        pass
    return False

# ── 登录（支持用户名或邮箱） ──
@app.route("/ctl/login", methods=["POST"])
def login():
    import datetime
    body = request.get_json(silent=True) or {}
    login_id = (body.get("username") or body.get("email") or "").strip()
    password = (body.get("password") or "").strip()
    if not login_id or not password:
        return jsonify({"msg": "请填写用户名/邮箱和密码"}), 400

    # Try username first, then email
    row = db_fetch_one("SELECT id, username, _hashed_password FROM users WHERE username=%s", (login_id,))
    if not row:
        row = db_fetch_one("SELECT id, username, _hashed_password FROM users WHERE email=%s", (login_id,))
    if not row:
        return jsonify({"msg": "用户名或邮箱不存在"}), 401
    uid, username, pw_hash = row
    if not verify_pw(password, pw_hash):
        return jsonify({"msg": "密码错误"}), 401

    # Get roles
    roles = [r[0] for r in db_fetch("SELECT name FROM roles WHERE user_id=%s", (uid,))]
    # Generate JWT matching TensorHive format
    now = datetime.datetime.utcnow()
    access_payload = {
        "iat": now, "nbf": now, "jti": os.urandom(16).hex(),
        "exp": now + datetime.timedelta(minutes=30),
        "identity": uid, "fresh": True, "type": "access",
        "user_claims": {"roles": roles}
    }
    refresh_payload = {
        "iat": now, "nbf": now, "jti": os.urandom(16).hex(),
        "exp": now + datetime.timedelta(days=7),
        "identity": uid, "type": "refresh"
    }
    raw_access = jwt.encode(access_payload, JWT_SECRET, algorithm="HS256")
    raw_refresh = jwt.encode(refresh_payload, JWT_SECRET, algorithm="HS256")
    access_token = raw_access.decode('utf-8') if isinstance(raw_access, bytes) else raw_access
    refresh_token = raw_refresh.decode('utf-8') if isinstance(raw_refresh, bytes) else raw_refresh
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "msg": "Logged in as %s" % username
    })

# ── 在线用户检测 ──
@app.route("/ctl/machines/<host>/users")
@require_auth
def machine_users(host):
    """Detect active users on a machine by checking running processes."""
    # Get non-system users with active Python/Cuda/Shell processes
    cmd = (
        "ps -eo user:20 --no-headers 2>/dev/null | "
        "awk '!/^(root|nobody|www-data|messagebus|syslog|_|systemd|daemon|"
        "cups|rtkit|gnome|message|lp|nvidia|kernoops|avahi|xrdp|polkitd|colord|"
        "dhcpcd|dnsmasq|gdm|sd|ntp|uuidd|usbmux|whoopsie|tss|fwupd|speech|ollama|sddm|geoclue)"
        "/ && !/^[0-9]+$/ {print $1}' | sort -u"
    )
    try:
        out = ssh_run(host, cmd)
        users = []
        if out:
            for u in out.strip().split('\n'):
                u = u.strip()
                if u and u[0] != '_' and not u.startswith('systemd'):
                    users.append({"username": u})
        out2 = ssh_run(host, "who -u 2>/dev/null | awk '{print $1}' | sort -u || true")
        if out2:
            for u in out2.strip().split('\n'):
                u = u.strip()
                if u and u not in [x["username"] for x in users]:
                    users.append({"username": u})
        return jsonify(users)
    except ApiError:
        return jsonify([])

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
    body = request.get_json(silent=True) or {}
    target_user = (body.get("username") or user["username"]).strip()
    if not USERNAME_RE.match(target_user):
        return jsonify({"msg": "非法用户名"}), 400
    if not has_claim(user, host):
        return jsonify({"msg": "请先预约(认领)该机器后再使用"}), 403
    path = "~/workspace/%s" % target_user
    # Also create the actual user account if needed
    cmd = (
        "id {u} 2>/dev/null || sudo useradd -m -s /bin/bash {u} 2>/dev/null; "
        "mkdir -p {p} && chown -R {u}:{u} {p} 2>/dev/null || mkdir -p {p} && chmod 700 {p}; "
        "echo OK:$(cd {p} 2>/dev/null && pwd || echo {p})"
    ).format(u=target_user, p=path)
    try:
        out = ssh_run(host, cmd)
    except ApiError as e:
        return jsonify({"msg": e.msg}), e.code
    real = out.strip().split("OK:", 1)[-1].strip() if "OK:" in out else path
    return jsonify({"ok": True, "path": real, "user": target_user})

# ── 结束当前预约 ──
@app.route("/ctl/machines/<host>/end_reservation", methods=["POST"])
@require_auth
def end_reservation(host):
    user = g.user
    now = datetime.datetime.utcnow().isoformat() + "Z"
    # Map hostname to resource IDs
    resources = th_get("/resources", user["token"])
    res_host = {r["id"]: r["hostname"] for r in resources}
    host_resource_ids = [rid for rid, h in res_host.items() if h == host]
    reservations = th_get("/reservations", user["token"])
    from dateutil.parser import parse
    for r in reservations:
        if r.get("isCancelled"): continue
        if r.get("userId") != user["id"]: continue
        if r.get("resourceId") not in host_resource_ids: continue
        try:
            now_aware = datetime.datetime.now(datetime.timezone.utc)
            if parse(r["start"]) <= now_aware <= parse(r["end"]):
                r2 = requests.put(TH_API + "/reservations/" + str(r["id"]),
                    headers={"Authorization": "Bearer "+user["token"], "Content-Type": "application/json"},
                    json={"end": now}, timeout=10)
                if r2.ok: return jsonify({"msg": "已结束使用"})
        except: pass
    return jsonify({"msg": "没有找到进行中的预约"}), 404


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


# ---------- 用户 / 权限管理（仅管理员） ----------
def is_admin(user):
    return "admin" in (user.get("roles") or [])


@app.route("/ctl/users")
@require_auth
def list_users():
    if not is_admin(g.user):
        return jsonify({"msg": "需要管理员权限"}), 403
    rows = db_fetch("SELECT id, username, email, created_at, ssh_pubkey FROM users ORDER BY id")
    roles = {}
    for uid, name in db_fetch("SELECT user_id, name FROM roles"):
        roles.setdefault(uid, []).append(name)
    out = [{"id": r[0], "username": r[1], "email": r[2], "created_at": r[3],
            "ssh_pubkey": r[4] or "",
            "roles": roles.get(r[0], []), "is_admin": "admin" in roles.get(r[0], [])}
           for r in rows]
    return jsonify(out)


@app.route("/ctl/users/<int:uid>/admin", methods=["POST"])
@require_auth
def set_admin(uid):
    if not is_admin(g.user):
        return jsonify({"msg": "需要管理员权限"}), 403
    value = bool((request.get_json(silent=True) or {}).get("value"))
    if not db_fetch_one("SELECT 1 FROM users WHERE id=%s", (uid,)):
        return jsonify({"msg": "用户不存在"}), 404
    has = db_fetch_one("SELECT 1 FROM roles WHERE user_id=%s AND name='admin'", (uid,))
    if not value:  # 取消管理员
        if uid == g.user["id"]:
            return jsonify({"msg": "不能取消自己的管理员权限"}), 400
        admin_cnt = db_fetch_one("SELECT COUNT(DISTINCT user_id) FROM roles WHERE name='admin'")[0]
        if has and admin_cnt <= 1:
            return jsonify({"msg": "系统至少需要保留一个管理员"}), 400
        db_exec("DELETE FROM roles WHERE user_id=%s AND name='admin'", (uid,))
    else:          # 设为管理员
        if not has:
            db_exec("INSERT INTO roles(name, user_id) VALUES('admin', %s)", (uid,))
        if not db_fetch_one("SELECT 1 FROM roles WHERE user_id=%s AND name='user'", (uid,)):
            db_exec("INSERT INTO roles(name, user_id) VALUES('user', %s)", (uid,))
    return jsonify({"ok": True, "is_admin": value,
                    "note": "对方将在下次登录或令牌刷新(约1分钟内)后生效"})

# ── 修改自己的密码 ──
@app.route("/ctl/password", methods=["POST"])
@require_auth
def change_my_password():
    from passlib.hash import pbkdf2_sha256 as sha256
    body = request.get_json(silent=True) or {}
    old_pw = (body.get("old_password") or "").strip()
    new_pw = (body.get("new_password") or "").strip()
    if not old_pw or not new_pw:
        return jsonify({"msg": "请填写旧密码和新密码"}), 400
    if len(new_pw) < 8:
        return jsonify({"msg": "新密码至少8个字符"}), 400
    row = db_fetch_one("SELECT _hashed_password FROM users WHERE id=%s", (g.user["id"],))
    if not row or not verify_pw(old_pw, row[0]):
        return jsonify({"msg": "旧密码不正确"}), 403
    db_exec("UPDATE users SET _hashed_password=%s WHERE id=%s", (sha256.hash(new_pw), g.user["id"]))
    return jsonify({"msg": "密码已更新"})

# ── 创建用户 (admin) ──
@app.route("/ctl/users", methods=["POST"])
@require_auth
def create_user():
    if not is_admin(g.user):
        return jsonify({"msg": "需要管理员权限"}), 403
    from passlib.hash import pbkdf2_sha256 as sha256
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    email = (body.get("email") or "").strip()
    password = (body.get("password") or "").strip()
    admin = bool(body.get("is_admin"))
    if not username or not USERNAME_RE.match(username):
        return jsonify({"msg": "用户名格式无效（1-32位字母数字_.-）"}), 400
    if not email or "@" not in email:
        return jsonify({"msg": "请填写有效邮箱"}), 400
    if len(password) < 8:
        return jsonify({"msg": "密码至少8个字符"}), 400
    if db_fetch_one("SELECT 1 FROM users WHERE username=%s", (username,)):
        return jsonify({"msg": "用户名已存在"}), 409
    db_exec("INSERT INTO users(username, email, created_at, _hashed_password) VALUES(%s,%s,NOW(),%s)",
            (username, email, sha256.hash(password)))
    new_id = db_fetch_one("SELECT id FROM users WHERE username=%s", (username,))[0]
    db_exec("INSERT INTO roles(name, user_id) VALUES('user',%s)", (new_id,))
    if admin:
        db_exec("INSERT INTO roles(name, user_id) VALUES('admin',%s)", (new_id,))
    return jsonify({"msg": "用户 %s 创建成功" % username, "id": new_id}), 201

# ── 管理员重置用户密码 ──
@app.route("/ctl/users/<int:uid>/password", methods=["POST"])
@require_auth
def reset_user_password(uid):
    if not is_admin(g.user):
        return jsonify({"msg": "需要管理员权限"}), 403
    from passlib.hash import pbkdf2_sha256 as sha256
    body = request.get_json(silent=True) or {}
    new_pw = (body.get("password") or "").strip()
    if len(new_pw) < 8:
        return jsonify({"msg": "新密码至少8个字符"}), 400
    if not db_fetch_one("SELECT 1 FROM users WHERE id=%s", (uid,)):
        return jsonify({"msg": "用户不存在"}), 404
    db_exec("UPDATE users SET _hashed_password=%s WHERE id=%s", (sha256.hash(new_pw), uid))
    return jsonify({"msg": "密码已重置"})

# ── 删除用户 (admin) ──
@app.route("/ctl/users/<int:uid>", methods=["DELETE"])
@require_auth
def delete_user(uid):
    if not is_admin(g.user):
        return jsonify({"msg": "需要管理员权限"}), 403
    if uid == g.user["id"]:
        return jsonify({"msg": "不能删除自己"}), 400
    user_row = db_fetch_one("SELECT username FROM users WHERE id=%s", (uid,))
    if not user_row:
        return jsonify({"msg": "用户不存在"}), 404
    db_exec("DELETE FROM roles WHERE user_id=%s", (uid,))
    db_exec("DELETE FROM user2group WHERE user_id=%s", (uid,))
    db_exec("DELETE FROM users WHERE id=%s", (uid,))
    return jsonify({"msg": "用户 %s 已删除" % user_row[0]})

# ── 一键安装所有用户公钥到指定机器 ──
def _install_keys_to_host(host, dry_run=False):
    """Push all registered SSH keys to a host's authorized_keys. Returns (added, errors)."""
    keys = db_fetch("SELECT username, ssh_pubkey FROM users WHERE ssh_pubkey IS NOT NULL AND ssh_pubkey != ''")
    if not keys:
        return 0, ["没有用户登记 SSH 公钥"]
    user = SSH.AVAILABLE_NODES[host]["user"]
    # Build the authorized_keys block
    block = "\n".join("# tensorhive:{}".format(u) + "\n" + k for u, k in keys)
    # Read existing authorized_keys, append only new keys
    cmd = (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && "
        "python3 -c \"\n"
        "import sys; existing = set(open('$HOME/.ssh/authorized_keys').read().splitlines());\n"
        r"new_keys = '''{block}'''.splitlines();\n"
        "to_add = [l for l in new_keys if l.strip() and l not in existing and not l.startswith('#')];\n"
        "for l in to_add:\n"
        "    existing.add(l);\n"
        "if to_add:\n"
        "    open('$HOME/.ssh/authorized_keys','w').write(chr(10).join(sorted(existing)));\n"
        "    print(f'added:{{len(to_add)}}');\n"
        "else:\n"
        "    print('no_new');\n"
        "\""
    ).format(block=block.replace("'", r"'\''"))
    if dry_run:
        return len(keys), ["dry_run: {} keys would be pushed".format(len(keys))]
    try:
        out = ssh_run(host, cmd)
        return len(keys), [out.strip() or "ok"]
    except ApiError as e:
        return 0, [e.msg]

@app.route("/ctl/machines/<host>/install_keys", methods=["POST"])
@require_auth
def install_keys(host):
    if not is_admin(g.user):
        return jsonify({"msg": "需要管理员权限"}), 403
    if host not in SSH.AVAILABLE_NODES:
        return jsonify({"msg": "未知机器: %s" % host}), 404
    added, msgs = _install_keys_to_host(host)
    return jsonify({"added": added, "messages": msgs})

@app.route("/ctl/install_all_keys", methods=["POST"])
@require_auth
def install_all_keys():
    if not is_admin(g.user):
        return jsonify({"msg": "需要管理员权限"}), 403
    results = {}
    for host in SSH.AVAILABLE_NODES:
        added, msgs = _install_keys_to_host(host)
        results[host] = {"added": added, "messages": msgs}
    return jsonify(results)

# ── SSH 公钥管理 ──
KEY_RE = re.compile(r"^(ssh-(?:ed25519|rsa|ed448|ecdsa-[a-z0-9-]+)|ecdsa-[a-z0-9-]+)\s+\S+\s+\S.*$")

@app.route("/ctl/sshkey", methods=["GET", "PUT"])
@require_auth
def my_ssh_key():
    if request.method == "GET":
        row = db_fetch_one("SELECT ssh_pubkey FROM users WHERE id=%s", (g.user["id"],))
        return jsonify({"ssh_pubkey": (row[0] or "") if row else ""})
    # PUT
    body = request.get_json(silent=True) or {}
    pubkey = (body.get("ssh_pubkey") or "").strip()
    if not pubkey:
        return jsonify({"msg": "请提供 SSH 公钥"}), 400
    if not KEY_RE.match(pubkey):
        return jsonify({"msg": "公钥格式无效，应为 ssh-ed25519/ssh-rsa ... comment"}), 400
    db_exec("UPDATE users SET ssh_pubkey=%s WHERE id=%s", (pubkey, g.user["id"]))
    return jsonify({"msg": "SSH 公钥已保存"})

# ── 批量导出所有用户的 authorized_keys (admin) ──
@app.route("/ctl/authorized_keys")
@require_auth
def authorized_keys_export():
    if not is_admin(g.user):
        return jsonify({"msg": "需要管理员权限"}), 403
    rows = db_fetch("SELECT username, ssh_pubkey FROM users WHERE ssh_pubkey IS NOT NULL AND ssh_pubkey != ''")
    lines = ["# {}@{}\n{}".format(r[0], socket.gethostname(), r[1]) for r in rows]
    return jsonify({"text": "\n".join(lines), "count": len(rows)})

# ── 科研进度追踪 ──
@app.route("/ctl/progress")
@require_auth
def get_progress():
    """Get progress entries with caching. ?user=name&days=365"""
    username = request.args.get("user", "")
    days = int(request.args.get("days", 365))
    if username:
        rows = db_fetch("""
            SELECT p.id, u.username, p.entry_date, p.content
            FROM progress_entries p JOIN users u ON u.id=p.user_id
            WHERE u.username=%s
            ORDER BY p.entry_date DESC, p.id DESC LIMIT 500
        """, (username,))
    else:
        rows = db_fetch("""
            SELECT p.id, u.username, p.entry_date, p.content
            FROM progress_entries p JOIN users u ON u.id=p.user_id
            ORDER BY p.entry_date DESC, p.id DESC LIMIT 2000
        """, ())
    out = [{"id": r[0], "username": r[1], "date": r[2], "content": r[3]} for r in rows]
    return jsonify(out)

@app.route("/ctl/progress", methods=["POST"])
@require_auth
def add_progress():
    """Add a progress entry for the current user."""
    body = request.get_json(silent=True) or {}
    entry_date = (body.get("date") or "").strip()
    content = (body.get("content") or "").strip()
    if not content:
        return jsonify({"msg": "请填写进展内容"}), 400
    if not entry_date:
        entry_date = datetime.datetime.now().strftime("%m-%d")
    # Allow admin to post for any user
    target_uid = g.user["id"]
    if is_admin(g.user) and body.get("username"):
        row = db_fetch_one("SELECT id FROM users WHERE username=%s", (body["username"].strip(),))
        if row:
            target_uid = row[0]
    db_exec("INSERT INTO progress_entries(user_id, entry_date, content) VALUES(%s,%s,%s)",
            (target_uid, entry_date, content))
    return jsonify({"msg": "已记录"}), 201

@app.route("/ctl/progress/<int:eid>", methods=["PUT", "DELETE"])
@require_auth
def update_progress(eid):
    row = db_fetch_one("SELECT user_id FROM progress_entries WHERE id=%s", (eid,))
    if not row:
        return jsonify({"msg": "记录不存在"}), 404
    if row[0] != g.user["id"] and not is_admin(g.user):
        return jsonify({"msg": "只能编辑自己的记录"}), 403
    if request.method == "DELETE":
        db_exec("DELETE FROM progress_entries WHERE id=%s", (eid,))
        return jsonify({"msg": "已删除"})
    body = request.get_json(silent=True) or {}
    content = (body.get("content") or "").strip()
    entry_date = (body.get("date") or "").strip()
    if not content:
        return jsonify({"msg": "请填写进展内容"}), 400
    if entry_date:
        db_exec("UPDATE progress_entries SET content=%s, entry_date=%s WHERE id=%s", (content, entry_date, eid))
    else:
        db_exec("UPDATE progress_entries SET content=%s WHERE id=%s", (content, eid))
    return jsonify({"msg": "已更新"})

# ── 成员分组列表 ──
GROUPS = {
    "孙庚": ["liboshen","hbx","jinkj","guojinpeng","yangxiang","zcx","qfy","XiaoYujie","oujinfeng","Firework","qijia","wangy","sunzemin"],
    "孙泽敏": ["junan-zhao","heyuxuan","yixian_w","qwh","chensiyi","yuliqiang"],
    "王爱民": ["wenjh25","GYY"],
    "何龙": ["yangxiang","zcx","wenjh25","wangy"],
    "秦玮鸿": ["qin","qfy","GYY"],
}

@app.route("/ctl/groups")
@require_auth
def get_groups():
    """Return group structure for the sidebar."""
    result = {}
    for advisor, members in GROUPS.items():
        member_data = []
        for name in members:
            row = db_fetch_one("SELECT id FROM users WHERE username=%s", (name,))
            has_progress = False
            if row:
                cnt = db_fetch_one("SELECT COUNT(*) FROM progress_entries WHERE user_id=%s AND entry_date >= %s",
                                   (row[0], datetime.datetime.now().strftime("%m-%d")))
                has_progress = (cnt[0] if cnt else 0) > 0
            member_data.append({"name": name, "has_progress": has_progress})
        result[advisor] = member_data
    return jsonify(result)

# ── 论文追踪（从 acta PG 库读取） ──
ACTA_DB_HOST = os.environ.get('TH_DB_HOST', 'postgresql')  # Docker DNS for PG in 1panel-network
ACTA_DB = dict(host=ACTA_DB_HOST, port=5432, user='user_Q8mjjw', password='password_kfwteh')

def _acta_conn():
    return psycopg2.connect(host=ACTA_DB['host'], port=ACTA_DB['port'],
                             user=ACTA_DB['user'], password=ACTA_DB['password'],
                             dbname='acta')

# Match Acta author names to TensorHive usernames
_AUTHOR_MAP = {
    '乔旭': 'xqiao', '孙泽敏': 'sunzemin', '孙庚': 'sunzemin',
    '王爱民': 'wenjh25', '何龙': 'wenjh25', '秦玮鸿': 'qfy',
    '张程翔': 'zcx', '何博轩': 'hbx', '靳康杰': 'jinkj',
    '郭锦鹏': 'guojinpeng', '赵俊安': 'junan-zhao', '杨湘': 'yangxiang',
    '温家昊': 'wenjh25', '邱丰艺': 'qfy', '高宇阳': 'GYY',
    '肖宇杰': 'XiaoYujie', '秦振华': 'qin', '区锦锋': 'oujinfeng',
    '邢亚欣': 'Firework', '祁嘉': 'qijia', '王颖': 'wangy',
    '何宇轩': 'heyuxuan', '王逸娴': 'yixian_w', '陈思艺': 'chensiyi',
    '于立强': 'yuliqiang',
}

def _get_paper_status_label(status):
    labels = {
        'writing': '写作中', 'submitted': '已投稿', 'under_review': '审稿中',
        'major_revision': '大修', 'minor_revision': '小修',
        'accepted': '已接收', 'rejected': '被拒', 'withdrawn': '已撤回',
        'camera_ready': '终稿中', 'published': '已发表',
    }
    return labels.get(status or '', status or '未知')

def _get_paper_status_color(status):
    colors = {
        'writing': 'var(--accent)', 'submitted': '#4a86e8', 'under_review': '#e69138',
        'major_revision': '#e55', 'minor_revision': '#f6b26b',
        'accepted': '#6aa84f', 'rejected': '#999', 'withdrawn': '#999',
        'camera_ready': '#6aa84f', 'published': '#6aa84f',
    }
    return colors.get(status or '', '#999')

@app.route("/ctl/papers")
@require_auth
def list_papers():
    """Get all papers with author matching and submission status. ?user=name"""
    username = request.args.get("user", "")
    try:
        conn = _acta_conn()
        cur = conn.cursor()
        if username:
            # Find papers where this user is an author
            cur.execute("""
                SELECT id, title, target_venue, status, authors, my_role,
                       started_date, abstract, notes, created_at
                FROM papers WHERE deleted_at IS NULL AND authors LIKE %s
                ORDER BY created_at DESC LIMIT 50
            """, (f'%{username}%',))
        else:
            cur.execute("""
                SELECT id, title, target_venue, status, authors, my_role,
                       started_date, abstract, notes, created_at
                FROM papers WHERE deleted_at IS NULL
                ORDER BY created_at DESC LIMIT 100
            """)
        papers = []
        for r in cur.fetchall():
            authors_raw = (r[4] or '').strip()
            # Parse authors (handles both "Chinese, English" and "Chinese, 中文" formats)
            authors = []
            for part in authors_raw.replace(',;', ',').replace('; ', ',').split(','):
                part = part.strip()
                if not part: continue
                # Check if it's Western "Last, First" format
                if ' ' in part and not any('一' <= c <= '鿿' for c in part):
                    authors.append(part)
                else:
                    authors.append(part)
            author_names = []
            for a in authors:
                mapped = _AUTHOR_MAP.get(a, None)
                # Try fuzzy match for Western format "Zemin Sun" → sunzemin
                if not mapped:
                    for cn_name, uname in _AUTHOR_MAP.items():
                        if cn_name and cn_name.lower() in a.lower().replace(',', '').strip():
                            mapped = uname
                            break
                author_names.append({"name": a, "username": mapped})
            # Get latest submission
            cur2 = conn.cursor()
            cur2.execute("""
                SELECT venue_name, round, decision, submitted_date, decision_date
                FROM paper_submissions WHERE paper_id=%s AND deleted_at IS NULL
                ORDER BY round DESC LIMIT 1
            """, (r[0],))
            submission = cur2.fetchone()
            cur2.close()
            status = r[3] or ''
            papers.append({
                "id": r[0], "title": r[1] or '未命名', "venue": r[2] or '',
                "status": status, "status_label": _get_paper_status_label(status),
                "status_color": _get_paper_status_color(status),
                "authors": author_names, "my_role": r[5], "started": r[6] or '',
                "abstract": r[7] or '', "notes": r[8] or '',
                "submission": {
                    "venue_name": submission[0] if submission else '',
                    "round": submission[1] if submission else 0,
                    "decision": submission[2] if submission else '',
                    "submitted_date": submission[3] if submission else '',
                    "decision_date": submission[4] if submission else '',
                } if submission else None
            })
        conn.close()
        return jsonify(papers)
    except Exception as e:
        return jsonify({"msg": str(e)}), 500

@app.route("/ctl/papers/<pid>")
@require_auth
def paper_detail(pid):
    try:
        conn = _acta_conn()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, title, target_venue, status, authors, my_role,
                   started_date, abstract, notes, created_at
            FROM papers WHERE id=%s AND deleted_at IS NULL
        """, (pid,))
        r = cur.fetchone()
        if not r:
            return jsonify({"msg": "论文不存在"}), 404
        # Get all submissions
        cur.execute("""
            SELECT id, venue_name, round, decision, submitted_date, decision_date, reviewer_summary
            FROM paper_submissions WHERE paper_id=%s AND deleted_at IS NULL
            ORDER BY round ASC
        """, (pid,))
        submissions = [{
            "id": s[0], "venue": s[1], "round": s[2], "decision": s[3],
            "submitted": s[4], "decided_at": s[5],
        } for s in cur.fetchall()]
        conn.close()
        return jsonify({
            "id": r[0], "title": r[1], "venue": r[2], "status": r[3],
            "status_label": _get_paper_status_label(r[3]),
            "status_color": _get_paper_status_color(r[3]),
            "authors": r[4] or '', "my_role": r[5],
            "started": r[6], "abstract": r[7] or '', "notes": r[8] or '',
            "submissions": submissions,
        })
    except Exception as e:
        return jsonify({"msg": str(e)}), 500


if __name__ == "__main__":
    print("[机器资源池] 管理后端: http://0.0.0.0:8091  nodes=%s" % list(SSH.AVAILABLE_NODES.keys()))
    app.run(host="0.0.0.0", port=8091, threaded=True)
