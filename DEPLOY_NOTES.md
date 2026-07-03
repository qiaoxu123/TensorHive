# TensorHive 部署与运维手册（本地 fork）

机器租赁/共享统一管理面板。所有人登录同一个 Web 界面，实时看到有哪些机器、CPU/GPU/内存占用、谁在用，并可"认领"（reservation）机器。节点**纯 SSH 接入，目标机零安装**。

- Fork 仓库：`qiaoxu123/TensorHive`（upstream = `roscisz/TensorHive`）
- 本地源码：`~/Workspace/tensorhive`（editable 安装，改代码即生效）
- 运行环境：conda env **`tensorhive`**（Python 3.8）
- 配置目录：`~/.config/TensorHive/`（`main_config.ini` / `hosts_config.ini` / `database.sqlite` / `ssh_key` / `logs/`）

## 访问地址与账号

| 项 | 值 |
|---|---|
| Web 界面（大家用这个） | http://<本机局域网IP>:5000 |
| API / Swagger | http://<本机局域网IP>:1111/api/ui/ |
| 管理员 | 用户名 `xqiao` / 密码见本机私密记录（**勿入库**） |
| 演示普通用户 | 用户名 `alice` / 密码见本机私密记录 |

> 本仓库为公开 fork，切勿把真实密码/内网地址写入文档。默认账号密码只记录在本机，请尽快改掉；`alice` 仅用于验证多用户，可删除。

## 启动 / 停止 / 重启

```bash
source $HOME/anaconda3/etc/profile.d/conda.sh && conda activate tensorhive

# 启动（后台，日志写入 logs/run.log）
cd ~/Workspace/tensorhive
nohup tensorhive > ~/.config/TensorHive/logs/run.log 2>&1 &

# 查看状态 / 日志
ss -tlnp | grep -E ':5000|:1111'
tail -f ~/.config/TensorHive/logs/run.log

# 停止
pkill -f 'bin/tensorhive'
```

> 修改 `hosts_config.ini`（新增/删除机器）后**必须重启** TensorHive 才生效——节点列表在启动时读取。

## ⭐ 新增一台资源机器（标准流程）

> 场景：你把某台机器的 SSH 给我（`user@host`、端口），我照下面做。目标机只需能 SSH 登录 + 有 `nvidia-smi`（无 GPU 也能接，只显示 CPU/内存）。

**1. 拿到 TensorHive 的公钥**（所有节点共用这一把 key）：
```bash
conda activate tensorhive
tensorhive key          # 复制输出里的 `ssh-ed25519 AAAA... xqiao@xqiao-desk` 整行
```

**2. 把这把公钥装到目标机**（在目标机上、用目标账号执行）：
```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAA...（第1步那一整行）' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

**3. 在本机把节点写入 `~/.config/TensorHive/hosts_config.ini`**：
```ini
[<目标机的hostname或IP>]
user = <目标机用户名>
port = 22
```
（若目标机在 NAT/跳板机后，用文件里的 `[proxy_tunneling]` 段配置代理。）

**4. 验证连通 + 能读 GPU**：
```bash
tensorhive test         # 期望：[✔] <目标机> OK
```

**5. 重启 TensorHive**，刷新页面即可在面板看到新机器。

## ⚠️ 重要改动：Ed25519 密钥（本 fork 与上游的关键差异）

原版 TensorHive 用 **RSA-2048** 密钥，底层 `parallel-ssh/libssh2` 只能用 **SHA-1（ssh-rsa）** 签名，而 **OpenSSH ≥ 8.8（Ubuntu 22.04/24.04 默认）拒绝 SHA-1**，导致 `tensorhive test` 报 `AuthenticationException`。

本 fork 的修复（已改代码，无需动服务器 sshd）：
- `setup.py`：`ssh2-python==0.26.0` → `ssh2-python>=1.0.0`
- `tensorhive/core/ssh.py`：`generate_cert()`/`init_ssh_key()` 改用 **Ed25519**（`cryptography` 生成 OpenSSH 格式，`paramiko.Ed25519Key` 加载），并兼容加载旧 RSA key
- `tensorhive/cli.py`：`tensorhive key` 输出的前缀由硬编码 `ssh-rsa` 改为按 key 类型自动（`ssh-ed25519`）

因此**新装环境务必用本 fork**，否则会踩同样的 SSH 认证坑。

## 依赖环境速记

- Python 3.8（`conda create -n tensorhive python=3.8`）
- `pip install -e ~/Workspace/tensorhive`（全部老 pin 在 cp38 有 wheel，安装无冲突）
- 唯一手动升级：`ssh2-python>=1.0.0`（见上）
- 账号规则：用户名 3–15 字符且非保留词（`demo`/`admin` 等被 python-usernames 拒绝）；密码 ≥8 字符

## 用户怎么用（傻瓜版说明）

1. 浏览器打开 http://<本机局域网IP>:5000 ，用自己账号登录。
2. 首页 **Nodes/Dashboard** 实时看每台机器的 GPU/CPU/内存占用、谁的进程在跑。
3. 想独占某段时间的机器 → 用 **Reservations（预约/认领）** 选机器+时间段，别人就能看到"已被占用"。

## 待办 / 下一阶段（fork 定制方向）

- [ ] 改默认密码 / 删除 `alice`
- [ ] 无密码登录（邮箱直登）——需改 `controllers/user.py` 与前端登录页
- [ ] 首页信息瘦身 + 中文化，做到"傻瓜化"
- [ ] 节点显示名与 SSH host 解耦（现在节点名=SSH 目标，如 `localhost`）
- [ ] 开机自启（systemd user service）
