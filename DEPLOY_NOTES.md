# TensorHive 部署与运维手册（本地 fork）

机器租赁/共享统一管理面板。所有人登录同一个 Web 界面，实时看到有哪些机器、CPU/GPU/内存占用、谁在用，并可"认领"（reservation）机器。节点**纯 SSH 接入，目标机零安装**。

- Fork 仓库：`qiaoxu123/TensorHive`（upstream = `roscisz/TensorHive`）
- 本地源码：`~/Workspace/tensorhive`（editable 安装，改代码即生效）
- 运行环境：conda env **`tensorhive`**（Python 3.8）
- 配置目录：`~/.config/TensorHive/`（`main_config.ini` / `hosts_config.ini` / `database.sqlite` / `ssh_key` / `logs/`）

## 访问地址与账号

| 项 | 值 |
|---|---|
| **新版界面（推荐，中文/现代化）** | http://<本机局域网IP>:8090 |
| 旧版原生界面（保留备用） | http://<本机局域网IP>:5000 |
| API / Swagger | http://<本机局域网IP>:1111/api/ui/ |
| 管理员 | 用户名 `xqiao` / 密码见本机私密记录（**勿入库**） |
| 演示普通用户 | 用户名 `alice` / 密码见本机私密记录 |

> 本仓库为公开 fork，切勿把真实密码/内网地址写入文档。默认账号密码只记录在本机，请尽快改掉；`alice` 仅用于验证多用户，可删除。

## 启动 / 停止 / 重启

```bash
source $HOME/anaconda3/etc/profile.d/conda.sh && conda activate tensorhive

# 1) 启动后端（API :1111 + 旧版 web :5000）
cd ~/Workspace/tensorhive
nohup tensorhive > ~/.config/TensorHive/logs/run.log 2>&1 &

# 2) 启动新版前端（:8090，静态单文件）
cd ~/Workspace/tensorhive/webui
nohup python3 serve.py 8090 > ~/.config/TensorHive/logs/webui.log 2>&1 &

# 3) 启动管理后端（:8091，AutoDL 式功能：硬件/服务/SSH/建目录/停服务）
cd ~/Workspace/tensorhive/webui
nohup python backend.py > ~/.config/TensorHive/logs/backend.log 2>&1 &

# 查看状态 / 日志
ss -tlnp | grep -E ':8090|:8091|:5000|:1111'
tail -f ~/.config/TensorHive/logs/backend.log

# 停止（注意：别用 pkill -f 'python backend.py'，会误杀自身 shell）
pkill -f 'bin/tensorhive'
pkill -f 'serve.py 8090'
kill $(ss -tlnpH 'sport = :8091' | grep -oP 'pid=\K[0-9]+' | head -1)   # 停管理后端
```

## 新版前端（webui/）

- 纯静态单文件 `webui/index.html`（内联 CSS+JS，**无需构建**），由 `webui/serve.py` 起一个静态服务器托管。
- 设计参考 acta（中性面 + 单一强调色，支持浅/深色），**默认中文**，**机器优先**：首页大卡片展示每台机器的 GPU 利用率环形图、显存/CPU/内存条、温度功耗、以及"谁在用"；预约是次要页签，不占满页面。
- 通过浏览器直接调用 `http://<hostname>:1111/api`（TensorHive 已开 CORS）。access token 60s 过期 → 前端用 refresh_token 自动续期。用户 id/角色从 JWT `identity`/`user_claims` 解析（`GET /user` 不支持）。
- 每 4 秒轮询一次实时指标。改前端只需编辑 `index.html` 刷新页面即可（服务器禁用了缓存）。

## 管理后端（webui/backend.py，:8091）— AutoDL 式功能

Flask 小服务（零新依赖），**复用 TensorHive 的 SSH 通道**（`tensorhive.core.ssh`，同一把 Ed25519 key 连所有节点）在机器上执行命令。前端"机器详情"抽屉调它。

- **鉴权**：校验 TensorHive JWT（HS256，`jwt-some-secret`）；用户名从 sqlite users 表按 id 查。
- **授权**：写操作要求该用户对该机器有"活跃预约"（已认领）或为 admin，否则 403；只读信息任意登录用户可看。
- 端点：`GET /ctl/machines/<host>/hwinfo`（CPU 型号/核数、内存、硬盘、OS、GPU，缓存 60s）、`.../services`（探测 TensorBoard/Jupyter + 端口）、`.../ssh`（一键复制的 ssh 命令）、`POST .../workspace/ensure`（建 `~/workspace/<用户名>`）、`POST .../services/<pid>/stop`（停服务）。
- **用户/权限（仅管理员）**：`GET /ctl/users`（列出用户+角色）、`POST /ctl/users/<id>/admin {value:bool}`（设/取消管理员）。守护：不能取消自己、至少保留一个管理员。前端"用户"页（仅管理员可见）用开关管理。角色改动在对方下次登录或令牌刷新（约 1 分钟）后生效。xqiao 为默认管理员。
- **机器卡片显示修复**：状态（使用中/空闲/已预约/离线）改由真实 GPU 负载 + 预约决定，不再被 Xorg/gnome/ToDesk 等桌面进程误判为"使用中"；"谁在用"过滤桌面/系统进程只显示真实计算用户；卡片新增硬件条（CPU 型号·核数、内存总量、硬盘）。
- 前端能力：详情抽屉展示硬件规格、SSH 一键复制、运行服务（打开/停止）、工作目录初始化、使用时长；预约支持"⏳ 时长未知（长期占用）"；认领后自动建工作目录。
- **访问模型**：共享账号（hosts_config 的 user）+ 每人 `~/workspace/<用户名>` 目录，无需 root。

### ⚠️ 安全提醒
- JWT 密钥当前是 TensorHive 默认弱值 `jwt-some-secret`（管理后端也用它验签）。生产前建议改强并两边同步。
- 已做防注入：host 白名单、pid 整数校验、用户名字符集校验、命令不拼接用户自由文本。
- **未做（需后续确认）**：每人独立系统账号（需 sudo）、整机 reboot、重度环境配置（装驱动/Docker/系统包）、开机自启。

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
