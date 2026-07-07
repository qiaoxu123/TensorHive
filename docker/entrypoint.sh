#!/bin/bash
set -e

echo "=== TensorHive Docker Entrypoint ==="

# ── 1. Generate config files ──
CONFIG_DIR="$HOME/.config/TensorHive"
mkdir -p "$CONFIG_DIR"

# main_config.ini
cat > "$CONFIG_DIR/main_config.ini" << MAINEOF
[api]
url_hostname = ${TH_API_HOST:-0.0.0.0}
url_schema = http
url_port = 1111

[database]
type = ${TH_DB_TYPE:-postgresql}
host = ${TH_DB_HOST:-postgresql}
port = ${TH_DB_PORT:-5432}
name = ${TH_DB_NAME:-tensorhive_db}
user = ${TH_DB_USER:-tensorhive_app}
password = ${TH_DB_PASSWORD:-}

[ssh]
key_file = $CONFIG_DIR/ssh_key
MAINEOF

# hosts_config.ini (empty template with docs)
if [ ! -f "$CONFIG_DIR/hosts_config.ini" ]; then
    cat > "$CONFIG_DIR/hosts_config.ini" << 'HOSTSEOF'
# 添加你要纳管的机器，每台一个 [section]：
#
# ── 方式一：密钥认证（推荐） ──
# 1. 在容器内跑 tensorhive key，拿到公钥
# 2. 将公钥加入目标机的 ~/.ssh/authorized_keys
# 3. 配置如下：
#   [192.168.3.100]
#   user = your_name
#   port = 22
#
# ── 方式二：密码认证 ──
#   [192.168.3.100]
#   user = your_name
#   port = 22
#   password = your_password
#
# ── 方式三：指定独立密钥文件 ──
#   [192.168.3.100]
#   user = your_name
#   port = 22
#   key_file = /path/to/private_key
#
# 修改此文件后必须重启 tensorhive 容器生效。
HOSTSEOF
fi

# mailbot_config.ini (copy template from package, but disable mailbot)
if [ ! -f "$CONFIG_DIR/mailbot_config.ini" ]; then
    python3 << PYEOF
import configparser, os
c = configparser.ConfigParser()
c.read('/app/tensorhive/mailbot_config.ini')
c.set('general', 'notify_intruder', 'no')
c.set('general', 'notify_admin', 'no')
os.makedirs(os.path.dirname('$CONFIG_DIR/mailbot_config.ini'), exist_ok=True)
with open('$CONFIG_DIR/mailbot_config.ini', 'w') as f:
    c.write(f)
PYEOF
    echo '[✔] mailbot_config.ini written (disabled)'
fi

echo "[✔] Config files written"

# ── 1b. Add /etc/hosts entries for machines that share an IP with different ports ──
# This allows parallel-ssh to use display names as connection targets.
# Each entry in hosts_config.ini can optionally define a static IP via 'host' field,
# but parallel-ssh doesn't read that field — so we add the mapping to /etc/hosts.
if [ -f "$CONFIG_DIR/hosts_config.ini" ]; then
    python3 -c "
import configparser, os
c = configparser.ConfigParser()
c.read('$CONFIG_DIR/hosts_config.ini')
with open('/etc/hosts', 'a') as f:
    for section in c.sections():
        if section == 'proxy_tunneling': continue
        if c.has_option(section, 'host'):
            ip = c.get(section, 'host')
            f.write(f'{ip} {section}\n')
            print(f'  {ip} -> {section}')
" 2>/dev/null
fi

# ── 2. Generate SSH key if missing (persisted on host, survives rebuild) ──
if [ ! -f "$CONFIG_DIR/ssh_key" ]; then
    ssh-keygen -t ed25519 -f "$CONFIG_DIR/ssh_key" -N "" -C "tensorhive@docker" 2>/dev/null
    echo "[✔] SSH key generated (NEW — add this to target machines)"
else
    echo "[✔] SSH key exists (persisted)"
fi

# ── 3. Wait for PG + init DB ──
echo "[•] Waiting for PostgreSQL..."
for i in $(seq 1 30); do
    if python3 -c "
import psycopg2
psycopg2.connect(host='${TH_DB_HOST}',port=${TH_DB_PORT},user='${TH_DB_USER}',password='${TH_DB_PASSWORD}',dbname='${TH_DB_NAME}')
print('ok')
" 2>/dev/null; then
        echo "[✔] PostgreSQL ready"
        break
    fi
    sleep 2
done

# ── 4. Create tables + seed admin ──
python3 /app/docker/db_init.py

echo "=== Starting services ==="

# ── 5. Start all 3 services ──
# ① TensorHive backend (API :1111 + legacy web :5000)
cd /app
tensorhive &
PID1=$!

# ② Admin backend (:8091)
cd /app/webui
python3 backend.py &
PID2=$!

# ③ Nginx reverse proxy (:8090 → api:1111 + ctl:8091 + static files)
nginx &
PID3=$!

echo "[✔] All services started"
echo "  API:          http://0.0.0.0:1111/api/ui/"
echo "  Legacy web:   http://0.0.0.0:5000/"
echo "  Frontend:     http://0.0.0.0:8090/"
echo "  Admin API:    http://0.0.0.0:8091/"

# Wait for any to die, then exit
trap "kill $PID1 $PID2 $PID3 2>/dev/null; exit 0" TERM INT
wait -n $PID1 $PID2 $PID3
