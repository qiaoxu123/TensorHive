FROM python:3.8-slim-bullseye

# system deps: crypt.h for ssh2-python compile + nginx for reverse proxy
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libcrypt-dev libffi-dev libssl-dev openssh-client \
    nginx \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# nginx config (reverse-proxy :8090 → api:1111 + ctl:8091 + static files)
COPY docker/nginx.conf /etc/nginx/sites-enabled/default
RUN rm -f /etc/nginx/sites-enabled/default.conf 2>/dev/null; \
    echo "daemon off;" >> /etc/nginx/nginx.conf

# copy everything first, then install
COPY . .
RUN pip install --no-cache-dir --upgrade pip wheel setuptools \
    && pip install --no-cache-dir psycopg2-binary flask flask-cors requests PyJWT
RUN pip install --no-cache-dir .

# entrypoint + init script
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/db_init.py /app/docker/db_init.py
RUN chmod +x /entrypoint.sh /app/docker/db_init.py

ENV TH_DB_TYPE=postgresql \
    TH_DB_HOST=postgresql \
    TH_DB_PORT=5432 \
    TH_DB_NAME=tensorhive_db \
    TH_DB_USER=tensorhive_app \
    TH_DB_PASSWORD=Th2026SecretDB!@# \
    TH_ADMIN_USER=xqiao \
    TH_ADMIN_EMAIL=george.x.qiao@gmail.com \
    TH_ADMIN_PASSWORD=ChangeMe123! \
    TH_API_HOST=0.0.0.0

EXPOSE 1111 5000 8090 8091

ENTRYPOINT ["/entrypoint.sh"]
