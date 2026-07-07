#!/usr/bin/env python3
"""Container-first-run: init DB schema + seed admin + ensure columns.

Uses raw psycopg2 to avoid SQLAlchemy pool issues during startup.
"""
import os, sys

def main():
    host = os.environ.get('TH_DB_HOST', 'postgresql')
    port = os.environ.get('TH_DB_PORT', '5432')
    name = os.environ.get('TH_DB_NAME', 'tensorhive_db')
    user = os.environ.get('TH_DB_USER', 'tensorhive_app')
    password = os.environ.get('TH_DB_PASSWORD', '')

    import psycopg2
    try:
        conn = psycopg2.connect(host=host, port=port, user=user, password=password, dbname=name,
                                 connect_timeout=10)
    except Exception as e:
        print(f'[!] PG connect failed: {e}', flush=True)
        sys.exit(1)

    conn.autocommit = True
    cur = conn.cursor()

    # ── 1. Ensure ssh_pubkey column ──
    try:
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS ssh_pubkey TEXT DEFAULT NULL")
        cur.execute("ALTER TABLE users ALTER COLUMN _hashed_password TYPE VARCHAR(300)")
        print('[✔] columns ensured', flush=True)
    except Exception as e:
        print(f'[!] ssh_pubkey column: {e}', flush=True)

    # ── 2. Use SQLAlchemy to check/create tables (via existing engine) ──
    try:
        from tensorhive.database import ensure_db_with_current_schema
        ensure_db_with_current_schema()
        print('[✔] DB schema ready', flush=True)
    except Exception as e:
        print(f'[!] SA schema check failed: {e}', flush=True)
        # Don't exit — might already have tables

    # ── 3. Seed admin ──
    try:
        from tensorhive.models.User import User
        from tensorhive.models.Role import Role
        from tensorhive.models.Group import Group

        if User.query.count() == 0:
            admin_user = os.environ.get('TH_ADMIN_USER', 'xqiao')
            admin_email = os.environ.get('TH_ADMIN_EMAIL', 'admin@localhost')
            admin_pass = os.environ.get('TH_ADMIN_PASSWORD', 'ChangeMe123!')

            u = User(username=admin_user, email=admin_email)
            u.password = admin_pass
            u.roles.append(Role(name='user'))
            u.roles.append(Role(name='admin'))
            u.save()
            for g in Group.get_default_groups():
                g.add_user(u)
            print(f'[✔] Admin account created: {admin_user}', flush=True)
        else:
            print('[•] Users already exist, skipping admin seed', flush=True)
    except Exception as e:
        print(f'[!] Admin seed: {e}', flush=True)

    conn.close()

    # ── 4. Sync Discourse users ──
    try:
        _sync_discourse_users(host, port, user, password)
    except Exception as e:
        print(f'[!] Discourse sync: {e}', flush=True)

    print('[✔] DB init complete', flush=True)


def _sync_discourse_users(pg_host, pg_port, pg_user, pg_password):
    """Import active Discourse users into TensorHive (shared password hashes)."""
    import psycopg2
    d_conn = psycopg2.connect(host=pg_host, port=pg_port, user=pg_user,
                               password=pg_password, dbname='discourse_jnkifp',
                               connect_timeout=5)
    d_cur = d_conn.cursor()
    d_cur.execute("""
        SELECT u.username, ue.email, up.password_hash
        FROM users u
        JOIN user_emails ue ON ue.user_id = u.id AND ue.primary = true
        LEFT JOIN user_passwords up ON up.user_id = u.id
        WHERE u.active = true AND u.username NOT IN ('discobot', 'system')
        ORDER BY u.id
    """)
    discourse_users = d_cur.fetchall()
    d_conn.close()

    if not discourse_users:
        print('[•] No Discourse users to sync', flush=True)
        return

    from tensorhive.models.User import User
    from tensorhive.models.Role import Role
    from tensorhive.models.Group import Group

    added = 0
    for username, email, pw_hash in discourse_users:
        if User.query.filter(User.username == username).first():
            continue  # already exists
        if not username or not email:
            continue
        try:
            u = User(username=username, email=email)
            if pw_hash:
                u._hashed_password = pw_hash
            else:
                u.password = os.environ.get('TH_ADMIN_PASSWORD', 'ChangeMe123!')
            u.roles.append(Role(name='user'))
            if username == 'xqiao':
                from tensorhive.database import db_session
                existing_admin = db_session.query(User).filter(
                    User.roles.any(Role.name == 'admin')).first()
                if not existing_admin:
                    u.roles.append(Role(name='admin'))
            u.save()
            for g in Group.get_default_groups():
                g.add_user(u)
            added += 1
        except Exception:
            # Fallback: raw SQL for usernames that fail ORM validation
            try:
                import psycopg2
                pg_conn = psycopg2.connect(host=pg_host, port=pg_port, user=pg_user,
                                            password=pg_password, dbname='tensorhive_db')
                pg_cur = pg_conn.cursor()
                pg_cur.execute(
                    "INSERT INTO users(username, email, created_at, _hashed_password) VALUES(%s,%s,NOW(),%s) ON CONFLICT (username) DO NOTHING RETURNING id",
                    (username, email, pw_hash or ''))
                row = pg_cur.fetchone()
                if row:
                    pg_cur.execute("INSERT INTO roles(name, user_id) SELECT 'user',%s WHERE NOT EXISTS (SELECT 1 FROM roles WHERE user_id=%s AND name='user')", (row[0], row[0]))
                    pg_conn.commit()
                    added += 1
                pg_conn.close()
            except Exception as e2:
                print(f'[!] Skip {username}: {e2}', flush=True)

    print(f'[✔] Synced {added} users from Discourse', flush=True)


if __name__ == '__main__':
    main()
