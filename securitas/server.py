"""Start Securitas: database, bootstrap data, scan workers and scheduler, web server."""
import logging
import os

from sqlalchemy import select

from . import __version__, auth
from .db import Database, RoleMapping, User, audit
from .jobs import Jobs
from .web import create_app

log = logging.getLogger("securitas")


def bootstrap(cfg, db):
    with db.Session() as s, s.begin():
        if not s.scalar(select(RoleMapping.id).limit(1)):
            for pair in cfg.role_map:
                g, _, r = pair.partition("=")
                if g.strip() and r.strip() in auth.ROLES:
                    s.add(RoleMapping(group=auth.group_cn(g), role=r.strip()))
                else:
                    log.warning("ignored role mapping %r (expected Group=viewer|operator|admin)", pair)
        if cfg.admin_password:
            u = s.scalar(select(User).where(User.username == cfg.admin_username))
            if u is None:
                s.add(User(username=cfg.admin_username, display_name="Administrator", source="local",
                           password_hash=auth.hash_password(cfg.admin_password), role="admin"))
                audit(s, "", "", "user.bootstrap", "created local admin %s" % cfg.admin_username)
            elif u.source == "local":
                if not auth.verify_password(u.password_hash, cfg.admin_password):
                    u.password_hash = auth.hash_password(cfg.admin_password)
                    audit(s, "", "", "user.bootstrap", "admin password set from the deployment")
                u.role, u.disabled = "admin", False
            else:
                log.warning("SECURITAS_ADMIN_USERNAME %s belongs to an %s user; no local admin was created", u.username, u.source)
        elif not s.scalar(select(User.id).where(User.role == "admin").limit(1)) and not cfg.role_map:
            log.warning("no admin exists: set SECURITAS_ADMIN_PASSWORD, or map a group to the admin role")


def build(cfg, start_threads=True, scanners=None):
    os.makedirs(cfg.data_dir, exist_ok=True)
    db = Database(cfg.database_url)
    db.create()
    bootstrap(cfg, db)
    jobs = Jobs(cfg, db, scanners)
    jobs.bootstrap()
    if start_threads:
        jobs.start()
    return create_app(cfg, db, jobs), db, jobs


def serve(cfg):
    import uvicorn
    app, _, _ = build(cfg)
    if cfg.oidc.enabled and not cfg.base_url:
        raise SystemExit("SECURITAS_BASE_URL is required for single sign-on")
    log.info("securitas %s listening on :%d (database %s)", __version__, cfg.port, cfg.database_url.split("://")[0])
    uvicorn.run(app, host="0.0.0.0", port=cfg.port, log_level="warning", access_log=False, proxy_headers=False,
                server_header=False)
