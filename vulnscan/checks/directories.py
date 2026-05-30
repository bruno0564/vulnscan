COMMON_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/backup.zip",
    "/backup.sql",
    "/admin",
    "/admin/",
    "/phpmyadmin",
    "/wp-admin",
    "/api/v1",
    "/swagger",
    "/swagger-ui.html",
    "/openapi.json",
    "/docs",
    "/actuator",
    "/actuator/env",
    "/.DS_Store",
    "/robots.txt",
    "/sitemap.xml",
    "/server-status",
    "/debug",
]


def check_directories(base_url, session):
    findings = []
    base = base_url.rstrip("/")

    for path in COMMON_PATHS:
        try:
            r = session.get(f"{base}{path}", timeout=4, allow_redirects=False)
            if r.status_code in (200, 403):
                findings.append({
                    "type": "exposed_path",
                    "severity": "low" if r.status_code == 403 else "medium",
                    "path": path,
                    "status": r.status_code,
                    "detail": f"HTTP {r.status_code}",
                })
        except Exception:
            pass

    return findings
