"""
Module 5 - Information Disclosure
Probes for commonly exposed resources: robots.txt, sitemap.xml,
.git directories, backup files, phpinfo, directory listing, and
exposed configuration files.
"""

import urllib.parse as urlparse

from utils import logger

CHECKS = [
    {"path": "robots.txt", "title": "robots.txt exposed", "severity": "INFO",
    "recommendation": "Review robots.txt to ensure it does not reveal sensitive paths."},
    {"path": "sitemap.xml", "title": "sitemap.xml exposed", "severity": "INFO",
    "recommendation": "Review sitemap.xml for unintentionally disclosed URLs."},
    {"path": ".git/HEAD", "title": ".git directory exposed", "severity": "CRITICAL",
    "recommendation": "Remove the .git directory from the web root or block access to it; "
                        "exposed source control history can leak credentials and source code."},
    {"path": ".env", "title": "Exposed .env configuration file", "severity": "CRITICAL",
    "recommendation": "Remove .env from the public web root; store secrets outside the "
                        "webroot and rotate any credentials that may have been exposed."},
    {"path": "config.php.bak", "title": "Backup configuration file exposed", "severity": "HIGH",
    "recommendation": "Remove backup files (.bak, .old, ~) from the web root."},
    {"path": "web.config.bak", "title": "Backup web.config exposed", "severity": "HIGH",
    "recommendation": "Remove backup configuration files from the web root."},
    {"path": "backup.zip", "title": "Backup archive exposed", "severity": "HIGH",
    "recommendation": "Remove backup archives from publicly accessible directories."},
    {"path": "phpinfo.php", "title": "phpinfo() page exposed", "severity": "MEDIUM",
    "recommendation": "Remove phpinfo.php from production; it discloses detailed server "
                        "configuration useful for attackers."},
    {"path": "info.php", "title": "phpinfo() page exposed", "severity": "MEDIUM",
    "recommendation": "Remove info.php from production; it discloses detailed server "
                        "configuration useful for attackers."},
    {"path": ".htaccess", "title": ".htaccess file exposed", "severity": "MEDIUM",
    "recommendation": "Block web access to .htaccess and other dotfiles."},
    {"path": "wp-config.php.bak", "title": "WordPress config backup exposed", "severity": "CRITICAL",
    "recommendation": "Remove wp-config.php backups; they contain database credentials."},
    {"path": "server-status", "title": "Apache server-status exposed", "severity": "MEDIUM",
    "recommendation": "Restrict access to /server-status to trusted internal IPs only."},
]

PHPINFO_MARKERS = ["phpinfo()", "PHP Version", "php.ini"]
DIR_LISTING_MARKERS = ["Index of /", "<title>Index of", "Directory Listing For"]


def run(target, client, **kwargs):
    logger.info(f"[Disclosure] Probing {target}")
    findings = []

    parsed = urlparse.urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}/"

    for check in CHECKS:
        url = urlparse.urljoin(base, check["path"])
        resp = client.get(url)
        if resp is None or not hasattr(resp, "status_code"):
            continue

        if resp.status_code == 200 and resp.text:
            body = resp.text
            evidence = f"HTTP 200 returned for {url}"
            severity = check["severity"]

            if "phpinfo" in check["path"] or "info.php" in check["path"]:
                if not any(m.lower() in body.lower() for m in PHPINFO_MARKERS):
                    continue  # false positive (custom 200 error page)

            findings.append({
                "title": check["title"],
                "severity": severity,
                "evidence": evidence,
                "recommendation": check["recommendation"],
            })
            logger.finding(severity, f"{check['title']} -> {url}")

    # Directory listing check on the base path itself
    resp = client.get(base)
    if resp is not None and getattr(resp, "text", None):
        if any(marker.lower() in resp.text.lower() for marker in DIR_LISTING_MARKERS):
            findings.append({
                "title": "Directory listing enabled",
                "severity": "MEDIUM",
                "evidence": f"Directory index markers found at {base}",
                "recommendation": "Disable directory listing/autoindex on the web server.",
            })
            logger.finding("MEDIUM", "Directory listing enabled")

    if not findings:
        findings.append({
            "title": "No common information disclosure issues detected",
            "severity": "INFO",
            "evidence": f"{len(CHECKS)} known-sensitive paths tested; none returned exposed content.",
            "recommendation": "No action required.",
        })

    logger.success(f"[Disclosure] Probed {len(CHECKS)} known paths")
    return findings
