#!/usr/bin/env python3
"""
framework.py
Custom Web Security Testing Framework - CLI entry point.

Usage examples:
    python custom_websec_testing_tool.py --target http://testphp.vulnweb.com --module headers
    python custom_websec_testing_tool.py --target http://demo.testfire.net --module all --output html
    python custom_websec_testing_tool.py --target http://testphp.vulnweb.com --module xss,sqli --threads 4

IMPORTANT: Only run this tool against systems you own or are explicitly
authorized to test (e.g. DVWA, OWASP Juice Shop, bWAPP, WebGoat,
Mutillidae, testphp.vulnweb.com, demo.testfire.net).
"""

import argparse
import concurrent.futures
import importlib.util
import os
import sys
import time

import yaml
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import logger
from utils.http_client import HttpClient
from utils.report import Report
from utils.session_auth import perform_login

from modules import headers as mod_headers
from modules import auth as mod_auth
from modules import xss as mod_xss
from modules import sqli as mod_sqli
from modules import disclosure as mod_disclosure
from utils import jwt_detection as mod_jwt
from utils import api_discovery as mod_api

BASE_MODULE_REGISTRY = {
    "headers": mod_headers.run,
    "auth": mod_auth.run,
    "xss": mod_xss.run,
    "sqli": mod_sqli.run,
    "disclosure": mod_disclosure.run,
    "jwt": mod_jwt.run,
    "api": mod_api.run,
}

PLUGINS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")


def load_plugins(registry):
    """Plugin architecture: any .py file in plugins/ exposing a
    MODULE_NAME string and a run(target, client, **kwargs) function is
    auto-discovered and registered as a new --module option, without
    any change to core framework code."""
    if not os.path.isdir(PLUGINS_DIR):
        return
    for fname in sorted(os.listdir(PLUGINS_DIR)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        path = os.path.join(PLUGINS_DIR, fname)
        spec = importlib.util.spec_from_file_location(fname[:-3], path)
        plugin_mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(plugin_mod)
        except Exception as exc:
            logger.error(f"Failed to load plugin '{fname}': {exc}")
            continue
        if hasattr(plugin_mod, "run"):
            name = getattr(plugin_mod, "MODULE_NAME", fname[:-3]).lower()
            registry[name] = plugin_mod.run
            logger.info(f"Loaded plugin module: '{name}' (from plugins/{fname})")


def parse_args():
    p = argparse.ArgumentParser(
        prog="framework.py",
        description=
        "Custom Web Security Testing Framework - modular vulnerability scanner "
                    "for authorized penetration testing engagements."
    )
    p.add_argument("--target", required=True, help="Target base URL, e.g. http://testphp.vulnweb.com")
    p.add_argument("--module", default="all",
                    help="Module(s) to run: headers,auth,xss,sqli,disclosure,jwt,api, any loaded "
                        "plugin (e.g. cors), or 'all' (comma-separated for multiple).")
    p.add_argument("--output", choices=["html", "json", "both"], default="both",
                    help="Report output format (default: both).")
    p.add_argument("--report-name", default=None, help="Base filename for the report (no extension).")
    p.add_argument("--threads", type=int, default=1, help="Number of modules to run concurrently.")
    p.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds.")
    p.add_argument("--user-agent", default=None, help="Custom User-Agent string.")
    p.add_argument("--cookies", default=None, help="Cookies to send, 'k1=v1; k2=v2'.")
    p.add_argument("--header", action="append", default=[],
                    help="Extra request header 'Key: Value' (repeatable).")
    p.add_argument("--proxy", default=None, help="Proxy URL, e.g. http://127.0.0.1:8080 (Burp Suite).")
    p.add_argument("--burp", action="store_true",
                    help="Shorthand for routing all traffic through a local Burp Suite instance "
                        "(proxy=http://127.0.0.1:8080, TLS verification disabled). Overridden by "
                        "an explicit --proxy if both are given.")
    p.add_argument("--no-verify-ssl", action="store_true", help="Disable TLS certificate verification.")
    p.add_argument("--config", default=None, help="Path to a YAML config file with default options.")
    p.add_argument("--login-path", default=None, help="Login endpoint URL for the auth module.")
    p.add_argument("--register-path", default=None,
                    help="Optional registration endpoint URL, used only by the auth module's "
                        "weak-password-policy check (submits throwaway test accounts).")
    p.add_argument("--login-user", default=None,
                    help="Username for automated login (session management). Requires "
                        "--login-pass and --login-path.")
    p.add_argument("--login-pass", default=None,
                    help="Password for automated login (session management).")
    p.add_argument("--jwt", default=None,
                    help="Explicit JWT to analyze with the jwt module, in addition to any "
                        "tokens discovered automatically.")
    p.add_argument("--time-based-sqli", action="store_true",
                    help="Enable optional time-based SQL injection tests (slower).")
    return p.parse_args()


def load_config(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def build_headers(header_list):
    extra = {}
    for h in header_list:
        if ":" in h:
            k, v = h.split(":", 1)
            extra[k.strip()] = v.strip()
    return extra


def resolve_modules(module_arg, registry):
    if module_arg.strip().lower() == "all":
        return list(registry.keys())
    names = [m.strip().lower() for m in module_arg.split(",") if m.strip()]
    invalid = [m for m in names if m not in registry]
    if invalid:
        logger.error(f"Unknown module(s): {', '.join(invalid)}. "
                    f"Available: {', '.join(registry.keys())}")
        sys.exit(1)
    return names


def main():
    args = parse_args()
    config = load_config(args.config)

    # config file values act as defaults; CLI flags override them
    timeout = args.timeout if args.timeout != 10 else config.get("timeout", args.timeout)
    user_agent = args.user_agent or config.get("user_agent")
    cookies = args.cookies or config.get("cookies")

    # Burp Suite integration: --burp is a convenience shorthand for the
    # standard local Burp proxy setup; an explicit --proxy always wins.
    proxy = args.proxy or config.get("proxy")
    verify_ssl = not args.no_verify_ssl and config.get("verify_ssl", True)
    if args.burp and not args.proxy:
        proxy = "http://127.0.0.1:8080"
        verify_ssl = False

    extra_headers = build_headers(args.header)
    extra_headers.update(config.get("headers", {}))

    client = HttpClient(
        timeout=timeout,
        user_agent=user_agent,
        cookies=cookies,
        extra_headers=extra_headers,
        proxy=proxy,
        verify_ssl=verify_ssl,
    )

    registry = dict(BASE_MODULE_REGISTRY)
    load_plugins(registry)

    modules_to_run = resolve_modules(args.module, registry)

    logger.banner("Custom Web Security Testing Framework")
    logger.info(f"Target        : {args.target}")
    logger.info(f"Modules       : {', '.join(modules_to_run)}")
    logger.info(f"Threads       : {args.threads}")
    logger.info(f"Proxy         : {proxy or 'none'}" + (" (Burp)" if args.burp and not args.proxy else ""))
    print()

    report = Report(target=args.target, modules_run=modules_to_run)

    # Session management / login automation: if credentials are supplied,
    # authenticate once up front and leave the resulting session cookies
    # on the shared client so every module below runs authenticated.
    if args.login_user and args.login_pass:
        login_url = args.login_path or args.target
        logger.info(f"[Session] Attempting automated login to {login_url} as '{args.login_user}'")
        success, detail = perform_login(client, login_url, args.login_user, args.login_pass)
        if success:
            logger.success(f"[Session] {detail}")
        else:
            logger.warn(f"[Session] {detail}")
        report.add_findings("session", [{
            "title": "Automated login " + ("succeeded" if success else "did not appear to succeed"),
            "severity": "INFO",
            "evidence": detail,
            "recommendation": "N/A — informational context for how the rest of this scan was "
                            "authenticated." if success else
                            "Verify --login-path/--login-user/--login-pass are correct, or "
                            "the login form uses non-default field names.",
        }])

    module_kwargs = {
        "login_path": args.login_path,
        "register_path": args.register_path,
        "test_time_based": args.time_based_sqli,
        "jwt_token": args.jwt,
    }

    start_time = time.time()

    def run_module(name):
        fn = registry[name]
        try:
            return name, fn(args.target, client, **{k: v for k, v in module_kwargs.items()})
        except TypeError:
            # module/plugin doesn't accept one of the extra kwargs; retry with none
            return name, fn(args.target, client)
        except Exception as exc:
            logger.error(f"Module '{name}' raised an exception: {exc}")
            return name, [{
                "title": f"Module '{name}' failed to complete",
                "severity": "INFO",
                "evidence": str(exc),
                "recommendation": "Re-run the module individually with --module for details.",
            }]

    if args.threads > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(run_module, name): name for name in modules_to_run}
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures),
                                desc="Running modules", ncols=70):
                name, findings = future.result()
                report.add_findings(name, findings)
    else:
        for name in tqdm(modules_to_run, desc="Running modules", ncols=70):
            _, findings = run_module(name)
            report.add_findings(name, findings)

    elapsed = time.time() - start_time
    print()
    logger.success(f"Scan completed in {elapsed:.2f}s")

    # --- write reports ---
    os.makedirs("reports", exist_ok=True)
    base_name = args.report_name or f"report_{int(time.time())}"
    json_path = os.path.join("reports", f"{base_name}.json")
    html_path = os.path.join("reports", f"{base_name}.html")

    if args.output in ("json", "both"):
        report.save_json(json_path)
        logger.success(f"JSON report saved to {json_path}")
    if args.output in ("html", "both"):
        report.save_html(html_path)
        logger.success(f"HTML report saved to {html_path}")

    data = report.to_dict()
    print()
    logger.banner(f"Overall Risk Rating: {data['overall_risk_rating']} "
                f"(score {data['risk_score']}/100, {data['total_findings']} findings)")


if __name__ == "__main__":
    main()
