import argparse
import json
from pathlib import Path

from colorama import Fore, Style, init

from .auth import build_session
from .report import render_html
from .scanner import scan
from .types import ScanResult

init(autoreset=True)

SEVERITY_COLOR = {
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.CYAN,
}


def print_report(result: ScanResult) -> None:
    if "error" in result:
        print(f"{Fore.RED}Error: {result['error']}")
        return

    print(f"\n{Style.BRIGHT}Target: {result['url']}  [{result['status']}]")
    s = result["summary"]
    print(
        f"Findings: {Fore.RED}{s['high']} high  "
        f"{Fore.YELLOW}{s['medium']} medium  "
        f"{Fore.CYAN}{s['low']} low\n"
    )

    for f in result["findings"]:
        color = SEVERITY_COLOR.get(f["severity"], "")
        tag = f"[{f['severity'].upper()}]".ljust(10)
        title = f.get("header") or f.get("path") or f.get("param") or f.get("host") or f.get("type")
        print(f"{color}{tag}{Style.RESET_ALL} {title}")
        print(f"         {f.get('detail', '')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="vulnscan — web vulnerability scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Write a self-contained HTML report to FILE",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        metavar="SECONDS",
        help="Per-request timeout in seconds (default: 8)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Delay between requests in seconds — be polite, avoid rate limits (default: 0)",
    )

    auth = parser.add_argument_group("authentication")
    creds = auth.add_mutually_exclusive_group()
    creds.add_argument("--bearer", metavar="TOKEN", help="Send 'Authorization: Bearer <token>'")
    creds.add_argument("--basic", metavar="USER:PASS", help="HTTP Basic auth credentials")
    auth.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help="Extra request header (repeatable), e.g. --header 'Cookie: session=abc'",
    )
    args = parser.parse_args()

    try:
        session = build_session(bearer=args.bearer, basic=args.basic, headers=args.header)
    except ValueError as e:
        parser.error(str(e))

    result = scan(args.url, timeout=args.timeout, delay=args.delay, session=session)

    if args.html:
        Path(args.html).write_text(render_html(result), encoding="utf-8")
        print(f"HTML report written to {args.html}")

    if args.json:
        print(json.dumps(result, indent=2))
    elif not args.html:
        print_report(result)


if __name__ == "__main__":
    main()
