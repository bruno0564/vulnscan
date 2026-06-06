import argparse
import json

from colorama import Fore, Style, init

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
        print(f"{color}{tag}{Style.RESET_ALL} {f.get('header') or f.get('path') or f.get('type')}")
        print(f"         {f.get('detail', '')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="vulnscan — web vulnerability scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    result = scan(args.url)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)


if __name__ == "__main__":
    main()
