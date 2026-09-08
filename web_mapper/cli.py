"""
WebAdminMapper - Enterprise CLI Interface & Execution Controller
================================================================
Interactive terminal runner with multithreaded recursion, technology
profiling, soft-404 heuristics, defensive security auditing, and TLS checks.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import argparse
import os
import signal
import sys
import time
from typing import List, Optional, Set

from .cert_inspector import CertificateInfo, CertInspector
from .checkpoint import SessionCheckpoint
from .config import DEFAULT_FILTER_CODES, DEFAULT_MATCH_CODES, ScanConfig
from .crawler import RouteHarvester
from .engine import ExecutionEngine
from .network_diag import NetworkDiagnostics, NetworkDiagResult
from .reporter import Colors, ScanReporter
from .requester import HTTPRequester, ScanResult
from .security_assertions import SecurityAssertion, SecurityAssertionValidator
from .security_audit import SecurityAuditor, SecurityAuditResult

__author__ = "Ahmed Wael"
__version__ = "1.0.0"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"

BANNER = rf"""{Colors.CYAN}{Colors.BOLD}
==========================================================================
  __      __      ___.       _____       .___      .__         _____   
 /  \    /  \ ____\_ |__    /  _  \    __| _/_____ |__| ____  /     \  
 \   \/\/   // __ \| __ \  /  /_\  \  / __ |/     \|  |/    \/  \ /  \ 
  \        /\  ___/| \_\ \/    |    \/ /_/ |  Y Y  \  |   |  \    Y    \
   \__/\  /  \___  >___  /\____|__  /\____ |__|_|  /__|___|  /__|__|_  /
        \/       \/    \/         \/      \/     \/        \/        \/ 
                 [ WebAdminMapper v{__version__} - Enterprise Edition ]
                 Developed & Authored by Ahmed Wael
=========================================================================={Colors.RESET}
"""


def parse_csv_ints(val: Optional[str]) -> set:
    """Parse comma-separated integer strings into a set."""
    if not val:
        return set()
    res = set()
    for item in val.split(","):
        item = item.strip()
        if item.isdigit():
            res.add(int(item))
    return res


def build_parser() -> argparse.ArgumentParser:
    """Build and configure the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="webadminmapper",
        description=(
            "WebAdminMapper - Enterprise Web Administration, Directory Mapping, "
            "and File Structure Discovery Suite. Authored by Ahmed Wael."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Target
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument(
        "-u", "--url",
        dest="url",
        type=str,
        help="Target base URL (e.g., https://example.com or http://192.168.1.50:8080)",
    )
    target_group.add_argument(
        "--profile",
        dest="profile",
        type=str,
        default=None,
        help="Load complete scan configuration from a JSON profile file",
    )
    target_group.add_argument(
        "--resume",
        dest="resume",
        type=str,
        default=None,
        help="Resume discovery session from a saved JSON checkpoint file",
    )

    # Wordlist & Path Generation
    wordlist_group = parser.add_argument_group("Wordlist & Fuzzing Mutations")
    wordlist_group.add_argument(
        "-w", "--wordlist",
        dest="wordlist",
        type=str,
        default=None,
        help="Path to custom wordlist file, or '-' to read candidate paths from STDIN",
    )
    wordlist_group.add_argument(
        "-m", "--mode",
        dest="mode",
        type=str,
        choices=["admin", "common", "sensitive", "cloud", "all"],
        default="all",
        help="Curated wordlist category (default: 'all'):\n"
             "  admin     : Administrative portals, logins, panels, dashboards\n"
             "  common    : Standard directories, API routes, assets, uploads\n"
             "  sensitive : Sensitive files, .env, backups, SQL dumps, configs\n"
             "  cloud     : Cloud metadata, Docker, K8s, Spring Actuator, Swagger\n"
             "  all       : Combined catalog of all curated routes",
    )
    wordlist_group.add_argument(
        "-x", "--extensions",
        dest="extensions",
        type=str,
        default="",
        help="Comma-separated file extensions to permute (e.g., php,html,json,bak)",
    )
    wordlist_group.add_argument(
        "--prefix",
        dest="prefix",
        type=str,
        default="",
        help="Prefix to prepend to every candidate word (e.g., 'v1_' or 'api/')",
    )
    wordlist_group.add_argument(
        "--suffix",
        dest="suffix",
        type=str,
        default="",
        help="Suffix to append to every candidate word (e.g., '_backup' or '-dev')",
    )
    wordlist_group.add_argument(
        "--case",
        dest="case_transform",
        choices=["lower", "upper", "title"],
        default=None,
        help="Case transformation for wordlist entries",
    )

    # Recursion
    rec_group = parser.add_argument_group("Recursive Directory Mapping")
    rec_group.add_argument(
        "-r", "--recursive",
        dest="recursive",
        action="store_true",
        help="Enable recursive exploration of discovered directories",
    )
    rec_group.add_argument(
        "--depth",
        dest="max_depth",
        type=int,
        default=1,
        help="Maximum recursion depth for directory mapping (default: 1)",
    )

    # Concurrency & Network
    net_group = parser.add_argument_group("Performance & Network Engine")
    net_group.add_argument(
        "-t", "--threads",
        dest="threads",
        type=int,
        default=25,
        help="Number of concurrent worker threads (default: 25, max: 200)",
    )
    net_group.add_argument(
        "-to", "--timeout",
        dest="timeout",
        type=float,
        default=7.0,
        help="HTTP request timeout in seconds (default: 7.0)",
    )
    net_group.add_argument(
        "-d", "--delay",
        dest="delay",
        type=float,
        default=0.0,
        help="Delay in seconds between requests per thread for rate-limiting (default: 0.0)",
    )
    net_group.add_argument(
        "--retries",
        dest="retries",
        type=int,
        default=1,
        help="Number of retries upon network timeout (default: 1)",
    )

    # Filter & Match Criteria
    filter_group = parser.add_argument_group("Advanced Filters & Match Criteria")
    filter_group.add_argument(
        "-mc", "--match-codes",
        dest="match_codes",
        type=str,
        default="",
        help="Status codes to match (comma-separated, default: 200,204,301,302,307,308,401,403,500)",
    )
    filter_group.add_argument(
        "-fc", "--filter-codes",
        dest="filter_codes",
        type=str,
        default="",
        help="Status codes to filter out (comma-separated, default: 404)",
    )
    filter_group.add_argument(
        "-ms", "--match-size",
        dest="match_size",
        type=str,
        default="",
        help="Response body sizes (in bytes) to match (comma-separated)",
    )
    filter_group.add_argument(
        "-fs", "--filter-size",
        dest="filter_size",
        type=str,
        default="",
        help="Response body sizes (in bytes) to filter out (comma-separated)",
    )
    filter_group.add_argument(
        "-mw", "--match-words",
        dest="match_words",
        type=str,
        default="",
        help="Word counts to match (comma-separated)",
    )
    filter_group.add_argument(
        "-fw", "--filter-words",
        dest="filter_words",
        type=str,
        default="",
        help="Word counts to filter out (comma-separated)",
    )
    filter_group.add_argument(
        "-ml", "--match-lines",
        dest="match_lines",
        type=str,
        default="",
        help="Line counts to match (comma-separated)",
    )
    filter_group.add_argument(
        "-fl", "--filter-lines",
        dest="filter_lines",
        type=str,
        default="",
        help="Line counts to filter out (comma-separated)",
    )
    filter_group.add_argument(
        "-mr", "--match-regex",
        dest="match_regex",
        type=str,
        default=None,
        help="Regular expression pattern that response bodies MUST match",
    )
    filter_group.add_argument(
        "-fr", "--filter-regex",
        dest="filter_regex",
        type=str,
        default=None,
        help="Regular expression pattern to filter out responses",
    )
    filter_group.add_argument(
        "--filter-text",
        dest="filter_text",
        type=str,
        default=None,
        help="Filter responses containing specified substring in the body",
    )
    filter_group.add_argument(
        "--no-wildcard",
        dest="no_wildcard",
        action="store_true",
        help="Disable automatic soft-404 and wildcard calibration",
    )

    # Heuristics & Profiling
    heur_group = parser.add_argument_group("Technology Profiling, Auditing & Heuristics")
    heur_group.add_argument(
        "--no-tech",
        dest="no_tech",
        action="store_true",
        help="Disable automatic technology & CMS profiling",
    )
    heur_group.add_argument(
        "--no-audit",
        dest="no_audit",
        action="store_true",
        help="Disable defensive security posture and HTTP header evaluation",
    )
    heur_group.add_argument(
        "--no-cert",
        dest="no_cert",
        action="store_true",
        help="Disable SSL/TLS certificate inspection",
    )
    heur_group.add_argument(
        "--no-net-diag",
        dest="no_net_diag",
        action="store_true",
        help="Disable network DNS resolution and TCP latency diagnostics",
    )
    heur_group.add_argument(
        "--no-harvest",
        dest="no_harvest",
        action="store_true",
        help="Disable automatic route harvesting from robots.txt and sitemap.xml",
    )
    heur_group.add_argument(
        "--no-tree",
        dest="no_tree",
        action="store_true",
        help="Disable rendering hierarchical directory tree at scan conclusion",
    )
    heur_group.add_argument(
        "--audit-vulns",
        dest="audit_vulns",
        action="store_true",
        default=True,
        help="Perform automated non-destructive security assertions and vulnerability validation (default: enabled)",
    )
    heur_group.add_argument(
        "--no-vuln-validate",
        dest="no_vuln_validate",
        action="store_true",
        help="Disable automated security assertions and vulnerability validation",
    )
    heur_group.add_argument(
        "--no-title",
        dest="no_title",
        action="store_true",
        help="Disable HTML page title extraction",
    )

    # Request Customization
    req_group = parser.add_argument_group("HTTP Customization & Proxies")
    req_group.add_argument(
        "-a", "--user-agent",
        dest="user_agent",
        type=str,
        default=None,
        help="Custom HTTP User-Agent header string",
    )
    req_group.add_argument(
        "-H", "--header",
        dest="headers",
        action="append",
        help="Custom header in 'Key: Value' format (can be specified multiple times)",
    )
    req_group.add_argument(
        "-b", "--cookie",
        dest="cookie",
        type=str,
        default=None,
        help="HTTP Cookie string (e.g., 'sessionid=xyz; token=123')",
    )
    req_group.add_argument(
        "-p", "--proxy",
        dest="proxy",
        type=str,
        default=None,
        help="HTTP/HTTPS/SOCKS proxy URL (e.g., http://127.0.0.1:8080)",
    )
    req_group.add_argument(
        "-k", "--insecure",
        dest="insecure",
        action="store_true",
        default=False,
        help="Explicitly disable SSL certificate verification (default behavior)",
    )
    req_group.add_argument(
        "--verify-ssl",
        dest="verify_ssl",
        action="store_true",
        help="Strictly enforce SSL certificate verification",
    )
    req_group.add_argument(
        "--follow-redirects",
        dest="follow_redirects",
        action="store_true",
        help="Follow HTTP redirects automatically (default: logs redirect target without following)",
    )

    # Output & Display
    out_group = parser.add_argument_group("Output & Reporting")
    out_group.add_argument(
        "-o", "--output",
        dest="output",
        type=str,
        default=None,
        help="Path to save exported report file (HTML, JSON, CSV, Markdown, or TXT)",
    )
    out_group.add_argument(
        "-f", "--format",
        dest="format",
        choices=["table", "html", "json", "csv", "markdown", "txt"],
        default="table",
        help="Report export format (default: table; recommended: html)",
    )
    out_group.add_argument(
        "--save-profile",
        dest="save_profile",
        type=str,
        default=None,
        help="Save current configuration options to a JSON profile file",
    )
    out_group.add_argument(
        "--checkpoint",
        dest="checkpoint",
        type=str,
        default=None,
        help="Save scan session state to a JSON checkpoint file upon completion or interruption",
    )
    out_group.add_argument(
        "-q", "--quiet",
        dest="quiet",
        action="store_true",
        help="Quiet mode: suppress banners, progress counters, and print findings only",
    )
    out_group.add_argument(
        "-v", "--version",
        action="version",
        version=f"WebAdminMapper v{__version__} - Authored by Ahmed Wael",
    )

    return parser


def parse_headers_list(raw_headers: Optional[List[str]]) -> dict:
    """Parse list of 'Key: Value' strings into header dictionary."""
    headers = {}
    if not raw_headers:
        return headers
    for h in raw_headers:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def run_scanner(config: ScanConfig) -> int:
    """
    Main orchestration loop for WebAdminMapper.
    Authored and designed by Ahmed Wael.
    """
    reporter = ScanReporter(config)
    requester = HTTPRequester(config)

    # Banner & Info
    if not config.quiet:
        print(BANNER)
        print(f"  {Colors.BOLD}[*] Target Host       :{Colors.RESET} {config.target_url}")
        print(f"  {Colors.BOLD}[*] Worker Threads    :{Colors.RESET} {config.threads}")
        print(f"  {Colors.BOLD}[*] Wordlist Strategy :{Colors.RESET} {config.wordlist_type}")
        if config.wordlist_path:
            w_disp = "STDIN" if config.wordlist_path == "-" else config.wordlist_path
            print(f"  {Colors.BOLD}[*] Custom Wordlist   :{Colors.RESET} {w_disp}")
        if config.extensions:
            print(f"  {Colors.BOLD}[*] Active Extensions :{Colors.RESET} {', '.join(config.extensions)}")
        if config.recursive:
            print(f"  {Colors.BOLD}[*] Recursion Enabled :{Colors.RESET} Depth <= {config.max_depth}")
        if config.proxy:
            print(f"  {Colors.BOLD}[*] Proxy Upstream    :{Colors.RESET} {config.proxy}")
        print(f"  {Colors.BOLD}[*] Lead Developer    :{Colors.RESET} Ahmed Wael\n")

    # Session Checkpoint Resumption
    initial_completed: Optional[Set[str]] = None
    initial_results: Optional[List[ScanResult]] = None
    if config.resume_checkpoint:
        try:
            chk_data = SessionCheckpoint.load(config.resume_checkpoint)
            initial_completed = set(chk_data.get("completed_paths", []))
            initial_results = SessionCheckpoint.deserialize_results(chk_data.get("results", []))
            if not config.quiet:
                print(f"  {Colors.GREEN}[+] Resumed From Checkpoint:{Colors.RESET} {len(initial_completed)} completed paths, {len(initial_results)} findings loaded")
        except Exception as exc:
            print(f"  {Colors.RED}[!] Checkpoint Load Failed  :{Colors.RESET} {exc}")

    # Baseline & Heuristics Calibration
    if not config.quiet:
        sys.stdout.write(f"  {Colors.YELLOW}[*] Probing target & calibrating heuristics...{Colors.RESET}\r")
        sys.stdout.flush()

    calib = requester.calibrate_heuristics()

    # Network & DNS Diagnostics
    network_diag: Optional[NetworkDiagResult] = None
    if config.network_diag:
        network_diag = NetworkDiagnostics.inspect(config.target_url, timeout=config.timeout)

    # Route Harvesting (robots.txt and sitemap.xml)
    harvested_routes: Set[str] = set()
    if config.harvest_routes:
        harvester = RouteHarvester(config.target_url)
        r_routes = harvester.harvest_robots_txt(requester)
        s_routes = harvester.harvest_sitemap_xml(requester)
        harvested_routes.update(r_routes)
        harvested_routes.update(s_routes)

    # TLS Certificate Inspection
    cert_info: Optional[CertificateInfo] = None
    if config.cert_inspect and config.target_url.startswith("https://"):
        cert_info = CertInspector.inspect(config.target_url, timeout=config.timeout)

    # Security Posture Evaluation
    security_audit: Optional[SecurityAuditResult] = None
    if config.security_audit and requester.base_headers:
        security_audit = SecurityAuditor().audit(config.target_url, requester.base_headers)

    if not config.quiet:
        if network_diag and network_diag.primary_ip:
            rev_txt = f" ({network_diag.reverse_dns})" if network_diag.reverse_dns else ""
            print(f"  {Colors.GREEN}[+] Network Resolution    :{Colors.RESET} {network_diag.primary_ip}{rev_txt} ({network_diag.tcp_latency_ms:.1f}ms TCP)")
        if cert_info:
            exp_col = Colors.GREEN if cert_info.days_remaining > 30 else Colors.RED
            print(f"  {Colors.GREEN}[+] TLS Certificate       :{Colors.RESET} {cert_info.issuer} ({exp_col}{cert_info.days_remaining}d left{Colors.RESET}) [{cert_info.tls_version}]")
        if security_audit:
            grade_col = Colors.GREEN if security_audit.grade in ("A+", "A") else Colors.YELLOW if security_audit.grade == "B" else Colors.RED
            print(f"  {Colors.GREEN}[+] Defensive Posture     :{Colors.RESET} Grade {grade_col}{security_audit.grade}{Colors.RESET} ({security_audit.score}/100)")
        if calib["techs"]:
            print(f"  {Colors.GREEN}[+] Technologies Detected :{Colors.RESET} {', '.join(calib['techs'])}")
        if calib["waf"]:
            print(f"  {Colors.YELLOW}[!] WAF / CDN Identified  :{Colors.RESET} {calib['waf']}")
        if calib["soft404_active"]:
            print(f"  {Colors.GREEN}[+] Soft-404 Calibration  :{Colors.RESET} Active (Adaptive signature suppression)")
        if harvested_routes:
            print(f"  {Colors.GREEN}[+] Harvested Routes      :{Colors.RESET} {len(harvested_routes)} paths (robots.txt / sitemap.xml)")

        print(f"\n  {Colors.BOLD}{Colors.BLUE}{'STATUS':<8}  {'SIZE':>7}  {'WORDS':>5}  {'LINES':>5}  {'LATENCY':>7}  {'PATH / DETAILS'}{Colors.RESET}")
        print(f"  {Colors.BLUE}{'-' * 74}{Colors.RESET}")

    # Progress Callback
    def on_progress(done: int, total: int, speed: float, eta_sec: float, current_path: str, found_count: int) -> None:
        if config.quiet:
            return
        percent = (done / max(1, total)) * 100.0
        eta_m, eta_s = divmod(int(eta_sec), 60)
        eta_str = f"{eta_m:02d}:{eta_s:02d}"
        clean_path = current_path if len(current_path) <= 22 else current_path[:19] + "..."
        line = (
            f"\r  {Colors.DIM}[{done}/{total} ({percent:4.1f}%)] "
            f"[{speed:4.1f} req/s] "
            f"[ETA: {eta_str}] "
            f"[Found: {found_count}] "
            f"Probing: {clean_path:<22}{Colors.RESET}"
        )
        sys.stdout.write(line)
        sys.stdout.flush()

    # Result Callback
    def on_result(res: ScanResult) -> None:
        reporter.print_result_line(res)

    # Execution Engine
    engine = ExecutionEngine(config, requester)
    start_time = time.perf_counter()
    results = engine.run(
        on_result=on_result,
        on_progress=on_progress,
        extra_seed_paths=harvested_routes,
        initial_completed_paths=initial_completed,
        initial_results=initial_results,
        checkpoint_path=config.checkpoint_file,
    )
    duration = time.perf_counter() - start_time

    # Clear progress line
    if not config.quiet:
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    # Automated Security Assertions & Vulnerability Validations
    security_assertions: List[SecurityAssertion] = []
    if config.validate_vulns and results:
        validator = SecurityAssertionValidator()
        security_assertions = validator.validate_all(results)

    # Summary
    if not config.quiet:
        reporter.print_summary(
            results=results,
            total_requests=engine.total_requests,
            duration_sec=duration,
            sitemap=engine.sitemap,
            detected_techs=requester.discovered_techs,
            detected_waf=requester.detected_waf,
            security_audit=security_audit,
            cert_info=cert_info,
            network_diag=network_diag,
            security_assertions=security_assertions,
            crawled_routes_count=len(harvested_routes),
        )

    # Export Report
    if config.output_file:
        out_saved = reporter.export_results(
            results=results,
            duration_sec=duration,
            detected_techs=requester.discovered_techs,
            detected_waf=requester.detected_waf,
            sitemap=engine.sitemap,
            security_audit=security_audit,
            cert_info=cert_info,
            network_diag=network_diag,
            security_assertions=security_assertions,
        )
        if out_saved and not config.quiet:
            print(f"  {Colors.GREEN}[+] Report successfully exported to:{Colors.RESET} {out_saved}")

    if config.checkpoint_file and not config.quiet:
        print(f"  {Colors.GREEN}[+] Session checkpoint preserved at:{Colors.RESET} {config.checkpoint_file}")

    return 0 if not engine.interrupted else 130


def main() -> None:
    """Entrypoint for CLI execution."""
    parser = build_parser()
    args = parser.parse_args()

    # Load target URL from checkpoint if resuming without explicit URL
    if args.resume and not args.url and not args.profile:
        try:
            chk_data = SessionCheckpoint.load(args.resume)
            args.url = chk_data.get("metadata", {}).get("target_url")
        except Exception as exc:
            print(f"{Colors.RED}Checkpoint Load Error: {exc}{Colors.RESET}")
            sys.exit(1)

    # Load configuration from profile if requested
    if args.profile:
        try:
            config = ScanConfig.load_profile(args.profile)
            if args.url:
                config.target_url = ScanConfig.normalize_url(args.url)
            if args.checkpoint:
                config.checkpoint_file = args.checkpoint
            if args.resume:
                config.resume_checkpoint = args.resume
        except Exception as exc:
            print(f"{Colors.RED}Profile Load Error: {exc}{Colors.RESET}")
            sys.exit(1)
    else:
        if not args.url:
            parser.print_help()
            print(f"\n{Colors.RED}Error: Target URL (-u / --url), --profile, or --resume is required.{Colors.RESET}")
            sys.exit(1)

        # Parse extensions
        extensions = [x.strip() for x in args.extensions.split(",") if x.strip()]

        # Parse status codes and sizes
        match_codes = parse_csv_ints(args.match_codes) if args.match_codes else set(DEFAULT_MATCH_CODES)
        filter_codes = parse_csv_ints(args.filter_codes) if args.filter_codes else set(DEFAULT_FILTER_CODES)
        match_sizes = parse_csv_ints(args.match_size)
        filter_sizes = parse_csv_ints(args.filter_size)
        match_words = parse_csv_ints(args.match_words)
        filter_words = parse_csv_ints(args.filter_words)
        match_lines = parse_csv_ints(args.match_lines)
        filter_lines = parse_csv_ints(args.filter_lines)

        verify_ssl = args.verify_ssl and not args.insecure

        try:
            config = ScanConfig(
                target_url=args.url,
                threads=args.threads,
                timeout=args.timeout,
                delay=args.delay,
                retries=args.retries,
                user_agent=args.user_agent or ScanConfig.user_agent,
                headers=parse_headers_list(args.headers),
                cookies=args.cookie,
                proxy=args.proxy,
                verify_ssl=verify_ssl,
                follow_redirects=args.follow_redirects,
                match_codes=match_codes,
                filter_codes=filter_codes,
                match_sizes=match_sizes,
                filter_sizes=filter_sizes,
                match_words=match_words,
                filter_words=filter_words,
                match_lines=match_lines,
                filter_lines=filter_lines,
                filter_text=args.filter_text,
                match_regex=args.match_regex,
                filter_regex=args.filter_regex,
                extensions=extensions,
                prefix=args.prefix,
                suffix=args.suffix,
                wordlist_path=args.wordlist,
                wordlist_type=args.mode,
                case_transform=args.case_transform,
                recursive=args.recursive,
                max_depth=args.max_depth,
                output_file=args.output,
                output_format=args.format,
                quiet=args.quiet,
                extract_title=not args.no_title,
                show_tree=not args.no_tree,
                wildcard_detection=not args.no_wildcard,
                tech_detect=not args.no_tech,
                harvest_routes=not args.no_harvest,
                security_audit=not args.no_audit,
                cert_inspect=not args.no_cert,
                network_diag=not args.no_net_diag,
                validate_vulns=not args.no_vuln_validate,
                checkpoint_file=args.checkpoint,
                resume_checkpoint=args.resume,
            )
        except Exception as exc:
            print(f"{Colors.RED}Configuration Error: {exc}{Colors.RESET}")
            sys.exit(1)

    # Save profile if requested
    if args.save_profile:
        try:
            config.save_profile(args.save_profile)
            print(f"{Colors.GREEN}[+] Configuration profile saved to: {args.save_profile}{Colors.RESET}")
        except Exception as exc:
            print(f"{Colors.RED}Profile Save Error: {exc}{Colors.RESET}")
            sys.exit(1)

    exit_code = run_scanner(config)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
