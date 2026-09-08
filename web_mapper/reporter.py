"""
WebAdminMapper - Enterprise Reporting & Export Module
=====================================================
Generates terminal tables, interactive HTML dashboards, JSON APIs,
CSV spreadsheets, and Markdown audit reports with security posture analysis.

Developer & Author: Ahmed Wael
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import csv
import html
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .cert_inspector import CertificateInfo
from .compliance import ComplianceReport
from .config import ScanConfig
from .network_diag import NetworkDiagResult
from .requester import ScanResult
from .security_assertions import SecurityAssertion
from .security_audit import SecurityAuditResult
from .sitemap import SiteMapTree

__author__ = "Ahmed Wael"
__copyright__ = "Copyright (c) 2026, Ahmed Wael"


class Colors:
    """ANSI terminal styling sequences."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def colorize_status(code: int) -> str:
    """Colorize HTTP status codes according to category."""
    badge = f"[{code}]"
    if 200 <= code < 300:
        return f"{Colors.GREEN}{badge}{Colors.RESET}"
    elif 300 <= code < 400:
        return f"{Colors.CYAN}{badge}{Colors.RESET}"
    elif code in (401, 403):
        return f"{Colors.YELLOW}{badge}{Colors.RESET}"
    elif 400 <= code < 500:
        return f"{Colors.DIM}{badge}{Colors.RESET}"
    elif 500 <= code < 600:
        return f"{Colors.RED}{badge}{Colors.RESET}"
    return f"{Colors.WHITE}{badge}{Colors.RESET}"


def calculate_latency_percentiles(latencies: List[float]) -> Dict[str, float]:
    """Calculate min, max, mean, p50, p90, and p99 latencies in ms."""
    if not latencies:
        return {"min": 0.0, "max": 0.0, "mean": 0.0, "p50": 0.0, "p90": 0.0, "p99": 0.0}
    s = sorted(latencies)
    n = len(s)
    return {
        "min": round(s[0], 2),
        "max": round(s[-1], 2),
        "mean": round(sum(s) / n, 2),
        "p50": round(s[int(n * 0.50)], 2),
        "p90": round(s[min(n - 1, int(n * 0.90))], 2),
        "p99": round(s[min(n - 1, int(n * 0.99))], 2),
    }


class ScanReporter:
    """
    Advanced Reporting Engine with HTML, JSON, CSV, and Markdown generators.
    Authored and designed by Ahmed Wael.
    """

    def __init__(self, config: ScanConfig):
        self.config = config

    def print_result_line(self, res: ScanResult) -> None:
        """Print a single discovered endpoint in clean tabular format."""
        status_badge = colorize_status(res.status_code)
        size_str = f"{res.content_length:>7}B"
        words_str = f"{res.word_count:>4}w"
        lines_str = f"{res.line_count:>4}l"
        time_str = f"{res.response_time_ms:>5.0f}ms"
        path_str = f"{Colors.BOLD}{res.path}{Colors.RESET}"

        details = []
        if res.redirect_location:
            details.append(f"-> {Colors.CYAN}{res.redirect_location}{Colors.RESET}")
        if res.title:
            details.append(f'"{Colors.DIM}{res.title}{Colors.RESET}"')

        detail_str = f" ({' '.join(details)})" if details else ""
        sys.stdout.write(
            f"\r  {status_badge}  {size_str}  {words_str}  {lines_str}  {time_str}  {path_str}{detail_str}\n"
        )
        sys.stdout.flush()

    def print_summary(
        self,
        results: List[ScanResult],
        total_requests: int,
        duration_sec: float,
        sitemap: Optional[SiteMapTree] = None,
        detected_techs: Optional[List[str]] = None,
        detected_waf: Optional[str] = None,
        security_audit: Optional[SecurityAuditResult] = None,
        cert_info: Optional[CertificateInfo] = None,
        network_diag: Optional[NetworkDiagResult] = None,
        security_assertions: Optional[List[SecurityAssertion]] = None,
        compliance_report: Optional[ComplianceReport] = None,
        crawled_routes_count: int = 0,
    ) -> None:
        """Display comprehensive scan summary, security posture, and hierarchy."""
        req_per_sec = total_requests / max(0.001, duration_sec)
        status_counts = Counter(r.status_code for r in results)
        status_str = ", ".join(f"{k}: {v}" for k, v in sorted(status_counts.items())) or "None"

        latencies = [r.response_time_ms for r in results]
        lat_stats = calculate_latency_percentiles(latencies)

        print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 74}{Colors.RESET}")
        print(f"{Colors.BOLD}  SCAN SUMMARY & METRICS{Colors.RESET}")
        print(f"{Colors.BLUE}{'=' * 74}{Colors.RESET}")
        print(f"  Target Host       : {self.config.target_url}")
        if network_diag and network_diag.primary_ip:
            rev_str = f" ({network_diag.reverse_dns})" if network_diag.reverse_dns else ""
            cname_str = f" [CNAME: {network_diag.canonical_name}]" if network_diag.canonical_name and network_diag.canonical_name != network_diag.hostname else ""
            print(f"  Network Host      : {Colors.CYAN}{network_diag.primary_ip}{Colors.RESET}{rev_str}{cname_str} ({network_diag.tcp_latency_ms:.1f}ms TCP)")
        print(f"  Discovered Routes : {Colors.GREEN}{len(results)}{Colors.RESET}")
        print(f"  Total Requests    : {total_requests}")
        print(f"  Elapsed Duration  : {duration_sec:.2f}s ({req_per_sec:.1f} req/s)")
        print(f"  Status Breakdown  : {status_str}")
        print(f"  Latency Metrics   : avg={lat_stats['mean']}ms, p50={lat_stats['p50']}ms, p90={lat_stats['p90']}ms, p99={lat_stats['p99']}ms")

        if crawled_routes_count > 0:
            print(f"  Harvested Routes  : {Colors.CYAN}{crawled_routes_count} paths (robots.txt / sitemap.xml){Colors.RESET}")
        if detected_waf:
            print(f"  WAF Protection    : {Colors.YELLOW}{detected_waf}{Colors.RESET}")
        if detected_techs:
            print(f"  Detected Tech     : {Colors.CYAN}{', '.join(detected_techs)}{Colors.RESET}")

        if cert_info:
            exp_color = Colors.GREEN if cert_info.days_remaining > 30 else Colors.RED
            print(f"  TLS Certificate   : {cert_info.issuer} ({exp_color}{cert_info.days_remaining} days remaining{Colors.RESET}) [{cert_info.tls_version}]")

        if security_audit:
            grade_color = Colors.GREEN if security_audit.grade in ("A+", "A") else Colors.YELLOW if security_audit.grade == "B" else Colors.RED
            print(f"  Security Posture  : Grade {grade_color}{security_audit.grade}{Colors.RESET} ({security_audit.score}/100) - {len(security_audit.findings)} findings")

        if security_assertions:
            high_count = sum(1 for a in security_assertions if a.severity == "HIGH")
            med_count = sum(1 for a in security_assertions if a.severity == "MEDIUM")
            low_count = sum(1 for a in security_assertions if a.severity in ("LOW", "INFO"))
            high_disp = f"{Colors.RED}{high_count} High{Colors.RESET}" if high_count else "0 High"
            med_disp = f"{Colors.YELLOW}{med_count} Medium{Colors.RESET}" if med_count else "0 Medium"
            print(f"  Security Assertions: {high_disp}, {med_disp}, {low_count} Low/Info ({len(security_assertions)} findings)")

        if compliance_report:
            c_col = (
                Colors.GREEN if compliance_report.compliance_score >= 85.0
                else Colors.YELLOW if compliance_report.compliance_score >= 60.0
                else Colors.RED
            )
            print(f"  Compliance Baseline: Grade {c_col}{compliance_report.compliance_grade}{Colors.RESET} ({compliance_report.compliance_score:.1f}%) - {compliance_report.passed_rules} Passed, {compliance_report.failed_rules} Failed [Benchmark: {compliance_report.benchmark.upper()}]")
            if compliance_report.benchmark_scores:
                bm_summary = ", ".join(f"{k.split()[0]}={v}%" for k, v in compliance_report.benchmark_scores.items())
                print(f"  Benchmark Scores  : {bm_summary}")

        print(f"  Developer/Author  : {Colors.BOLD}Ahmed Wael{Colors.RESET}")
        print(f"{Colors.BLUE}{'=' * 74}{Colors.RESET}")

        # ASCII Site Map Tree
        if self.config.show_tree and sitemap and results:
            print(f"\n{Colors.BOLD}  HIERARCHICAL DIRECTORY TREE:{Colors.RESET}")
            print(f"{Colors.DIM}{'-' * 74}{Colors.RESET}")
            print(sitemap.render_ascii())
            print(f"{Colors.DIM}{'-' * 74}{Colors.RESET}\n")

    def export_results(
        self,
        results: List[ScanResult],
        duration_sec: float,
        detected_techs: Optional[List[str]] = None,
        detected_waf: Optional[str] = None,
        sitemap: Optional[SiteMapTree] = None,
        security_audit: Optional[SecurityAuditResult] = None,
        cert_info: Optional[CertificateInfo] = None,
        network_diag: Optional[NetworkDiagResult] = None,
        security_assertions: Optional[List[SecurityAssertion]] = None,
        compliance_report: Optional[ComplianceReport] = None,
    ) -> Optional[Path]:
        """Export results to configured destination file."""
        if not self.config.output_file:
            return None

        out_path = Path(self.config.output_file).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        fmt = self.config.output_format.lower()

        if fmt == "html":
            self._save_html(out_path, results, duration_sec, detected_techs, detected_waf, sitemap, security_audit, cert_info, network_diag, security_assertions, compliance_report)
        elif fmt == "json":
            self._save_json(out_path, results, duration_sec, detected_techs, detected_waf, security_audit, cert_info, network_diag, security_assertions, compliance_report)
        elif fmt == "csv":
            self._save_csv(out_path, results, security_assertions, compliance_report)
        elif fmt == "markdown":
            self._save_markdown(out_path, results, duration_sec, detected_techs, detected_waf, security_audit, cert_info, network_diag, security_assertions, compliance_report)
        else:
            self._save_txt(out_path, results)

        return out_path

    def _save_json(
        self,
        path: Path,
        results: List[ScanResult],
        duration_sec: float,
        techs: Optional[List[str]],
        waf: Optional[str],
        sec: Optional[SecurityAuditResult],
        cert: Optional[CertificateInfo],
        network_diag: Optional[NetworkDiagResult] = None,
        security_assertions: Optional[List[SecurityAssertion]] = None,
        compliance_report: Optional[ComplianceReport] = None,
    ) -> None:
        latencies = [r.response_time_ms for r in results]
        data = {
            "metadata": {
                "author": __author__,
                "tool": "WebAdminMapper",
                "version": "1.1.0",
                "target": self.config.target_url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(duration_sec, 2),
                "total_found": len(results),
                "detected_technologies": techs or [],
                "detected_waf": waf,
                "latency_percentiles": calculate_latency_percentiles(latencies),
                "network_diagnostics": network_diag.to_dict() if network_diag else None,
                "tls_certificate": cert.to_dict() if cert else None,
                "security_audit": sec.to_dict() if sec else None,
                "security_assertions": [a.to_dict() for a in (security_assertions or [])],
                "compliance_report": compliance_report.to_dict() if compliance_report else None,
            },
            "configuration": self.config.to_dict(),
            "results": [r.to_dict() for r in results],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _save_csv(
        self,
        path: Path,
        results: List[ScanResult],
        security_assertions: Optional[List[SecurityAssertion]] = None,
        compliance_report: Optional[ComplianceReport] = None,
    ) -> None:
        fieldnames = [
            "path",
            "url",
            "status_code",
            "content_length",
            "word_count",
            "line_count",
            "response_time_ms",
            "title",
            "redirect_location",
            "content_type",
            "server",
            "timestamp",
        ]
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for r in results:
                row = r.to_dict()
                row.pop("author", None)
                row.pop("waf_detected", None)
                row.pop("technologies", None)
                writer.writerow(row)

        if security_assertions:
            assertions_path = path.with_name(f"{path.stem}_assertions.csv")
            self._save_assertions_csv(assertions_path, security_assertions)

        if compliance_report and compliance_report.findings:
            compliance_path = path.with_name(f"{path.stem}_compliance.csv")
            self._save_compliance_csv(compliance_path, compliance_report)

    def _save_assertions_csv(self, path: Path, security_assertions: List[SecurityAssertion]) -> None:
        fieldnames = [
            "rule_id",
            "severity",
            "classification",
            "confidence",
            "category",
            "title",
            "description",
            "endpoint",
            "evidence",
            "impact",
            "manual_verification_required",
            "remediation",
        ]
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for a in security_assertions:
                row = a.to_dict()
                row.pop("author", None)
                writer.writerow(row)

    def _save_compliance_csv(self, path: Path, compliance_report: ComplianceReport) -> None:
        fieldnames = [
            "rule_id",
            "benchmark",
            "category",
            "severity",
            "status",
            "title",
            "endpoint",
            "evidence",
            "detection_logic",
            "limitations",
            "remediation",
        ]
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for cf in compliance_report.findings:
                row = cf.to_dict()
                row.pop("author", None)
                writer.writerow(row)

    def _save_markdown(
        self,
        path: Path,
        results: List[ScanResult],
        duration_sec: float,
        techs: Optional[List[str]],
        waf: Optional[str],
        sec: Optional[SecurityAuditResult],
        cert: Optional[CertificateInfo],
        network_diag: Optional[NetworkDiagResult] = None,
        security_assertions: Optional[List[SecurityAssertion]] = None,
        compliance_report: Optional[ComplianceReport] = None,
    ) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# WebAdminMapper Audit Report\n\n")
            f.write(f"- **Target URL:** `{self.config.target_url}`\n")
            f.write(f"- **Developer & Author:** **{__author__}**\n")
            f.write(f"- **Scan Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"- **Duration:** {duration_sec:.2f} seconds\n")
            f.write(f"- **Total Discovered Routes:** {len(results)}\n")
            if network_diag and network_diag.primary_ip:
                rev_txt = f" ({network_diag.reverse_dns})" if network_diag.reverse_dns else ""
                f.write(f"- **Host Resolution:** `{network_diag.primary_ip}`{rev_txt} (Latency: {network_diag.tcp_latency_ms:.1f}ms)\n")
            if waf:
                f.write(f"- **WAF Protection:** {waf}\n")
            if techs:
                f.write(f"- **Detected Technologies:** {', '.join(techs)}\n")
            if cert:
                f.write(f"- **TLS Certificate:** {cert.issuer} (Expires in {cert.days_remaining} days, {cert.tls_version})\n")
            if sec:
                f.write(f"- **Security Posture Grade:** **{sec.grade}** ({sec.score}/100)\n\n")
                f.write("### Defensive Header Findings\n\n")
                for finding in sec.findings:
                    f.write(f"- **[{finding.severity}] {finding.name}:** {finding.description} *(Fix: {finding.recommendation})*\n")

            if compliance_report:
                f.write("\n### Defensive Security Assessment & Compliance Baseline Audit\n\n")
                if getattr(compliance_report, "disclaimer", None):
                    f.write(f"> **Notice:** {compliance_report.disclaimer}\n\n")
                f.write(f"- **Standard / Benchmark:** `{compliance_report.benchmark.upper()}`\n")
                f.write(f"- **Compliance Grade:** **{compliance_report.compliance_grade}** ({compliance_report.compliance_score:.1f}%)\n")
                f.write(f"- **Control Statistics:** {compliance_report.passed_rules} Passed, {compliance_report.failed_rules} Failed\n")
                if compliance_report.benchmark_scores:
                    bm_line = " | ".join(f"{k}: {v}%" for k, v in compliance_report.benchmark_scores.items())
                    f.write(f"- **Benchmark Breakdown:** {bm_line}\n")
                if compliance_report.findings:
                    f.write("\n| Rule ID | Benchmark | Severity | Status | Control Title | Endpoint | Evidence | Detection Logic | Limitations | Remediation |\n")
                    f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
                    for cf in compliance_report.findings:
                        lim = getattr(cf, "limitations", "") or "N/A"
                        det = getattr(cf, "detection_logic", "") or "N/A"
                        f.write(f"| `{cf.rule_id}` | {cf.benchmark} | `{cf.severity}` | `{cf.status}` | **{cf.title}** | `{cf.endpoint}` | {cf.evidence} | {det} | {lim} | {cf.remediation} |\n")

            if security_assertions:
                f.write("\n### Automated Security Assertions & Vulnerability Validations\n\n")
                f.write("| Severity | Classification | Confidence | Category | Assertion / Finding | Endpoint | Evidence | Impact | Manual Verif. | Remediation |\n")
                f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
                for a in security_assertions:
                    m_ver = "Yes" if a.manual_verification_required else "No"
                    conf_disp = f"{a.confidence:.2f}" if isinstance(a.confidence, (int, float)) else str(a.confidence)
                    f.write(f"| `{a.severity}` | {a.classification} | {conf_disp} | {a.category} | **{a.title}** | `{a.endpoint}` | {a.evidence} | {a.impact} | {m_ver} | {a.remediation} |\n")

            f.write("\n## Discovered Endpoints\n\n")
            f.write("| Status | Size | Words | Time | Path | Title / Redirect |\n")
            f.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
            for r in results:
                title = r.title.replace("|", "/") if r.title else ""
                red = f"-> {r.redirect_location}" if r.redirect_location else ""
                detail = f"{red} {title}".strip()
                f.write(f"| `{r.status_code}` | {r.content_length}B | {r.word_count} | {r.response_time_ms:.1f}ms | `{r.path}` | {detail} |\n")

    def _save_txt(self, path: Path, results: List[ScanResult]) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# WebAdminMapper Discovery Results\n")
            f.write(f"# Developer & Author: Ahmed Wael\n")
            f.write(f"# Target: {self.config.target_url}\n")
            f.write(f"# Date: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"# {'-' * 70}\n\n")
            for r in results:
                extra = []
                if r.redirect_location:
                    extra.append(f"-> {r.redirect_location}")
                if r.title:
                    extra.append(f'"{r.title}"')
                extra_str = f" ({' '.join(extra)})" if extra else ""
                f.write(f"[{r.status_code}] {r.content_length:>7}B  {r.path}{extra_str}\n")

    def _save_html(
        self,
        path: Path,
        results: List[ScanResult],
        duration_sec: float,
        techs: Optional[List[str]],
        waf: Optional[str],
        sitemap: Optional[SiteMapTree],
        sec: Optional[SecurityAuditResult],
        cert: Optional[CertificateInfo],
        network_diag: Optional[NetworkDiagResult] = None,
        security_assertions: Optional[List[SecurityAssertion]] = None,
        compliance_report: Optional[ComplianceReport] = None,
    ) -> None:
        """Generate a sleek, responsive HTML dashboard report."""
        tech_badges = "".join(f'<span class="badge badge-tech">{html.escape(t)}</span>' for t in (techs or [])) or "<em>None detected</em>"
        waf_badge = f'<span class="badge badge-waf">{html.escape(waf)}</span>' if waf else "<em>None detected</em>"
        tree_ascii = html.escape(sitemap.render_ascii()) if sitemap else ""

        latencies = [r.response_time_ms for r in results]
        lat_stats = calculate_latency_percentiles(latencies)

        net_html = ""
        if network_diag and network_diag.primary_ip:
            rev_info = f" &bull; <strong>Reverse:</strong> {html.escape(network_diag.reverse_dns)}" if network_diag.reverse_dns else ""
            cname_info = f" &bull; <strong>CNAME:</strong> {html.escape(network_diag.canonical_name)}" if network_diag.canonical_name and network_diag.canonical_name != network_diag.hostname else ""
            net_html = f"""
            <div class="metric-card">
              <div class="metric-title">Network Diagnostics</div>
              <div style="font-size: 14px; margin-top: 6px;">
                <strong>IP:</strong> <code>{html.escape(network_diag.primary_ip)}</code>{rev_info}{cname_info}
              </div>
              <div style="font-size: 12px; color: #8b949e; margin-top: 4px;">
                <strong>TCP Latency:</strong> {network_diag.tcp_latency_ms:.1f} ms &bull; <strong>Port:</strong> {network_diag.port}
              </div>
            </div>
            """

        comp_card_html = ""
        comp_table_html = ""
        if compliance_report:
            c_col = "#3fb950" if compliance_report.compliance_score >= 85.0 else "#d29922" if compliance_report.compliance_score >= 60.0 else "#f85149"
            comp_card_html = f"""
            <div class="metric-card">
              <div class="metric-title">Compliance Baseline</div>
              <div class="metric-value" style="color: {c_col}; font-size: 20px; font-weight: bold;">
                {html.escape(compliance_report.compliance_grade)} <span style="font-size: 13px; color: #8b949e;">({compliance_report.compliance_score:.1f}%)</span>
              </div>
              <div style="font-size: 12px; color: #8b949e; margin-top: 4px;">
                {compliance_report.passed_rules} Passed &bull; {compliance_report.failed_rules} Failed &bull; Standard: {html.escape(compliance_report.benchmark.upper())}
              </div>
            </div>
            """
            if compliance_report.findings:
                cf_rows = []
                for cf in compliance_report.findings:
                    badge = "st-5xx" if cf.severity == "HIGH" else "st-4xx" if cf.severity == "MEDIUM" else "st-3xx"
                    lim_text = getattr(cf, "limitations", "") or "N/A"
                    det_logic = getattr(cf, "detection_logic", "") or "N/A"
                    cf_rows.append(f"""
                    <tr>
                      <td><code>{html.escape(cf.rule_id)}</code></td>
                      <td><span class="badge {badge}">{html.escape(cf.severity)}</span></td>
                      <td><strong>{html.escape(cf.benchmark)}</strong></td>
                      <td><strong>{html.escape(cf.title)}</strong></td>
                      <td><code>{html.escape(cf.endpoint)}</code></td>
                      <td><span style="font-size: 12px; color: #8b949e;">{html.escape(cf.evidence)}</span></td>
                      <td><span style="font-size: 12px; color: #79c0ff;">{html.escape(det_logic)}</span></td>
                      <td><span style="font-size: 12px; color: #8b949e;">{html.escape(lim_text)}</span></td>
                      <td><code style="color: #7ee787;">{html.escape(cf.remediation)}</code></td>
                    </tr>
                    """)
                disclaimer_html = ""
                if getattr(compliance_report, "disclaimer", None):
                    disclaimer_html = f"""
                  <div style="padding: 12px 16px; font-size: 13px; color: #8b949e; background: #161b22; border-bottom: 1px solid var(--border);">
                    <strong>Notice:</strong> {html.escape(compliance_report.disclaimer)}
                  </div>
                    """
                comp_table_html = f"""
                <div class="table-container" style="margin-bottom: 24px;">
                  <div style="padding: 16px; font-weight: bold; font-size: 16px; border-bottom: 1px solid var(--border);">
                    📋 Defensive Security Compliance Baseline Audit ({len(compliance_report.findings)} Findings) &bull; Standard: {html.escape(compliance_report.benchmark.upper())}
                  </div>
                  {disclaimer_html}
                  <table>
                    <thead>
                      <tr>
                        <th>Rule ID</th>
                        <th>Severity</th>
                        <th>Benchmark</th>
                        <th>Control Title</th>
                        <th>Endpoint</th>
                        <th>Evidence</th>
                        <th>Detection Logic</th>
                        <th>Limitations</th>
                        <th>Defensive Remediation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {"".join(cf_rows)}
                    </tbody>
                  </table>
                </div>
                """

        sec_grade_html = ""
        sec_findings_html = ""
        if sec:
            grade_color = "#3fb950" if sec.grade in ("A+", "A") else "#d29922" if sec.grade == "B" else "#f85149"
            sec_grade_html = f'<span style="color: {grade_color}; font-weight: bold; font-size: 24px;">{sec.grade}</span> <span style="font-size: 13px; color: #8b949e;">({sec.score}/100)</span>'
            
            f_rows = []
            for f in sec.findings:
                sev_badge = "st-5xx" if f.severity == "HIGH" else "st-4xx" if f.severity == "MEDIUM" else "st-3xx"
                f_rows.append(f"""
                <tr>
                  <td><span class="badge {sev_badge}">{f.severity}</span></td>
                  <td><strong>{html.escape(f.name)}</strong></td>
                  <td>{html.escape(f.description)}</td>
                  <td><code style="color: #7ee787;">{html.escape(f.recommendation)}</code></td>
                </tr>
                """)
        assertions_html = ""
        if security_assertions:
            a_rows = []
            for a in security_assertions:
                badge = "st-5xx" if a.severity == "HIGH" else "st-4xx" if a.severity == "MEDIUM" else "st-3xx"
                class_badge = "st-2xx" if a.classification == "Confirmed Observation" else "st-3xx" if a.classification == "Potential Finding" else "badge-tech"
                m_badge = '<span class="badge st-5xx">Yes</span>' if a.manual_verification_required else '<span class="badge st-2xx">No</span>'
                conf_str = f"{a.confidence * 100:.0f}%" if isinstance(a.confidence, (int, float)) else str(a.confidence)
                a_rows.append(f"""
                <tr>
                  <td><span class="badge {badge}">{a.severity}</span></td>
                  <td><span class="badge {class_badge}">{html.escape(a.classification)}</span></td>
                  <td><strong>{html.escape(conf_str)}</strong></td>
                  <td><strong>{html.escape(a.category)}</strong></td>
                  <td><strong>{html.escape(a.title)}</strong><br><span style="font-size: 12px; color: #8b949e;">{html.escape(a.description)}</span></td>
                  <td><code>{html.escape(a.endpoint)}</code></td>
                  <td><span style="font-size: 12px; color: #8b949e;">{html.escape(a.evidence)}</span></td>
                  <td><span style="font-size: 12px; color: #d29922;">{html.escape(a.impact)}</span></td>
                  <td>{m_badge}</td>
                  <td><code style="color: #7ee787;">{html.escape(a.remediation)}</code></td>
                </tr>
                """)
            assertions_html = f"""
            <div class="table-container" style="margin-bottom: 24px;">
              <div style="padding: 16px; font-weight: bold; font-size: 16px; border-bottom: 1px solid var(--border);">
                🛡️ Automated Security Assertions & Vulnerability Validations ({len(security_assertions)})
              </div>
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Classification</th>
                    <th>Confidence</th>
                    <th>Category</th>
                    <th>Assertion / Finding</th>
                    <th>Endpoint</th>
                    <th>Evidence</th>
                    <th>Impact</th>
                    <th>Manual Verif.</th>
                    <th>Remediation</th>
                  </tr>
                </thead>
                <tbody>
                  {"".join(a_rows)}
                </tbody>
              </table>
            </div>
            """

        cert_html = ""
        if cert:
            c_color = "#3fb950" if cert.days_remaining > 30 else "#f85149"
            cert_html = f"""
            <div class="metric-card" style="grid-column: span 2;">
              <div class="metric-title">SSL/TLS Certificate</div>
              <div style="font-size: 14px; margin-top: 6px;">
                <strong>Issuer:</strong> {html.escape(cert.issuer)} &bull; 
                <strong>Expires:</strong> <span style="color: {c_color}; font-weight: bold;">{cert.days_remaining} days left</span> &bull; 
                <strong>Protocol:</strong> {html.escape(cert.tls_version)} ({html.escape(cert.cipher)})
              </div>
              <div style="font-size: 12px; color: #8b949e; margin-top: 4px;">
                <strong>SANs:</strong> {html.escape(', '.join(cert.sans[:8]))}{'...' if len(cert.sans) > 8 else ''}
              </div>
            </div>
            """

        rows_html = []
        for r in results:
            badge_class = "st-2xx" if 200 <= r.status_code < 300 else "st-3xx" if 300 <= r.status_code < 400 else "st-4xx" if r.status_code < 500 else "st-5xx"
            title_esc = html.escape(r.title or "")
            red_esc = html.escape(r.redirect_location or "")
            path_esc = html.escape(r.path)
            url_esc = html.escape(r.url)

            details_parts = []
            if red_esc:
                details_parts.append(f'<span class="redirect">➔ {red_esc}</span>')
            if title_esc:
                details_parts.append(f'<span class="title">"{title_esc}"</span>')
            detail_disp = " ".join(details_parts)

            rows_html.append(f"""
            <tr>
              <td><span class="badge {badge_class}">{r.status_code}</span></td>
              <td><a href="{url_esc}" target="_blank" class="endpoint-link">{path_esc}</a></td>
              <td>{r.content_length:,} B</td>
              <td>{r.word_count}</td>
              <td>{r.line_count}</td>
              <td>{r.response_time_ms:.1f} ms</td>
              <td>{detail_disp}</td>
            </tr>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WebAdminMapper Report - {html.escape(self.config.target_url)}</title>
  <style>
    :root {{
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-bright: #f0f6fc;
      --accent: #58a6ff;
      --green: #2ea043;
      --cyan: #388bfd;
      --yellow: #d29922;
      --red: #f85149;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg); color: var(--text); padding: 30px 20px; }}
    .container {{ max-width: 1240px; margin: 0 auto; }}
    header {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 24px; }}
    h1 {{ color: var(--text-bright); font-size: 24px; display: flex; align-items: center; justify-content: space-between; }}
    .author-badge {{ font-size: 13px; background: #1f6feb33; color: var(--accent); padding: 6px 12px; border-radius: 20px; border: 1px solid var(--accent); }}
    .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-top: 20px; }}
    .metric-card {{ background: #21262d; border: 1px solid var(--border); padding: 16px; border-radius: 8px; }}
    .metric-title {{ font-size: 12px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; }}
    .metric-value {{ font-size: 22px; font-weight: bold; color: var(--text-bright); margin-top: 6px; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 12px; font-weight: 600; }}
    .st-2xx {{ background: #23863633; color: #3fb950; border: 1px solid #238636; }}
    .st-3xx {{ background: #1f6feb33; color: #58a6ff; border: 1px solid #1f6feb; }}
    .st-4xx {{ background: #bb800933; color: #d29922; border: 1px solid #bb8009; }}
    .st-5xx {{ background: #da363333; color: #f85149; border: 1px solid #da3633; }}
    .badge-tech {{ background: #388bfd22; color: #58a6ff; border: 1px solid #388bfd55; margin-right: 6px; }}
    .badge-waf {{ background: #f8514922; color: #f85149; border: 1px solid #f8514955; }}
    .table-container {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-top: 24px; }}
    .table-controls {{ padding: 16px; display: flex; gap: 12px; border-bottom: 1px solid var(--border); }}
    input[type="text"] {{ flex: 1; background: #0d1117; border: 1px solid var(--border); color: #fff; padding: 10px 14px; border-radius: 6px; outline: none; }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }}
    th {{ background: #21262d; padding: 12px 16px; color: #8b949e; font-weight: 600; border-bottom: 1px solid var(--border); }}
    td {{ padding: 12px 16px; border-bottom: 1px solid var(--border); }}
    tr:hover {{ background: #21262d55; }}
    .endpoint-link {{ color: var(--accent); text-decoration: none; font-family: monospace; font-weight: 600; }}
    .endpoint-link:hover {{ text-decoration: underline; }}
    .redirect {{ color: #58a6ff; font-family: monospace; font-size: 12px; }}
    .title {{ color: #8b949e; font-style: italic; font-size: 13px; margin-left: 6px; }}
    .tree-box {{ background: #0d1117; padding: 16px; border-radius: 6px; font-family: monospace; font-size: 13px; color: #7ee787; white-space: pre; overflow-x: auto; margin-top: 16px; border: 1px solid var(--border); }}
    footer {{ text-align: center; margin-top: 30px; font-size: 13px; color: #8b949e; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>
        <span>⚡ WebAdminMapper Report</span>
        <span class="author-badge">Developed & Authored by Ahmed Wael</span>
      </h1>
      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-title">Target Host</div>
          <div class="metric-value" style="font-size: 16px;">{html.escape(self.config.target_url)}</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Discovered Endpoints</div>
          <div class="metric-value" style="color: #3fb950;">{len(results)}</div>
        </div>
        <div class="metric-card">
          <div class="metric-title">Scan Duration & Latency</div>
          <div class="metric-value">{duration_sec:.2f}s <span style="font-size: 12px; color: #8b949e;">(p50: {lat_stats['p50']}ms)</span></div>
        </div>
        {f'''
        <div class="metric-card">
          <div class="metric-title">Security Posture Grade</div>
          <div class="metric-value">{sec_grade_html}</div>
        </div>
        ''' if sec_grade_html else ''}
        {cert_html}
        {net_html}
        {comp_card_html}
      </div>
      <div style="margin-top: 16px; font-size: 14px;">
        <strong>WAF/CDN:</strong> {waf_badge} &bull; 
        <strong>Technologies:</strong> {tech_badges}
      </div>
    </header>

    {f'''
    <div class="table-container" style="margin-bottom: 24px;">
      <div style="padding: 16px; font-weight: bold; font-size: 16px; border-bottom: 1px solid var(--border);">
        🛡️ Security Posture & Defensive Header Audit Findings ({len(sec.findings)})
      </div>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Check</th>
            <th>Description</th>
            <th>Remediation</th>
          </tr>
        </thead>
        <tbody>
          {sec_findings_html}
        </tbody>
      </table>
    </div>
    ''' if sec and sec_findings_html else ''}

    {comp_table_html}

    {assertions_html}

    <div class="table-container">
      <div class="table-controls">
        <input type="text" id="filterInput" placeholder="Filter discovered routes by path, status, or title..." onkeyup="filterTable()">
      </div>
      <table id="resultsTable">
        <thead>
          <tr>
            <th>Status</th>
            <th>Discovered Path</th>
            <th>Length</th>
            <th>Words</th>
            <th>Lines</th>
            <th>Latency</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {"".join(rows_html)}
        </tbody>
      </table>
    </div>

    {f'''
    <div style="margin-top: 24px;">
      <h2 style="font-size: 18px; color: var(--text-bright); margin-bottom: 8px;">📁 Hierarchical Structure Map</h2>
      <div class="tree-box">{tree_ascii}</div>
    </div>
    ''' if tree_ascii else ''}

    <footer>
      Generated by <strong>WebAdminMapper v1.0.0 (Enterprise)</strong> &bull; Developed & Authored by <strong>Ahmed Wael</strong>
    </footer>
  </div>

  <script>
    function filterTable() {{
      const query = document.getElementById("filterInput").value.toLowerCase();
      const rows = document.querySelectorAll("#resultsTable tbody tr");
      rows.forEach(row => {{
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(query) ? "" : "none";
      }});
    }}
  </script>
</body>
</html>
"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)
