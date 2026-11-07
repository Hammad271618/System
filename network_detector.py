import re
import ssl
import subprocess
import urllib.parse
import logging
import requests
from requests.adapters import HTTPAdapter
import urllib3

# Suppress insecure SSL warnings for Fortinet captive portal self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("urllib3").setLevel(logging.ERROR)

logger = logging.getLogger("MCS_NetworkDetector")

PROBE_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.google.com/generate_204",
    "http://msftconnecttest.com/connecttest.txt",
    "http://neverssl.com"
]

PROBE_HOSTS = (
    "connectivitycheck.gstatic.com",
    "www.google.com",
    "google.com",
    "msftconnecttest.com",
    "www.msftconnecttest.com",
    "neverssl.com"
)

DEFAULT_FORTINET_BASE = "https://172.23.200.254:1003"


STATIC_ASSET_EXTS = (".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".woff", ".woff2", ".ttf")


class FortinetTLSAdapter(HTTPAdapter):
    """Custom HTTPS adapter that tolerates self-signed certs and legacy FortiGate TLS ciphers."""
    @staticmethod
    def _build_ssl_context():
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if hasattr(ssl, "TLSVersion") and hasattr(ctx, "minimum_version"):
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except Exception:
                pass
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        except Exception:
            try:
                ctx.set_ciphers("DEFAULT")
            except Exception:
                pass
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
        return ctx

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._build_ssl_context()
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs["ssl_context"] = self._build_ssl_context()
        return super().proxy_manager_for(proxy, **proxy_kwargs)

    def cert_verify(self, conn, url, verify, cert):
        # Always bypass certificate verification for captive portal self-signed certs
        return super().cert_verify(conn, url, verify=False, cert=cert)


def is_probe_url(url):
    if not url:
        return True
    try:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        return any(host == ph or host.endswith("." + ph) for ph in PROBE_HOSTS)
    except Exception:
        return False


def _is_static_asset_url(url):
    if not url:
        return True
    try:
        path = (urllib.parse.urlparse(url).path or "").lower()
        if "/xx/yy/zz/" in path:
            return True
        return path.endswith(STATIC_ASSET_EXTS)
    except Exception:
        return False


def extract_redirect_from_html(html, base_url=None):
    """
    Extracts redirect target URLs from FortiGate 200 OK JavaScript / Meta-Refresh stubs.
    e.g. window.location="https://172.23.200.254:1003/fgtauth?060006914c305f33"
    """
    if not html:
        return None

    html_lower = html.lower()
    has_login_form = "<form" in html_lower and (
        'type="password"' in html_lower
        or "type='password'" in html_lower
        or 'name="magic"' in html_lower
        or "name='magic'" in html_lower
    )

    if has_login_form:
        # If the HTML already contains the login form, only extract an explicit /fgtauth?... URL
        # or an absolute form action pointing to the gateway, never sub-resource URLs.
        form_patterns = [
            r'(https?://[^\s"\'<>]+/fgtauth\?[^\s"\'<>]+)',
            r'<form[^>]+action=["\'](https?://[^"\']+)["\']'
        ]
        for pat in form_patterns:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                candidate = m.group(1).strip()
                if candidate and not is_probe_url(candidate) and not _is_static_asset_url(candidate):
                    return candidate
        return None

    patterns = [
        # 1. Explicit fgtauth URL anywhere in the response
        r'(https?://[^\s"\'<>]+/fgtauth\?[^\s"\'<>]+)',
        # 2. JS window.location / location.href = "..."
        r'(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
        # 3. JS location.replace("...") or location.assign("...")
        r'location\.(?:replace|assign)\(\s*["\']([^"\']+)["\']\s*\)',
        # 4. <meta http-equiv="refresh" content="0;url=...">
        r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\'][^"\']*url=([^"\'\s>;]+)',
        r'<meta[^>]*content=["\'][^"\']*url=([^"\'\s>;]+)[^>]*http-equiv=["\']?refresh["\']?',
        # 5. Direct Fortinet port 1003 / 1000 URL (excluding static assets like favicon.ico / images)
        r'(https?://[^\s"\'<>]+:100[03]/[^\s"\'<>]*)'
    ]

    for pat in patterns:
        for m in re.finditer(pat, html, re.IGNORECASE):
            candidate = m.group(1).strip()
            if candidate:
                if base_url and not candidate.lower().startswith(("http://", "https://")):
                    effective_base = DEFAULT_FORTINET_BASE if is_probe_url(base_url) else base_url
                    candidate = urllib.parse.urljoin(effective_base, candidate)
                if not is_probe_url(candidate) and not _is_static_asset_url(candidate):
                    return candidate

    return None


class NetworkDetector:
    def __init__(self):
        self.session = self._create_session()

    def _create_session(self):
        session = requests.Session()
        session.verify = False
        session.trust_env = False
        adapter = FortinetTLSAdapter(max_retries=0)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Connection": "close"
        })
        return session

    def get_current_wifi_ssid(self):
        """Returns the current Wi-Fi SSID using netsh wlan, or None if not on Wi-Fi."""
        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            ).decode("utf-8", errors="ignore")

            for line in output.splitlines():
                line = line.strip()
                if line.startswith("SSID") and not line.startswith("SSID name") and not line.startswith("BSSID"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        if ssid:
                            return ssid
        except Exception as e:
            logger.debug(f"Could not retrieve SSID: {e}")
        return None

    def _resolve_portal_page(self, initial_url, initial_html=""):
        """
        Follows HTTP 3xx and HTML/JS redirects (up to 4 hops) until the actual
        Fortinet login form page (e.g. https://172.23.200.254:1003/fgtauth?...) is loaded.
        """
        curr_url = initial_url
        curr_html = initial_html or ""

        # If initial_url is a probe URL, check if initial_html redirects to the real portal
        if is_probe_url(curr_url):
            extracted = extract_redirect_from_html(curr_html, curr_url)
            if extracted:
                logger.info(f"Extracted portal redirect URL from HTML: {extracted}")
                curr_url = extracted
                if "<form" not in curr_html.lower():
                    curr_html = ""
            else:
                # Check if magic input is already in initial_html
                magic_match = re.search(r'name=["\']magic["\']\s+value=["\']([^"\']+)["\']', curr_html, re.I)
                if not magic_match:
                    magic_match = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']magic["\']', curr_html, re.I)
                if magic_match:
                    magic_val = magic_match.group(1)
                    curr_url = f"{DEFAULT_FORTINET_BASE}/fgtauth?{magic_val}"
                    logger.info(f"Constructed Fortinet portal URL from magic token: {curr_url}")
                else:
                    curr_url = f"{DEFAULT_FORTINET_BASE}/"

        # Follow up to 4 hops to reach the login form
        for _ in range(4):
            if curr_html and "<form" in curr_html.lower() and not is_probe_url(curr_url):
                break
            try:
                resp = self.session.get(curr_url, timeout=6, allow_redirects=False, verify=False)
                if resp.status_code in [301, 302, 303, 307, 308]:
                    loc = resp.headers.get("Location", "")
                    if loc:
                        next_url = urllib.parse.urljoin(curr_url, loc)
                        logger.info(f"Portal redirect hop: {curr_url} -> {next_url}")
                        curr_url = next_url
                        curr_html = ""
                        continue
                if resp.status_code == 200 and resp.text:
                    curr_html = resp.text
                    curr_url = resp.url or curr_url

                # Check if this response is another JS/meta redirect stub without a <form>
                if "<form" not in curr_html.lower():
                    next_js_url = extract_redirect_from_html(curr_html, curr_url)
                    if next_js_url and next_js_url != curr_url:
                        logger.info(f"Following JS/meta redirect hop -> {next_js_url}")
                        curr_url = next_js_url
                        curr_html = ""
                        continue
                break
            except Exception as e:
                logger.debug(f"Could not fetch portal URL {curr_url}: {e}")
                break

        return {
            "portal_url": curr_url,
            "html": curr_html,
            "final_url": curr_url
        }

    def fast_probe(self):
        """
        Sub-1.5s connectivity check. Returns True if internet is active (HTTP 204),
        or False if intercepted by captive portal / offline.
        """
        try:
            resp = self.session.get(
                "http://connectivitycheck.gstatic.com/generate_204",
                timeout=1.5,
                allow_redirects=False,
                verify=False
            )
            return resp.status_code == 204
        except Exception:
            return False

    def get_telemetry(self):
        """
        Collects real-time network telemetry for dashboard and roaming.
        """
        telemetry = {
            "ssid": None,
            "signal": None,
            "local_ip": None,
            "gateway_ip": None,
            "is_dhcp": True,
            "latency_ms": None,
            "status": "OFFLINE"
        }
        try:
            # 1. SSID & Signal
            wlan_out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            ).decode("utf-8", errors="ignore")

            m_ssid = re.search(r"^\s*SSID\s+:\s+(.+)$", wlan_out, re.M)
            if m_ssid:
                telemetry["ssid"] = m_ssid.group(1).strip()

            m_sig = re.search(r"Signal\s+:\s+([0-9]+%)", wlan_out)
            if m_sig:
                telemetry["signal"] = m_sig.group(1).strip()

            # 2. IP & Gateway & DHCP
            ip_out = subprocess.check_output(
                ["netsh", "interface", "ipv4", "show", "config", "Wi-Fi"],
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            ).decode("utf-8", errors="ignore")

            m_ip = re.search(r"IP Address:\s+([0-9.]+)", ip_out)
            if m_ip:
                telemetry["local_ip"] = m_ip.group(1).strip()

            m_gw = re.search(r"Default Gateway:\s+([0-9.]+)", ip_out)
            if m_gw:
                telemetry["gateway_ip"] = m_gw.group(1).strip()

            m_dhcp = re.search(r"DHCP enabled:\s+(\w+)", ip_out)
            if m_dhcp:
                telemetry["is_dhcp"] = (m_dhcp.group(1).strip().lower() == "yes")

            # 3. Latency measurement
            import time
            t0 = time.time()
            if self.fast_probe():
                telemetry["latency_ms"] = int((time.time() - t0) * 1000)
                telemetry["status"] = "ONLINE"
            else:
                telemetry["status"] = "CAPTIVE_PORTAL" if telemetry["ssid"] else "OFFLINE"

        except Exception as e:
            logger.debug(f"Telemetry collection error: {e}")

        return telemetry

    def check_connection(self):
        """
        Tests internet and captive portal status.
        Returns:
            status (str): "ONLINE", "CAPTIVE_PORTAL", "OFFLINE"
            data (dict): contains portal_url, html, final_url, or error info
        """
        # If Wi-Fi link is completely disconnected, avoid throwing DNS getaddrinfo errors
        ssid = self.get_current_wifi_ssid()
        if not ssid:
            # Check if an Ethernet link is active
            telemetry = self.get_telemetry()
            if not telemetry.get("gateway_ip"):
                return "OFFLINE", {"error": "Network interface is disconnected"}

        for probe_url in PROBE_URLS:
            try:
                # First try without following redirects to cleanly catch 302/307 captive redirects
                resp = self.session.get(probe_url, timeout=4, allow_redirects=False, verify=False)
                
                # Direct success: 204 No Content
                if resp.status_code == 204:
                    return "ONLINE", {"probe": probe_url}
                
                # Windows connecttest check
                if "msftconnecttest" in probe_url and resp.status_code == 200 and "Microsoft Connect Test" in resp.text:
                    return "ONLINE", {"probe": probe_url}

                # HTTP Redirects indicate captive portal interception
                if resp.status_code in [301, 302, 303, 307, 308]:
                    redirect_url = resp.headers.get("Location", "")
                    if redirect_url:
                        redirect_url = urllib.parse.urljoin(probe_url, redirect_url)
                    logger.info(f"Captive Portal HTTP {resp.status_code} redirect detected from {probe_url} -> {redirect_url}")
                    portal_data = self._resolve_portal_page(redirect_url)
                    return "CAPTIVE_PORTAL", portal_data

                # FortiGuard Quota / Category Block Page returns HTTP 403 Forbidden or 401
                if resp.status_code in [400, 401, 403]:
                    text_lower = resp.text.lower()
                    has_block_markers = any(
                        k in text_lower
                        for k in [
                            "fortinet", "fortiguard", "blocked", "quota", "expired",
                            "access blocked", "web page blocked", "category of web page has expired"
                        ]
                    )
                    if has_block_markers:
                        logger.info(f"Fortinet HTTP {resp.status_code} quota/block page detected on {probe_url}")
                        portal_data = self._resolve_portal_page(probe_url, resp.text)
                        return "CAPTIVE_PORTAL", portal_data

                # Captive portals often return 200 OK to generate_204 or probe URLs with JS redirect or HTML form
                if resp.status_code == 200:
                    text_lower = resp.text.lower()
                    is_generate_204 = "generate_204" in probe_url
                    has_portal_markers = any(
                        k in text_lower
                        for k in [
                            "fortinet", "fgtauth", "firewall", "login", "captive", "quota",
                            "4tredir", "authentication required", "window.location",
                            "http-equiv=\"refresh\"", "access blocked", "web page blocked"
                        ]
                    )
                    if is_generate_204 or has_portal_markers:
                        logger.info(f"Captive portal 200 OK interception detected on {probe_url}")
                        portal_data = self._resolve_portal_page(probe_url, resp.text)
                        return "CAPTIVE_PORTAL", portal_data

            except (requests.ConnectionError, requests.Timeout):
                continue
            except Exception as e:
                logger.debug(f"Probe {probe_url} error: {e}")
                continue

        # Fallback: check if local gateway or default Fortinet base is reachable
        telemetry = self.get_telemetry()
        gw_ip = telemetry.get("gateway_ip")
        candidate_bases = []
        if gw_ip:
            candidate_bases.append(f"https://{gw_ip}:1003")
        if DEFAULT_FORTINET_BASE not in candidate_bases:
            candidate_bases.append(DEFAULT_FORTINET_BASE)

        for base_url in candidate_bases:
            try:
                gw_resp = self.session.get(f"{base_url}/", timeout=2, allow_redirects=False, verify=False)
                if gw_resp.status_code in [200, 301, 302, 303, 307]:
                    logger.info(f"Direct Fortinet gateway ({base_url}) responded while external probes failed.")
                    portal_data = self._resolve_portal_page(f"{base_url}/", gw_resp.text)
                    return "CAPTIVE_PORTAL", portal_data
            except Exception:
                pass

        return "OFFLINE", {"error": "All connectivity probes failed or timed out"}

