import re
import time
import urllib.parse
import logging
import requests
import urllib3
from bs4 import BeautifulSoup

from network_detector import (
    FortinetTLSAdapter,
    DEFAULT_FORTINET_BASE,
    is_probe_url,
    extract_redirect_from_html
)

# Suppress self-signed certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("MCS_FortinetClient")

QUOTA_KEYWORDS = [
    "quota",
    "limit exceeded",
    "transfer limit",
    "data limit",
    "bandwidth limit",
    "traffic limit",
    "usage limit",
    "over limit",
    "quota reached",
    "limit has been reached",
    "maximum transfer",
    "maximum session",
    "daily limit",
    "time limit",
    "session limit",
    "exceeded your",
    "web page blocked",
    "access blocked",
    "category of web page has expired",
    "quota for this category",
    "fortiguard intrusion prevention"
]

INVALID_CRED_KEYWORDS = [
    "invalid username or password",
    "authentication failed",
    "invalid credentials",
    "wrong password",
    "login failed",
    "user name or password error",
    "permission denied",
    "access denied",
    "failed: invalid"
]


class FortinetClient:
    def __init__(self):
        self.session = self._create_session()
        self.keepalive_url = None
        self.last_gateway_ip = None

    def logout(self, gateway_ip=None):
        """
        De-authenticates the client session from FortiGate firewall auth-list.
        Hits logout endpoints across gateway (ports 1003 and 1000), 172.23.200.254:1003, and 1.1.1.1.
        """
        self.keepalive_url = None
        raw_gw = gateway_ip or getattr(self, "last_gateway_ip", None)
        target_gw = None
        if raw_gw:
            gw_clean = str(raw_gw).strip()
            if "://" in gw_clean:
                gw_clean = urllib.parse.urlparse(gw_clean).hostname or gw_clean
            if ":" in gw_clean:
                gw_clean = gw_clean.split(":")[0]
            if not is_probe_url(f"http://{gw_clean}"):
                target_gw = gw_clean

        urls = []
        if target_gw:
            urls.append(f"https://{target_gw}:1003/logout?")
            urls.append(f"http://{target_gw}:1000/logout?")
        urls.append("https://172.23.200.254:1003/logout?")
        urls.append("http://1.1.1.1/logout?")

        unique_urls = list(dict.fromkeys(urls))
        logger.info(f"Sending Fortinet logout to clear firewall auth session: {unique_urls}")

        session = self._create_session(max_retries=0)
        try:
            for u in unique_urls:
                try:
                    session.get(u, timeout=0.6, verify=False)
                except Exception as e:
                    logger.debug(f"Logout request to {u} completed: {e}")
        finally:
            try:
                session.close()
            except Exception:
                pass

    def _create_session(self, max_retries=1):
        session = requests.Session()
        session.verify = False
        session.trust_env = False
        adapter = FortinetTLSAdapter(max_retries=max_retries)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Connection": "close"
        })
        return session

    def parse_portal_form(self, html, base_url):
        """
        Parses the captive portal HTML to extract form action and input fields.
        If html is a JS/meta redirect stub or base_url is an external probe URL,
        resolves the real Fortinet portal URL (https://172.23.200.254:1003/fgtauth?...) first.
        """
        effective_base = base_url or f"{DEFAULT_FORTINET_BASE}/"
        effective_html = html or ""

        # 1. If the HTML has no <form> or base_url is a probe URL, check if HTML contains a redirect URL
        if "<form" not in effective_html.lower() or is_probe_url(effective_base):
            redirect_target = extract_redirect_from_html(effective_html, effective_base)
            if redirect_target:
                logger.info(f"Following redirect inside portal HTML -> {redirect_target}")
                effective_base = redirect_target
                if "<form" not in effective_html.lower():
                    try:
                        r = self.session.get(redirect_target, timeout=6, verify=False)
                        if r.status_code == 200 and r.text:
                            effective_html = r.text
                            effective_base = r.url or redirect_target
                    except Exception as e:
                        logger.debug(f"Failed to fetch redirect target {redirect_target}: {e}")
            elif "<form" not in effective_html.lower():
                # No form and no redirect extracted; try fetching default Fortinet gateway directly
                try:
                    r = self.session.get(f"{DEFAULT_FORTINET_BASE}/", timeout=5, verify=False)
                    if r.status_code == 200 and r.text and "<form" in r.text.lower():
                        effective_html = r.text
                        effective_base = r.url or f"{DEFAULT_FORTINET_BASE}/"
                except Exception as e:
                    logger.debug(f"Fallback fetch to {DEFAULT_FORTINET_BASE}/ failed: {e}")

        soup = BeautifulSoup(effective_html, "html.parser")
        forms = soup.find_all("form")
        
        post_url = None
        payload = {}
        username_field = None
        password_field = None

        target_form = None
        for form in forms:
            # Look for a form containing password input
            pwd_input = form.find("input", {"type": "password"})
            if pwd_input:
                target_form = form
                break
        
        if not target_form and forms:
            target_form = forms[0]

        if target_form:
            # Extract all named inputs (per HTML spec, inputs with empty/missing name are not submitted)
            for inp in target_form.find_all("input"):
                name = (inp.get("name") or "").strip()
                if not name:
                    continue
                inp_type = (inp.get("type") or "text").lower()
                val = inp.get("value", "")

                if inp_type == "password":
                    password_field = name
                elif inp_type in ["text", "email"] and not username_field:
                    username_field = name
                elif inp_type not in ["submit", "button", "reset", "image"]:
                    payload[name] = val

        # Fallback heuristic if not detected via form elements
        if not username_field:
            username_field = "username"
        if not password_field:
            password_field = "password"

        # Check for magic token in query string (common in FortiGate e.g. /fgtauth?060006914c305f33)
        parsed_url = urllib.parse.urlparse(effective_base)
        query = parsed_url.query
        if query and not payload.get("magic"):
            clean_query = query.split("&")[0].split("=")[-1]
            if re.match(r"^[a-fA-F0-9]{8,}$", clean_query):
                payload["magic"] = clean_query

        # Ensure effective_base is NEVER an external probe URL (e.g. connectivitycheck.gstatic.com)
        if is_probe_url(effective_base):
            magic_token = payload.get("magic", "")
            if magic_token:
                effective_base = f"{DEFAULT_FORTINET_BASE}/fgtauth?{magic_token}"
            else:
                effective_base = f"{DEFAULT_FORTINET_BASE}/"

        if target_form:
            action = target_form.get("action", "")
            post_url = urllib.parse.urljoin(effective_base, action) if action else effective_base
        else:
            # Standard FortiGate form action is "/" on the portal host
            parsed_eff = urllib.parse.urlparse(effective_base)
            post_url = f"{parsed_eff.scheme}://{parsed_eff.netloc}/"

        if is_probe_url(post_url):
            post_url = f"{DEFAULT_FORTINET_BASE}/"

        return {
            "portal_url": effective_base,
            "post_url": post_url,
            "payload": payload,
            "username_field": username_field,
            "password_field": password_field
        }

    def check_for_quota_or_error(self, html_text):
        """Checks post-login HTML for quota/limit or invalid credential messages."""
        if not html_text:
            return None, None
        text_lower = html_text.lower()
        for kw in QUOTA_KEYWORDS:
            if kw in text_lower:
                return "QUOTA_EXHAUSTED", f"Fortinet reported quota/limit: '{kw}'"
        for kw in INVALID_CRED_KEYWORDS:
            if kw in text_lower:
                return "INVALID_CREDENTIALS", f"Fortinet reported auth error: '{kw}'"
        return None, None

    def _is_login_form_page(self, html_text):
        """Returns True if the HTML is still the Fortinet authentication login page."""
        if not html_text:
            return False
        text_lower = html_text.lower()
        if 'type="password"' in text_lower or "type='password'" in text_lower:
            return True
        if "authentication required" in text_lower or ("please enter" in text_lower and "username" in text_lower):
            return True
        if 'name="magic"' in text_lower and 'name="4tredir"' in text_lower:
            return True
        return False

    def _extract_portal_message(self, html_text):
        """Extracts human-readable status/error message from Fortinet HTML response."""
        if not html_text:
            return ""
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            parts = []
            for tag in soup.find_all(["h1", "h2", "h3", "p"]):
                txt = tag.get_text(" ", strip=True)
                if txt and txt not in parts:
                    parts.append(txt)
            return " | ".join(parts[:3])
        except Exception:
            return ""

    def _verify_internet_probe(self):
        """Directly checks if Google/Microsoft connectivity probe succeeds (HTTP 204)."""
        for attempt in range(2):
            try:
                probe_session = self._create_session()
                test_resp = probe_session.get(
                    "http://connectivitycheck.gstatic.com/generate_204",
                    timeout=4,
                    allow_redirects=False,
                    verify=False
                )
                if test_resp.status_code == 204:
                    return True, test_resp
                # Also try msftconnecttest if gstatic returned non-204
                ms_resp = probe_session.get(
                    "http://msftconnecttest.com/connecttest.txt",
                    timeout=4,
                    allow_redirects=False,
                    verify=False
                )
                if ms_resp.status_code == 200 and "Microsoft Connect Test" in ms_resp.text:
                    return True, ms_resp
                if attempt == 0:
                    time.sleep(0.6)
                else:
                    return False, test_resp
            except Exception as e:
                if attempt == 0:
                    time.sleep(0.6)
                else:
                    return False, None
        return False, None

    def login(self, portal_url, html, username, password):
        """
        Submits login credentials to the Fortinet captive portal.
        Returns:
            success (bool): True if login succeeded and internet was unlocked.
            status_code (str): 'SUCCESS', 'QUOTA_EXHAUSTED', 'INVALID_CREDENTIALS', 'PORTAL_REJECTED', 'FAILED'
            message (str): human-readable description
        """
        parsed = self.parse_portal_form(html, portal_url)
        effective_portal_url = parsed["portal_url"]
        post_url = parsed["post_url"]
        payload = parsed["payload"].copy()

        payload[parsed["username_field"]] = username
        payload[parsed["password_field"]] = password

        # Standard Fortinet redirect targets if not already present
        if "4Tredir" not in payload and "redir" not in payload:
            payload["4Tredir"] = "http://connectivitycheck.gstatic.com/generate_204"

        parsed_post = urllib.parse.urlparse(post_url)
        gw_host = parsed_post.hostname
        if gw_host and not is_probe_url(post_url):
            self.last_gateway_ip = gw_host
        elif effective_portal_url and not is_probe_url(effective_portal_url):
            eff_host = urllib.parse.urlparse(effective_portal_url).hostname
            if eff_host:
                self.last_gateway_ip = eff_host

        origin = f"{parsed_post.scheme}://{parsed_post.netloc}"
        headers = {
            "Origin": origin,
            "Referer": effective_portal_url,
            "Content-Type": "application/x-www-form-urlencoded",
            "Connection": "close"
        }

        magic_info = payload.get("magic", "none")
        logger.info(
            f"Submitting Fortinet credentials for '{username}' -> POST {post_url} "
            f"(Portal: {effective_portal_url}, magic: {magic_info})"
        )
        logger.debug(f"Payload fields: {list(payload.keys())}")

        resp = None
        last_exc = None
        candidate_urls = [post_url]
        if effective_portal_url != post_url and not is_probe_url(effective_portal_url):
            candidate_urls.append(effective_portal_url)

        for target_url in candidate_urls:
            for attempt in range(2):
                try:
                    if attempt > 0:
                        self.session = self._create_session()
                    resp = self.session.post(
                        target_url,
                        data=payload,
                        headers=headers,
                        timeout=8,
                        allow_redirects=True,
                        verify=False
                    )
                    last_exc = None
                    break
                except Exception as e:
                    last_exc = e
                    logger.warning(f"POST attempt {attempt + 1} to {target_url} failed: {e}")
                    time.sleep(0.5)
            if resp is not None:
                break

        if resp is None:
            logger.error(f"Error during login request to {post_url}: {last_exc}")
            return False, "FAILED", f"Could not reach Fortinet portal ({post_url}): {last_exc}"

        resp_text = resp.text or ""
        resp_lower = resp_text.lower()
        logger.info(f"Fortinet POST responded with HTTP {resp.status_code} (URL: {resp.url})")

        # 1. Check response for explicit quota or invalid credentials keywords
        err_type, err_msg = self.check_for_quota_or_error(resp_text)
        if not err_type and resp.status_code == 403:
            err_type = "QUOTA_EXHAUSTED"
            err_msg = "Fortinet returned HTTP 403 (Quota limit or access blocked)"

        if err_type:
            portal_summary = self._extract_portal_message(resp_text)
            full_msg = f"{err_msg} ({portal_summary})" if portal_summary else err_msg
            logger.warning(f"Login failed for {username}: {full_msg}")
            if err_type in ("QUOTA_EXHAUSTED", "PORTAL_REJECTED"):
                self.logout()
            return False, err_type, full_msg

        # 2. Check for Fortinet keepalive URL in response or JS redirect
        keepalive_match = re.search(r'(https?://[^\s"\'<>]+/keepalive\?[^\s"\'<>]+|/keepalive\?[a-zA-Z0-9]+)', resp_text, re.I)
        if keepalive_match:
            ka_url = urllib.parse.urljoin(post_url, keepalive_match.group(1))
            self.keepalive_url = ka_url
            try:
                ka_resp = self.session.get(ka_url, timeout=5, verify=False)
                if ka_resp.text:
                    ka_err_type, ka_err_msg = self.check_for_quota_or_error(ka_resp.text)
                    if not ka_err_type and ka_resp.status_code == 403:
                        ka_err_type = "QUOTA_EXHAUSTED"
                        ka_err_msg = "Fortinet keepalive returned HTTP 403 (Quota limit reached)"
                    if ka_err_type:
                        self.keepalive_url = None
                        if ka_err_type in ("QUOTA_EXHAUSTED", "PORTAL_REJECTED"):
                            self.logout()
                        return False, ka_err_type, ka_err_msg
            except Exception as e:
                logger.debug(f"Initial keepalive fetch for {ka_url} failed: {e}")
            logger.info(f"Login success! Fortinet keepalive URL acquired: {ka_url}")
            return True, "SUCCESS", "Logged in successfully (keepalive active)"

        if any(k in resp_lower for k in ["keepalive", "authentication successful", "you have successfully logged in"]):
            logger.info("Login success confirmed by Fortinet response text!")
            return True, "SUCCESS", "Logged in successfully"

        # 3. Check if response itself is still the Fortinet login form (credentials rejected or account limit hit)
        if self._is_login_form_page(resp_text):
            portal_summary = self._extract_portal_message(resp_text) or "Portal returned login form again"
            logger.warning(f"Fortinet returned login form after POST for '{username}': {portal_summary}")
            # Double-check if internet happened to unlock despite the form
            is_online, _ = self._verify_internet_probe()
            if is_online:
                return True, "SUCCESS", "Internet connection active!"
            self.logout()
            return False, "PORTAL_REJECTED", f"Account rejected by Fortinet portal ({portal_summary})"

        # 4. Verify real internet connectivity via HTTP 204 probe
        if resp.status_code == 204 or ("generate_204" in (resp.url or "") and not self._is_login_form_page(resp_text)):
            is_online, _ = self._verify_internet_probe()
            if is_online:
                return True, "SUCCESS", "Redirected and internet verified"

        is_online, test_resp = self._verify_internet_probe()
        if is_online:
            logger.info(f"Internet connectivity verified after login for '{username}'!")
            return True, "SUCCESS", "Internet connection active!"

        # 5. If still not online, inspect probe response for quota/error messages
        if test_resp is not None and test_resp.text:
            err_type, err_msg = self.check_for_quota_or_error(test_resp.text)
            if not err_type and test_resp.status_code == 403:
                err_type = "QUOTA_EXHAUSTED"
                err_msg = "Fortinet probe returned HTTP 403 (Quota limit or access blocked)"
            if err_type:
                if err_type in ("QUOTA_EXHAUSTED", "PORTAL_REJECTED"):
                    self.logout()
                return False, err_type, err_msg

        portal_summary = self._extract_portal_message(resp_text)
        reason = f"Still in captive portal after login ({portal_summary})" if portal_summary else "Still captured by portal after login"
        logger.warning(f"Login did not unlock internet for '{username}': {reason}")
        self.logout()
        return False, "PORTAL_REJECTED", reason

    def ping_keepalive(self):
        """Sends a periodic GET to the Fortinet keepalive URL if active."""
        if not self.keepalive_url:
            return False
        try:
            resp = self.session.get(self.keepalive_url, timeout=5, verify=False)
            return resp.status_code == 200
        except Exception as e:
            logger.debug(f"Keepalive ping to {self.keepalive_url} failed: {e}")
            return False

