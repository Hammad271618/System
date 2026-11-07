import sys
import logging
from account_manager import AccountManager
from network_detector import NetworkDetector
from fortinet_client import FortinetClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("MCS_Tester")

def test_system():
    print("=" * 60)
    print("      MCS Fortinet Auto-Login Diagnostics & Test")
    print("=" * 60)

    # 1. Test Account Manager
    acc_mgr = AccountManager()
    stats = acc_mgr.get_stats()
    print(f"\n[1] Accounts Pool:")
    print(f"    - Total Accounts: {stats['total']}")
    print(f"    - Available:      {stats['available']}")
    print(f"    - Exhausted:      {stats['exhausted']}")
    print(f"    - Active Account: {stats['current_user']} (Index #{stats['current_index']})")

    # 2. Test Network Detector & Telemetry
    detector = NetworkDetector()
    telemetry = detector.get_telemetry()
    print(f"\n[2] Network Interface & Telemetry:")
    print(f"    - Wi-Fi SSID:     {telemetry['ssid'] or 'Not on Wi-Fi (Ethernet / Disconnected)'} (Signal: {telemetry['signal'] or 'N/A'})")
    print(f"    - IPv4 Address:   {telemetry['local_ip'] or 'N/A'} (Config: {'DHCP' if telemetry['is_dhcp'] else 'Static'})")
    print(f"    - Default Gateway:{telemetry['gateway_ip'] or 'N/A'}")
    print(f"    - Fast Probe:     {'ONLINE (' + str(telemetry['latency_ms']) + 'ms)' if telemetry['status'] == 'ONLINE' else telemetry['status']}")

    # 3. Test IP Cycler & Wi-Fi Roamer
    from ip_cycler import IPCycler
    from wifi_roamer import WiFiRoamer
    cycler = IPCycler()
    roamer = WiFiRoamer()
    print(f"\n[3] Self-Healing & Roaming:")
    print(f"    - DHCP Health:    {'STUCK (Needs Auto-Heal)' if cycler.is_dhcp_failed() else 'OK'}")
    best_ap = roamer.get_best_mcs_ap()
    print(f"    - Best MCS AP:    {best_ap['ssid'] + ' (' + str(best_ap['signal']) + '%)' if best_ap else 'None detected'}")

    print(f"\n[4] Testing Detailed Connectivity...")
    status, data = detector.check_connection()
    print(f"    - Status: {status}")
    print(f"    - Details: {data}")

    # 3. If Captive Portal Detected
    if status == "CAPTIVE_PORTAL":
        print("\n[!] Captive Portal Detected!")
        portal_url = data.get("portal_url", "")
        html = data.get("html", "")
        print(f"    - Portal URL: {portal_url}")
        
        client = FortinetClient()
        parsed = client.parse_portal_form(html, portal_url)
        print(f"    - Detected Form Action:   {parsed['post_url']}")
        print(f"    - Username Field Name:    {parsed['username_field']}")
        print(f"    - Password Field Name:    {parsed['password_field']}")
        print(f"    - Hidden Fields Detected: {list(parsed['payload'].keys())}")

        acc = acc_mgr.get_current_account()
        if acc:
            print(f"\n[4] Attempting login with: {acc['username']} ...")
            success, code, msg = client.login(portal_url, html, acc["username"], acc["password"])
            print(f"    - Result: {success} ({code}) -> {msg}")
    elif status == "ONLINE":
        print("\n[OK] You are currently ONLINE! Internet is working normally.")
    elif status == "OFFLINE":
        print("\n[OFFLINE] No connection to internet or captive portal.")

    print("\n" + "=" * 60)


def run_unit_tests():
    print("\n[Unit Tests] Verifying MCS Fortinet Portal Parser & Redirect Resolver...")
    import urllib.parse as up
    from network_detector import extract_redirect_from_html, is_probe_url

    # 1. Exact HTML structure of captive portal gateway (172.23.200.254:1003)
    sample_mcs_portal_html = """
    <html>
    <head>
      <title>Firewall Authentication</title>
      <link rel="icon" href="https://172.23.200.254:1003/favicon.ico">
    </head>
    <body>
      <div class="oc">
        <div class="ic">
          <img src="https://172.23.200.254:1003/XX/YY/ZZ/CI/MGPGHGPGPFGHCDPFGGOGFGEH">
          <form action="/" method="post">
            <input type="hidden" name="4Tredir" value="http://connectivitycheck.gstatic.com/generate_204">
            <input type="hidden" name="magic" value="060006914c305f33">
            <input type="hidden" name value>
            <h1 class="logo"> Authentication Required </h1>
            <h2> Please enter username and password </h2>
            <div class="fel"><input type="text" name="username" id="ft_un"></div>
            <div class="fel"><input type="password" name="password" id="ft_pd"></div>
            <div class="fer"><input type="submit" value="Continue"></div>
          </form>
        </div>
      </div>
    </body>
    </html>
    """

    client = FortinetClient()

    # Case A: When base_url is the actual Fortinet portal URL
    parsed_a = client.parse_portal_form(
        sample_mcs_portal_html,
        "https://172.23.200.254:1003/fgtauth?060006914c305f33"
    )
    assert parsed_a["post_url"] == "https://172.23.200.254:1003/", f"Unexpected post_url: {parsed_a['post_url']}"
    assert parsed_a["payload"].get("magic") == "060006914c305f33", f"Missing magic: {parsed_a['payload']}"
    assert parsed_a["payload"].get("4Tredir") == "http://connectivitycheck.gstatic.com/generate_204"
    assert parsed_a["username_field"] == "username"
    assert parsed_a["password_field"] == "password"
    assert "" not in parsed_a["payload"], "Empty-name `<input type='hidden' name value>` must be omitted per HTML spec"
    encoded_a = up.urlencode(parsed_a["payload"])
    assert "=&" not in encoded_a and not encoded_a.startswith("="), f"Malformed empty key in form body: {encoded_a}"

    # Case B: Base URL is the probe URL, and HTML has :1003/favicon.ico & :1003/XX/YY/ZZ/... static assets
    parsed_b = client.parse_portal_form(
        sample_mcs_portal_html,
        "http://connectivitycheck.gstatic.com/generate_204"
    )
    assert not is_probe_url(parsed_b["post_url"]), f"POST URL must NEVER be a probe URL! Got: {parsed_b['post_url']}"
    assert parsed_b["post_url"] == "https://172.23.200.254:1003/", f"Expected Fortinet gateway POST URL, got: {parsed_b['post_url']}"
    assert parsed_b["portal_url"] == "https://172.23.200.254:1003/fgtauth?060006914c305f33"

    # Case C: 200 OK JS redirect stub intercepted on connectivitycheck.gstatic.com
    js_stub = '<html><head><script>window.location="https://172.23.200.254:1003/fgtauth?060006914c305f33";</script></head></html>'
    extracted = extract_redirect_from_html(js_stub, "http://connectivitycheck.gstatic.com/generate_204")
    assert extracted == "https://172.23.200.254:1003/fgtauth?060006914c305f33", f"Failed JS redirect extraction: {extracted}"

    # Case D: Meta refresh redirect stub
    meta_stub = '<html><head><meta http-equiv="refresh" content="0;url=https://172.23.200.254:1003/fgtauth?060006914c305f33"></head></html>'
    extracted_meta = extract_redirect_from_html(meta_stub, "http://connectivitycheck.gstatic.com/generate_204")
    assert extracted_meta == "https://172.23.200.254:1003/fgtauth?060006914c305f33", f"Failed meta redirect extraction: {extracted_meta}"

    # Case E: Login form detection & static asset filtering
    assert client._is_login_form_page(sample_mcs_portal_html) is True
    assert client._is_login_form_page("<html><body>Keepalive</body></html>") is False
    assert extract_redirect_from_html(sample_mcs_portal_html, "http://connectivitycheck.gstatic.com/generate_204") is None

    # Case F: End-to-End Mock Captive Portal Server, Cookie Persistence, Keepalive GET & Account Rotation
    import threading
    from http.server import HTTPServer, BaseHTTPRequestHandler

    submitted_requests = []
    keepalive_hits = []

    class MockFortiGateHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            if "fgtauth" in self.path:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Set-Cookie", "FGTSESSID=testcookie123; Path=/")
                self.end_headers()
                self.wfile.write(sample_mcs_portal_html.encode("utf-8"))
            elif "keepalive" in self.path:
                keepalive_hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>Keepalive active</body></html>")
            else:
                self.send_response(200)
                self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            form_data = dict(up.parse_qsl(body, keep_blank_values=True))
            submitted_requests.append({
                "path": self.path,
                "headers": dict(self.headers),
                "raw_body": body,
                "form": form_data
            })
            # First account fails with quota limit; second account succeeds with keepalive URL
            if len(submitted_requests) == 1:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Transfer limit exceeded</h1><p>Daily quota reached</p></body></html>")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b'<html><body>Authentication Successful! <script>window.location="/keepalive?060006914c305f33";</script></body></html>')

    server = HTTPServer(("127.0.0.1", 0), MockFortiGateHandler)
    port = server.server_port
    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()

    try:
        mock_portal_url = f"http://127.0.0.1:{port}/fgtauth?060006914c305f33"
        js_redirect_html = f'<html><script>window.location="{mock_portal_url}";</script></html>'

        # Simulate starting from intercepted probe URL (http://connectivitycheck.gstatic.com/generate_204)
        ok1, code1, msg1 = client.login("http://connectivitycheck.gstatic.com/generate_204", js_redirect_html, "user1", "pass1")
        assert ok1 is False and code1 == "QUOTA_EXHAUSTED", f"Expected QUOTA_EXHAUSTED, got {ok1}, {code1}, {msg1}"
        assert submitted_requests[0]["form"].get("username") == "user1"
        assert submitted_requests[0]["form"].get("magic") == "060006914c305f33"
        assert "" not in submitted_requests[0]["form"], "Empty key should not be submitted"
        assert "FGTSESSID=testcookie123" in (submitted_requests[0]["headers"].get("Cookie") or ""), "Session cookie from GET /fgtauth must be preserved on POST /"

        # Second account login succeeds and triggers GET /keepalive?060006914c305f33
        ok2, code2, msg2 = client.login("http://connectivitycheck.gstatic.com/generate_204", js_redirect_html, "user2", "pass2")
        assert ok2 is True and code2 == "SUCCESS", f"Expected SUCCESS, got {ok2}, {code2}, {msg2}"
        assert submitted_requests[1]["form"].get("username") == "user2"
        assert client.keepalive_url == f"http://127.0.0.1:{port}/keepalive?060006914c305f33"
        assert len(keepalive_hits) >= 1, "Expected initial GET to /keepalive?... upon login"
        assert client.ping_keepalive() is True

        # Case G: Verify tray_app.attempt_login_loop rotation on QUOTA_EXHAUSTED -> SUCCESS
        # and full-cycle PORTAL_REJECTED recovery (does not brick all accounts on transient outage)
        import tempfile, json, os
        from tray_app import MCSTrayApp
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tf:
            temp_acc_path = tf.name
            json.dump([
                {"id": 1, "name": "Test1", "username": "u1", "password": "p1", "status": "in_use"},
                {"id": 2, "name": "Test2", "username": "u2", "password": "p2", "status": "available"}
            ], tf)
        try:
            app = MCSTrayApp(check_interval_sec=60)
            app.account_mgr = AccountManager(filepath=temp_acc_path)
            app.notifier.notify = lambda title, msg: None
            app.update_tray = lambda state, text: None
            app.detector.get_telemetry = lambda: {"gateway_ip": "127.0.0.1"}
            app.detector.check_connection = lambda: ("CAPTIVE_PORTAL", {"portal_url": mock_portal_url, "html": sample_mcs_portal_html})

            # Reset submitted_requests so 1st POST fails with quota and 2nd POST succeeds
            submitted_requests.clear()
            res = app.attempt_login_loop(mock_portal_url, sample_mcs_portal_html)
            assert res is True, "attempt_login_loop should rotate from account #1 to #2 and return True"
            assert app.account_mgr.accounts[0]["status"] == "exhausted"
            assert app.account_mgr.accounts[1]["status"] == "in_use"

            # Now simulate a transient RADIUS outage where ALL accounts return PORTAL_REJECTED:
            app.account_mgr.reset_all_accounts()
            app.client.login = lambda portal_url, html, username, password: (False, "PORTAL_REJECTED", "Portal returned login form again")
            res_outage = app.attempt_login_loop(mock_portal_url, sample_mcs_portal_html)
            assert res_outage is False
            avail_after_outage = app.account_mgr.get_stats()["available"]
            assert avail_after_outage == 2, f"Transient full-cycle PORTAL_REJECTED must restore accounts, got {avail_after_outage} available"
        finally:
            if os.path.exists(temp_acc_path):
                os.remove(temp_acc_path)
    finally:
        server.shutdown()
        server.server_close()

    # Suite 9: Test IPCycler candidate generation, APIPA detection, IP: None renewal & unreachable gateway auto-revert
    from ip_cycler import IPCycler
    cycler = IPCycler()
    cand = cycler.find_available_ip("172.23.210.1")
    assert cand is not None and cand.startswith("172.23.210."), f"Invalid candidate IP: {cand}"
    # Verify mock APIPA detection
    cycler.get_current_ip_info = lambda: ("169.254.45.12", None, True)
    assert cycler.is_dhcp_failed() is True, "APIPA 169.254.x.x should be detected as DHCP failed"
    # Verify IP: None does NOT assign static IP, but renews DHCP
    renew_called = []
    cycler.get_current_ip_info = lambda: (None, None, True)
    cycler.renew_dhcp = lambda: renew_called.append("renew")
    healed_none, _ = cycler.auto_heal_ip()
    assert healed_none is True and "renew" in renew_called, "IP: None must trigger renew_dhcp"
    # Verify unreachable gateway on static IP triggers auto-revert to DHCP
    cycler.get_current_ip_info = lambda: ("172.23.210.140", "172.23.210.1", False)
    cycler.is_ip_in_use = lambda ip: False
    revert_called = []
    cycler.renew_dhcp = lambda: revert_called.append("revert")
    assert cycler.is_dhcp_failed() is True, "Unreachable gateway on static IP should return True"
    assert "revert" in revert_called, "Unreachable gateway on static IP must auto-revert to DHCP"

    # Suite 10: Test WiFiRoamer SSID recognition & sorting
    from wifi_roamer import WiFiRoamer
    roamer = WiFiRoamer()
    assert roamer.is_mcs_ssid("AccessNet-01") is True
    assert roamer.is_mcs_ssid("Campus_WiFi") is True
    assert roamer.is_mcs_ssid("LC02") is True
    assert roamer.is_mcs_ssid("MyHomeRouter") is False

    print("[Unit Tests] All 10 test suites (including FortiGate POST, cookies, keepalive, TrayApp recovery, IPCycler & WiFiRoamer) PASSED!")


if __name__ == "__main__":
    run_unit_tests()
    test_system()


