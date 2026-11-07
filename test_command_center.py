import os
import sys
import unittest
import tempfile
import json
from unittest.mock import patch, MagicMock

# Ensure current project directory in path
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from account_manager import AccountManager
from service_controller import ServiceController
from command_center import CommandCenter

class TestAccountManagerExtensions(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w", encoding="utf-8")
        self.initial_data = [
            {"id": 1, "sc": "1001", "name": "TEST USER 1", "username": "user1", "password": "pw1", "status": "available"},
            {"id": 2, "sc": "1002", "name": "TEST USER 2", "username": "user2", "password": "pw2", "status": "exhausted"},
        ]
        json.dump(self.initial_data, self.temp_file)
        self.temp_file.close()
        self.mgr = AccountManager(filepath=self.temp_file.name)

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            try:
                os.remove(self.temp_file.name)
            except Exception:
                pass

    def test_get_account_by_id(self):
        acc = self.mgr.get_account_by_id(1)
        self.assertIsNotNone(acc)
        self.assertEqual(acc["username"], "user1")

        acc2 = self.mgr.get_account_by_id("2")
        self.assertIsNotNone(acc2)
        self.assertEqual(acc2["username"], "user2")

        self.assertIsNone(self.mgr.get_account_by_id(999))
        self.assertIsNone(self.mgr.get_account_by_id("invalid"))

    def test_set_current_account_by_id(self):
        self.assertTrue(self.mgr.set_current_account_by_id(2))
        curr = self.mgr.get_current_account()
        self.assertEqual(curr["id"], 2)
        self.assertEqual(curr["status"], "in_use")

        # Invalid ID
        self.assertFalse(self.mgr.set_current_account_by_id(999))

    def test_add_and_remove_account(self):
        new_acc = self.mgr.add_account("newuser", "newpw", name="New Name", sc="1003")
        self.assertEqual(new_acc["id"], 3)
        self.assertEqual(new_acc["username"], "newuser")
        self.assertEqual(len(self.mgr.accounts), 3)

        # Removal
        self.assertTrue(self.mgr.remove_account(3))
        self.assertEqual(len(self.mgr.accounts), 2)
        self.assertIsNone(self.mgr.get_account_by_id(3))

        # Removing non-existent
        self.assertFalse(self.mgr.remove_account(999))

class TestServiceController(unittest.TestCase):
    def setUp(self):
        self.ctrl = ServiceController()

    def test_get_status_structure(self):
        status = self.ctrl.get_status()
        self.assertIn("running", status)
        self.assertIn("pids", status)
        self.assertIn("instances", status)
        self.assertIn("summary", status)
        self.assertIn("mode", status)
        self.assertIsInstance(status["running"], bool)
        self.assertIsInstance(status["pids"], list)

    def test_find_running_instances_execution(self):
        instances = self.ctrl.find_running_instances()
        self.assertIsInstance(instances, list)
        for inst in instances:
            self.assertIn("pid", inst)
            self.assertIn("name", inst)
            self.assertIn("cmdline", inst)

    def test_is_service_process_filtering(self):
        self.assertTrue(self.ctrl._is_service_process("MCS-AutoLogin.exe", ""))
        self.assertTrue(self.ctrl._is_service_process("pythonw.exe", "pythonw.exe main.py"))
        self.assertTrue(self.ctrl._is_service_process("python.exe", "python.exe tray_app.py"))
        self.assertFalse(self.ctrl._is_service_process("python.exe", "python.exe command_center.py"))
        self.assertFalse(self.ctrl._is_service_process("python.exe", "python.exe build_package.py"))
        self.assertFalse(self.ctrl._is_service_process("notepad.exe", "notepad.exe file.txt"))

class TestCommandCenterDispatch(unittest.TestCase):
    def setUp(self):
        self.cc = CommandCenter()

    def test_dispatch_exit(self):
        self.assertFalse(self.cc.dispatch("exit"))
        self.assertFalse(self.cc.dispatch("quit"))
        self.assertFalse(self.cc.dispatch("q"))
        self.assertFalse(self.cc.dispatch("15"))

    def test_dispatch_number_mapping(self):
        with patch.object(self.cc, "cmd_status") as mock_status:
            self.assertTrue(self.cc.dispatch("1"))
            mock_status.assert_called_once()

        with patch.object(self.cc, "cmd_accounts") as mock_accounts:
            self.assertTrue(self.cc.dispatch("4"))
            mock_accounts.assert_called_once()

        with patch.object(self.cc, "cmd_reset") as mock_reset:
            self.assertTrue(self.cc.dispatch("6"))
            mock_reset.assert_called_once()

    def test_dispatch_commands(self):
        with patch.object(self.cc, "cmd_switch") as mock_switch:
            self.assertTrue(self.cc.dispatch("switch"))
            mock_switch.assert_called_once()

        with patch.object(self.cc, "cmd_login") as mock_login:
            self.assertTrue(self.cc.dispatch("login 5"))
            mock_login.assert_called_once_with(5)

        with patch.object(self.cc, "cmd_roam") as mock_roam:
            self.assertTrue(self.cc.dispatch("roam"))
            mock_roam.assert_called_once()

        with patch.object(self.cc, "cmd_fix_ip") as mock_ip:
            self.assertTrue(self.cc.dispatch("fix-ip"))
            mock_ip.assert_called_once()

        with patch.object(self.cc, "cmd_dhcp") as mock_dhcp:
            self.assertTrue(self.cc.dispatch("dhcp"))
            mock_dhcp.assert_called_once()

        with patch.object(self.cc, "cmd_start_bg") as mock_start:
            self.assertTrue(self.cc.dispatch("start-bg"))
            mock_start.assert_called_once()

        with patch.object(self.cc, "cmd_stop_bg") as mock_stop:
            self.assertTrue(self.cc.dispatch("stop-bg"))
            mock_stop.assert_called_once()

        with patch.object(self.cc, "cmd_add_account") as mock_add:
            self.assertTrue(self.cc.dispatch("add test.user mypass 'Test User' 999"))
            mock_add.assert_called_once_with(["test.user", "mypass", "Test User", "999"])

        with patch.object(self.cc, "cmd_remove_account") as mock_rm:
            self.assertTrue(self.cc.dispatch("remove 7"))
            mock_rm.assert_called_once_with(7)

class TestBuildPackage(unittest.TestCase):
    def test_build_from_frozen(self):
        import build_package
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create mock dummy files in tmp_dir
            for fn in ["MCS-AutoLogin.exe", "MCS-CommandCenter.exe", "accounts.json", "command_center.bat"]:
                with open(os.path.join(tmp_dir, fn), "w") as f:
                    f.write("mock")
            zip_res = build_package.build_from_frozen(tmp_dir)
            self.assertTrue(os.path.exists(zip_res))
            import zipfile
            with zipfile.ZipFile(zip_res, "r") as zf:
                names = zf.namelist()
                self.assertIn("MCS-AutoLogin-v1.0/MCS-AutoLogin.exe", names)
                self.assertIn("MCS-AutoLogin-v1.0/README.txt", names)


class TestFortinetClientLogout(unittest.TestCase):
    def setUp(self):
        from fortinet_client import FortinetClient
        self.client = FortinetClient()

    def test_logout_hits_expected_endpoints(self):
        requested_urls = []
        with patch.object(self.client, "_create_session") as mock_sess_factory:
            mock_sess = MagicMock()
            mock_sess.get.side_effect = lambda url, **kwargs: requested_urls.append(url)
            mock_sess_factory.return_value = mock_sess

            self.client.logout(gateway_ip="172.23.210.1")

            expected = [
                "https://172.23.210.1:1003/logout?",
                "http://172.23.210.1:1000/logout?",
                "https://172.23.200.254:1003/logout?",
                "http://1.1.1.1/logout?"
            ]
            self.assertEqual(requested_urls, expected)
            self.assertIsNone(self.client.keepalive_url)

    def test_logout_ignores_probe_urls(self):
        requested_urls = []
        with patch.object(self.client, "_create_session") as mock_sess_factory:
            mock_sess = MagicMock()
            mock_sess.get.side_effect = lambda url, **kwargs: requested_urls.append(url)
            mock_sess_factory.return_value = mock_sess

            self.client.logout(gateway_ip="http://connectivitycheck.gstatic.com/generate_204")

            # Must NOT contain connectivitycheck.gstatic.com
            for u in requested_urls:
                self.assertNotIn("connectivitycheck.gstatic.com", u)
            self.assertIn("https://172.23.200.254:1003/logout?", requested_urls)
            self.assertIn("http://1.1.1.1/logout?", requested_urls)

    def test_logout_with_scheme_and_port(self):
        requested_urls = []
        with patch.object(self.client, "_create_session") as mock_sess_factory:
            mock_sess = MagicMock()
            mock_sess.get.side_effect = lambda url, **kwargs: requested_urls.append(url)
            mock_sess_factory.return_value = mock_sess

            self.client.logout(gateway_ip="https://172.23.210.1:1003/")

            self.assertIn("https://172.23.210.1:1003/logout?", requested_urls)
            self.assertIn("http://172.23.210.1:1000/logout?", requested_urls)

    def test_login_triggers_logout_on_quota(self):
        with patch.object(self.client, "logout") as mock_logout, \
             patch.object(self.client.session, "post") as mock_post:
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "<html><body>Transfer limit exceeded</body></html>"
            resp.url = "https://172.23.200.254:1003/"
            mock_post.return_value = resp

            ok, code, msg = self.client.login("https://172.23.200.254:1003/", "<form></form>", "u1", "p1")
            self.assertFalse(ok)
            self.assertEqual(code, "QUOTA_EXHAUSTED")
            mock_logout.assert_called_once()

    def test_login_triggers_logout_on_403(self):
        with patch.object(self.client, "logout") as mock_logout, \
             patch.object(self.client.session, "post") as mock_post:
            resp = MagicMock()
            resp.status_code = 403
            resp.text = "Forbidden"
            resp.url = "https://172.23.200.254:1003/"
            mock_post.return_value = resp

            ok, code, msg = self.client.login("https://172.23.200.254:1003/", "<form></form>", "u1", "p1")
            self.assertFalse(ok)
            self.assertEqual(code, "QUOTA_EXHAUSTED")
            mock_logout.assert_called_once()


class TestCommandCenterSwitchBehavior(unittest.TestCase):
    def setUp(self):
        self.cc = CommandCenter()

    def test_switch_calls_logout_and_submits_when_offline(self):
        mock_acc = {"id": 2, "username": "user2", "password": "pw2", "name": "User Two", "status": "available"}
        with patch.object(self.cc.acc_mgr, "get_next_account", return_value=mock_acc), \
             patch.object(self.cc.client, "logout") as mock_logout, \
             patch.object(self.cc.detector, "check_connection", return_value=("OFFLINE", {})), \
             patch.object(self.cc.detector, "get_telemetry", return_value={"gateway_ip": "172.23.200.254"}), \
             patch.object(self.cc.client.session, "get") as mock_get, \
             patch.object(self.cc.client, "login", return_value=(True, "SUCCESS", "OK")) as mock_login, \
             patch.object(self.cc.acc_mgr, "save"):

            portal_resp = MagicMock()
            portal_resp.status_code = 200
            portal_resp.text = "<form action='/'><input type='password' name='password'></form>"
            portal_resp.url = "https://172.23.200.254:1003/"
            mock_get.return_value = portal_resp

            self.cc.cmd_switch()

            mock_logout.assert_called_once_with(gateway_ip="172.23.200.254")
            mock_login.assert_called_once()
            args, _ = mock_login.call_args
            self.assertEqual(args[2], "user2")
            self.assertEqual(args[3], "pw2")

    def test_switch_handles_js_redirect_stub_when_offline(self):
        mock_acc = {"id": 2, "username": "user2", "password": "pw2", "name": "User Two", "status": "available"}
        with patch.object(self.cc.acc_mgr, "get_next_account", return_value=mock_acc), \
             patch.object(self.cc.client, "logout"), \
             patch.object(self.cc.detector, "check_connection", return_value=("OFFLINE", {})), \
             patch.object(self.cc.detector, "get_telemetry", return_value={"gateway_ip": "172.23.200.254"}), \
             patch.object(self.cc.client.session, "get") as mock_get, \
             patch.object(self.cc.client, "login", return_value=(True, "SUCCESS", "OK")) as mock_login, \
             patch.object(self.cc.acc_mgr, "save"):

            portal_resp = MagicMock()
            portal_resp.status_code = 200
            portal_resp.text = '<html><script>window.location="https://172.23.200.254:1003/fgtauth?060006914c305f33";</script></html>'
            portal_resp.url = "https://172.23.200.254:1003/"
            mock_get.return_value = portal_resp

            self.cc.cmd_switch()

            mock_login.assert_called_once()
            args, _ = mock_login.call_args
            self.assertIn("fgtauth", args[0])


class TestIPCyclerSubnetPoisoningFixes(unittest.TestCase):
    def setUp(self):
        from ip_cycler import IPCycler
        self.cycler = IPCycler("Wi-Fi")

    def test_ip_none_triggers_renew_dhcp_not_static_ip(self):
        with patch.object(self.cycler, "get_current_ip_info", return_value=(None, None, True)), \
             patch.object(self.cycler, "renew_dhcp") as mock_renew, \
             patch.object(self.cycler, "set_static_ip") as mock_static:

            healed, msg = self.cycler.auto_heal_ip()
            self.assertTrue(healed)
            mock_renew.assert_called_once()
            mock_static.assert_not_called()

    def test_unreachable_gateway_on_static_triggers_revert(self):
        with patch.object(self.cycler, "get_current_ip_info", return_value=("172.23.210.140", "172.23.210.1", False)), \
             patch.object(self.cycler, "is_ip_in_use", return_value=False), \
             patch.object(self.cycler, "renew_dhcp") as mock_renew:

            self.assertTrue(self.cycler.is_dhcp_failed())
            mock_renew.assert_called_once()

    def test_auto_heal_ip_avoids_double_renew_when_static_gw_unreachable(self):
        with patch.object(self.cycler, "get_current_ip_info", return_value=("172.23.210.140", "172.23.210.1", False)), \
             patch.object(self.cycler, "is_ip_in_use", return_value=False), \
             patch.object(self.cycler, "renew_dhcp") as mock_renew:

            healed, msg = self.cycler.auto_heal_ip()
            self.assertTrue(healed)
            # renew_dhcp should only be called once by is_dhcp_failed(), not duplicated
            mock_renew.assert_called_once()

    def test_apipa_with_no_reachable_gw_triggers_renew_not_poison(self):
        with patch.object(self.cycler, "get_current_ip_info", return_value=("169.254.10.20", None, True)), \
             patch.object(self.cycler, "is_ip_in_use", return_value=False), \
             patch.object(self.cycler, "renew_dhcp") as mock_renew, \
             patch.object(self.cycler, "set_static_ip") as mock_static:

            healed, msg = self.cycler.auto_heal_ip()
            self.assertTrue(healed)
            mock_renew.assert_called_once()
            mock_static.assert_not_called()


class TestTrayAppOfflineQuotaRecovery(unittest.TestCase):
    def test_attempt_login_loop_continues_on_offline(self):
        from tray_app import MCSTrayApp
        app = MCSTrayApp(check_interval_sec=60)
        app.notifier.notify = lambda title, msg: None
        app.update_tray = lambda state, text: None

        acc1 = {"id": 1, "name": "User One", "username": "u1", "password": "p1", "status": "in_use"}
        acc2 = {"id": 2, "name": "User Two", "username": "u2", "password": "p2", "status": "available"}
        app.account_mgr.accounts = [acc1, acc2]
        app.account_mgr.current_index = 0
        app.account_mgr.save = lambda: None

        login_calls = []
        def mock_login(portal_url, html, username, password):
            login_calls.append(username)
            if username == "u1":
                return False, "QUOTA_EXHAUSTED", "Limit reached"
            return True, "SUCCESS", "Logged in"

        app.client.login = mock_login
        app.detector.check_connection = MagicMock(return_value=("OFFLINE", {}))
        app.detector.get_telemetry = MagicMock(return_value={"gateway_ip": "172.23.200.254"})

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<form action='/'><input type='password' name='password'></form>"
        mock_resp.url = "https://172.23.200.254:1003/"

        with patch.object(app.client.session, "get", return_value=mock_resp), \
             patch.object(app.client, "logout"):
            res = app.attempt_login_loop("https://172.23.200.254:1003/", "<form></form>")

            self.assertTrue(res)
            self.assertEqual(login_calls, ["u1", "u2"])

    def test_attempt_login_loop_resolves_js_redirect_on_offline(self):
        from tray_app import MCSTrayApp
        app = MCSTrayApp(check_interval_sec=60)
        app.notifier.notify = lambda title, msg: None
        app.update_tray = lambda state, text: None

        acc1 = {"id": 1, "name": "User One", "username": "u1", "password": "p1", "status": "in_use"}
        acc2 = {"id": 2, "name": "User Two", "username": "u2", "password": "p2", "status": "available"}
        app.account_mgr.accounts = [acc1, acc2]
        app.account_mgr.current_index = 0
        app.account_mgr.save = lambda: None

        login_urls = []
        def mock_login(portal_url, html, username, password):
            login_urls.append((username, portal_url))
            if username == "u1":
                return False, "QUOTA_EXHAUSTED", "Limit reached"
            return True, "SUCCESS", "Logged in"

        app.client.login = mock_login
        app.detector.check_connection = MagicMock(return_value=("OFFLINE", {}))
        app.detector.get_telemetry = MagicMock(return_value={"gateway_ip": "172.23.200.254"})

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><script>window.location="https://172.23.200.254:1003/fgtauth?060006914c305f33";</script></html>'
        mock_resp.url = "https://172.23.200.254:1003/"

        with patch.object(app.client.session, "get", return_value=mock_resp), \
             patch.object(app.client, "logout"):
            res = app.attempt_login_loop("http://connectivitycheck.gstatic.com/generate_204", "stub")

            self.assertTrue(res)
            self.assertEqual(len(login_urls), 2)
            # Second call must NOT be the external probe URL
            self.assertIn("fgtauth", login_urls[1][1])

    def test_on_switch_account_triggers_logout(self):
        from tray_app import MCSTrayApp
        app = MCSTrayApp(check_interval_sec=60)
        app.notifier.notify = lambda title, msg: None
        app.detector.get_telemetry = MagicMock(return_value={"gateway_ip": "172.23.200.254"})

        app.account_mgr.save = lambda: None

        with patch.object(app.client, "logout") as mock_logout, \
             patch.object(app, "on_force_check"):
            app.on_switch_account()
            mock_logout.assert_called_once_with(gateway_ip="172.23.200.254")


if __name__ == "__main__":
    unittest.main()

