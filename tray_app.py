import os
import sys
import time
import threading
import logging
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
import pystray

from account_manager import AccountManager
from network_detector import NetworkDetector, is_probe_url, extract_redirect_from_html
from fortinet_client import FortinetClient
from notifier import Notifier
from startup_manager import StartupManager
from ip_cycler import IPCycler
from wifi_roamer import WiFiRoamer

def get_app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

# Setup file and console logging
LOG_FILE = os.path.abspath(os.path.join(get_app_dir(), "mcs_login.log"))
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("MCS_TrayApp")

def create_status_icon(color):
    """Dynamically creates a 64x64 PIL status icon."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Outer circle
    draw.ellipse((4, 4, 60, 60), fill=color, outline=(255, 255, 255, 180), width=3)
    
    # Letter 'M' in the center
    # Fallback to simple cross/text if font not loaded
    try:
        font = ImageFont.truetype("arialbd.ttf", 32)
        bbox = draw.textbbox((0, 0), "M", font=font)
        w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        draw.text(((64 - w) / 2, (60 - h) / 2), "M", fill="white", font=font)
    except Exception:
        draw.text((22, 16), "M", fill="white")
        
    return img

ICON_COLORS = {
    "green": (46, 204, 113, 255),    # Online / Authenticated
    "yellow": (241, 196, 15, 255),  # Logging in / Switching
    "red": (231, 76, 60, 255),      # Exhausted / Error
    "gray": (149, 165, 166, 255)    # Offline
}

class MCSTrayApp:
    def __init__(self, check_interval_sec=15):
        self.check_interval_sec = check_interval_sec
        self.adaptive_interval = check_interval_sec
        self.account_mgr = AccountManager()
        self.detector = NetworkDetector()
        self.client = FortinetClient()
        self.notifier = Notifier()
        self.ip_cycler = IPCycler()
        self.wifi_roamer = WiFiRoamer()

        self.running = True
        self.current_status = "Initializing..."
        self.current_ssid = "Unknown"
        self.icon_state = "yellow"
        self.force_check_event = threading.Event()

        # Build system tray
        self.icon = pystray.Icon(
            "MCSAutoLogin",
            create_status_icon(ICON_COLORS["yellow"]),
            "MCS Auto-Login: Starting...",
            menu=self.build_menu()
        )
        self.notifier.set_tray_icon(self.icon)

    def build_menu(self):
        stats = self.account_mgr.get_stats()
        curr_user = stats["current_user"]
        avail = stats["available"]
        total = stats["total"]
        exhausted = stats["exhausted"]

        return pystray.Menu(
            pystray.MenuItem(f"Status: {self.current_status}", None, enabled=False),
            pystray.MenuItem(f"Wi-Fi: {self.current_ssid}", None, enabled=False),
            pystray.MenuItem(f"Active ID: {curr_user}", None, enabled=False),
            pystray.MenuItem(f"Pool: {avail}/{total} Available ({exhausted} Exhausted)", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("⚡ Log In Now / Check Internet", self.on_force_check),
            pystray.MenuItem("🔄 Switch to Next Account", self.on_switch_account),
            pystray.MenuItem("♻️ Reset All Accounts (Daily Reset)", self.on_reset_accounts),
            pystray.MenuItem("📶 Roam to Strongest MCS Wi-Fi", self.on_roam_wifi),
            pystray.MenuItem("🔧 Fix IP (Cycle Static IP)", self.on_fix_ip),
            pystray.MenuItem("🔄 Reset IP to DHCP", self.on_reset_dhcp),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("📊 Open Live Dashboard", self.on_open_dashboard),
            pystray.MenuItem("📋 View Accounts (accounts.json)", self.on_open_accounts),
            pystray.MenuItem("📜 View Logs (mcs_login.log)", self.on_open_logs),
            pystray.MenuItem(
                "🚀 Start on Windows Boot",
                self.on_toggle_startup,
                checked=lambda item: StartupManager.is_startup_enabled()
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("❌ Exit", self.on_exit)
        )

    def update_tray(self, state, status_text):
        self.icon_state = state
        self.current_status = status_text
        self.current_ssid = self.detector.get_current_wifi_ssid() or "Ethernet / Disconnected"
        
        stats = self.account_mgr.get_stats()
        tooltip = f"MCS: {status_text} | ID: {stats['current_user']} ({stats['available']}/{stats['total']})"
        
        # pystray tooltip has 128 char limit in Windows
        if len(tooltip) > 125:
            tooltip = tooltip[:122] + "..."

        self.icon.icon = create_status_icon(ICON_COLORS.get(state, ICON_COLORS["gray"]))
        self.icon.title = tooltip
        self.icon.menu = self.build_menu()

    def attempt_login_loop(self, portal_url, html):
        """
        Attempts login using available accounts, rotating if quota/limit or auth rejection is hit.
        """
        consecutive_net_failures = 0
        tried_in_this_cycle = set()
        portal_rejected_ids = []

        while self.running:
            acc = self.account_mgr.get_current_account()
            if not acc:
                if len(portal_rejected_ids) > 1:
                    self.account_mgr.restore_accounts(portal_rejected_ids)
                self.update_tray("red", "All accounts exhausted!")
                self.notifier.notify("MCS Alert", "All 29 accounts have reached their quota limits!")
                return False

            if acc["id"] in tried_in_this_cycle:
                logger.warning("Cycled through all available accounts without unlocking internet.")
                if portal_rejected_ids:
                    self.account_mgr.restore_accounts(portal_rejected_ids)
                self.update_tray("red", "All tried accounts failed")
                return False
            tried_in_this_cycle.add(acc["id"])

            self.update_tray("yellow", f"Logging in as {acc['username']}...")
            self.notifier.notify("MCS Auto-Login", f"Logging into Fortinet with account #{acc['id']} ({acc['username']})...")

            try:
                self.client.session.cookies.update(self.detector.session.cookies)
            except Exception:
                pass

            success, status_code, message = self.client.login(
                portal_url=portal_url,
                html=html,
                username=acc["username"],
                password=acc["password"]
            )

            if success:
                self.update_tray("green", f"Online as {acc['username']}")
                self.notifier.notify("MCS Connected!", f"Successfully authenticated as {acc['username']} (ID #{acc['id']}).")
                return True

            if status_code == "QUOTA_EXHAUSTED":
                self.account_mgr.mark_current_exhausted(message)
                self.notifier.notify("MCS Quota Hit", f"Account #{acc['id']} ({acc['username']}) reached limit. Switching to next...")
                self.account_mgr.get_next_account()
            elif status_code == "INVALID_CREDENTIALS":
                self.account_mgr.mark_current_invalid(message)
                self.notifier.notify("MCS Auth Failed", f"Account #{acc['id']} ({acc['username']}) rejected. Trying next...")
                self.account_mgr.get_next_account()
            elif status_code == "PORTAL_REJECTED":
                # Portal returned the login page again without unlocking internet (e.g. silent quota limit or concurrent session limit)
                portal_rejected_ids.append(acc["id"])
                self.account_mgr.mark_current_exhausted(message)
                self.notifier.notify("MCS Portal Rejected", f"Account #{acc['id']} ({acc['username']}) rejected by portal. Switching to next...")
                self.account_mgr.get_next_account()
            else:
                consecutive_net_failures += 1
                logger.warning(f"Login network/transport error ({consecutive_net_failures}): {message}")
                self.update_tray("yellow", f"Login error: {message}")
                return False

            # De-authenticate previous account on FortiGate auth-list
            gw_ip = self.detector.get_telemetry().get("gateway_ip")
            self.client.logout(gateway_ip=gw_ip)

            # Refresh portal detection to get a fresh magic token for the next account
            time.sleep(1)
            conn_status, data = self.detector.check_connection()
            if conn_status == "ONLINE":
                stats = self.account_mgr.get_stats()
                self.update_tray("green", f"Online ({stats['current_user']})")
                return True

            # If conn_status is CAPTIVE_PORTAL or OFFLINE, fetch directly from gateway
            gw_candidates = []
            if gw_ip:
                gw_candidates.append(f"https://{gw_ip}:1003/")
            gw_candidates.append("https://172.23.200.254:1003/")

            fetched_portal = False
            if conn_status == "CAPTIVE_PORTAL" and (data.get("portal_url") or data.get("html")):
                portal_url = data.get("portal_url", portal_url)
                html = data.get("html", "")
                fetched_portal = True
            elif data.get("portal_url") and not is_probe_url(data.get("portal_url")):
                gw_candidates.insert(0, data.get("portal_url"))

            if not fetched_portal:
                logger.info(f"Connection status is {conn_status}. Fetching fresh portal directly from gateway...")
                unique_gw_candidates = list(dict.fromkeys(gw_candidates))
                for gw_target in unique_gw_candidates:
                    try:
                        resp = self.client.session.get(gw_target, timeout=2, allow_redirects=True, verify=False)
                        if resp.status_code in [200, 301, 302, 303, 307] and resp.text:
                            redir = extract_redirect_from_html(resp.text, resp.url or gw_target)
                            if "<form" in resp.text.lower() or "fgtauth" in (resp.url or "").lower() or "fgtauth" in resp.text.lower() or redir:
                                if redir and "<form" not in resp.text.lower():
                                    try:
                                        r2 = self.client.session.get(redir, timeout=2, allow_redirects=True, verify=False)
                                        if r2.status_code in [200, 301, 302, 303, 307] and r2.text:
                                            portal_url = r2.url if (r2.url and "fgtauth" in r2.url.lower()) else redir
                                            html = r2.text
                                        else:
                                            portal_url = redir
                                            html = resp.text
                                    except Exception:
                                        portal_url = redir
                                        html = resp.text
                                else:
                                    portal_url = redir or resp.url or gw_target
                                    html = resp.text
                                fetched_portal = True
                                logger.info(f"Acquired fresh portal token from gateway: {portal_url}")
                                break
                    except Exception as e:
                        logger.debug(f"Direct gateway fetch {gw_target} failed: {e}")

            if not fetched_portal:
                if not portal_url or is_probe_url(portal_url):
                    portal_url = f"https://{gw_ip}:1003/" if gw_ip else "https://172.23.200.254:1003/"
                    html = ""
                if conn_status == "OFFLINE":
                    consecutive_net_failures += 1
                    if consecutive_net_failures >= 3:
                        logger.warning("Unreachable gateway and OFFLINE status. Aborting login loop.")
                        return False

        return False

    def monitor_loop(self):
        """Main background worker running adaptive periodic health checks."""
        logger.info("MCS background monitor thread started with Adaptive Heartbeat.")
        while self.running:
            try:
                # Check for daily midnight reset
                self.account_mgr.check_daily_reset()
                self.current_ssid = self.detector.get_current_wifi_ssid() or "Connected"

                # Check if current state is Online and fast probe passes
                if self.icon_state == "green" and self.detector.fast_probe():
                    self.client.ping_keepalive()
                    self.adaptive_interval = 12  # Healthy active interval
                else:
                    # Drop detected or not online: run full diagnostic check
                    conn_status, data = self.detector.check_connection()
                    logger.debug(f"Connection check result: {conn_status}")

                    if conn_status == "ONLINE":
                        self.client.ping_keepalive()
                        stats = self.account_mgr.get_stats()
                        self.update_tray("green", f"Online ({stats['current_user']})")
                        self.adaptive_interval = 12

                    elif conn_status == "CAPTIVE_PORTAL":
                        logger.info("Captive portal detected! Initiating auto-login...")
                        portal_url = data.get("portal_url", "")
                        html = data.get("html", "")
                        self.attempt_login_loop(portal_url, html)
                        self.adaptive_interval = 2  # Rapid retry if failed

                    elif conn_status == "OFFLINE":
                        # Check if DHCP is failed and try auto-healing IP
                        if self.ip_cycler.is_dhcp_failed():
                            logger.info("DHCP failed or APIPA address detected. Attempting auto-heal...")
                            healed, msg = self.ip_cycler.auto_heal_ip()
                            if healed:
                                self.notifier.notify("MCS IP Cycler", msg)
                                self.force_check_event.set()
                        self.update_tray("gray", "Offline (No Network)")
                        self.adaptive_interval = 5

            except Exception as e:
                logger.error(f"Error in monitor loop: {e}", exc_info=True)

            # Wait for next adaptive interval or immediate wake up on force_check_event
            self.force_check_event.wait(timeout=self.adaptive_interval)
            self.force_check_event.clear()

    # --- Menu Event Handlers ---
    def on_force_check(self, icon=None, item=None):
        logger.info("User requested manual check/login.")
        self.update_tray("yellow", "Checking connection...")
        self.force_check_event.set()

    def on_switch_account(self, icon=None, item=None):
        logger.info("User requested switch to next account.")
        gw_ip = self.detector.get_telemetry().get("gateway_ip")
        self.client.logout(gateway_ip=gw_ip)
        next_acc = self.account_mgr.get_next_account()
        if next_acc:
            self.notifier.notify("MCS Account Switched", f"Active account switched to #{next_acc['id']}: {next_acc['username']}")
            self.on_force_check()
        else:
            self.notifier.notify("MCS Alert", "No available accounts left to switch to!")

    def on_reset_accounts(self, icon=None, item=None):
        self.account_mgr.reset_all_accounts()
        self.notifier.notify("MCS Accounts Reset", "All 29 accounts have been reset to 'Available'.")
        self.on_force_check()

    def on_roam_wifi(self, icon=None, item=None):
        roamed, msg = self.wifi_roamer.auto_roam()
        self.notifier.notify("MCS Wi-Fi Roamer", msg)
        self.on_force_check()

    def on_fix_ip(self, icon=None, item=None):
        success, msg = self.ip_cycler.auto_heal_ip()
        self.notifier.notify("MCS IP Cycler", msg)
        self.on_force_check()

    def on_reset_dhcp(self, icon=None, item=None):
        success = self.ip_cycler.revert_to_dhcp()
        msg = "Restored Wi-Fi to DHCP" if success else "Failed to restore DHCP"
        self.notifier.notify("MCS IP Cycler", msg)
        self.on_force_check()

    def on_open_dashboard(self, icon=None, item=None):
        dash_path = os.path.abspath(os.path.join(get_app_dir(), "dashboard.bat"))
        try:
            os.startfile(dash_path)
        except Exception as e:
            logger.error(f"Failed to open dashboard: {e}")

    def on_open_accounts(self, icon=None, item=None):
        try:
            os.startfile(self.account_mgr.filepath)
        except Exception as e:
            logger.error(f"Failed to open accounts.json: {e}")

    def on_open_logs(self, icon=None, item=None):
        try:
            os.startfile(LOG_FILE)
        except Exception as e:
            logger.error(f"Failed to open log file: {e}")

    def on_toggle_startup(self, icon=None, item=None):
        current = StartupManager.is_startup_enabled()
        StartupManager.set_startup(not current)
        self.icon.menu = self.build_menu()

    def on_exit(self, icon=None, item=None):
        logger.info("Exiting MCS Auto-Login app...")
        self.running = False
        self.force_check_event.set()
        self.icon.stop()

    def run(self):
        # Start background monitor thread
        monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        monitor_thread.start()

        # Run tray loop (blocking call on main thread for pystray)
        self.icon.run()
