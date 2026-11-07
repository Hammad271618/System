import os
import sys
import time
import shlex
import logging

# Ensure UTF-8 console output and enable Windows ANSI color codes
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

os.system("")  # Activates VT100 / ANSI escape sequences in Windows console

from account_manager import AccountManager
from network_detector import NetworkDetector, is_probe_url, extract_redirect_from_html
from fortinet_client import FortinetClient
from ip_cycler import IPCycler
from wifi_roamer import WiFiRoamer
from service_controller import ServiceController

# ANSI Colors
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_BLUE = "\033[94m"
C_WHITE = "\033[97m"
C_GRAY = "\033[90m"
C_BG_BLUE = "\033[44m"
C_BG_GREEN = "\033[42m"
C_BG_RED = "\033[41m"
C_BG_YELLOW = "\033[43m"

class CommandCenter:
    def __init__(self):
        self.acc_mgr = AccountManager()
        self.detector = NetworkDetector()
        self.client = FortinetClient()
        self.ip_cycler = IPCycler()
        self.wifi_roamer = WiFiRoamer()
        self.svc_ctrl = ServiceController()

    def print_banner(self):
        print(f"{C_CYAN}{C_BOLD}")
        print("  ╔══════════════════════════════════════════════════════════════════╗")
        print("  ║                       ⚙️ System v1.1                             ║")
        print("  ║             Automatic Login, Quota Rotator & Roaming             ║")
        print("  ╚══════════════════════════════════════════════════════════════════╝")
        print(f"{C_RESET}", end="")

    def print_friendly_menu(self):
        """Displays a clean, non-overwhelming main menu with live status."""
        telemetry = self.detector.get_telemetry()
        stats = self.acc_mgr.get_stats()
        curr_acc = self.acc_mgr.get_current_account()

        net_status = telemetry["status"]
        if net_status == "ONLINE":
            badge = f"{C_GREEN}{C_BOLD}🟢 ONLINE ({telemetry['latency_ms']}ms){C_RESET}"
        elif net_status == "CAPTIVE_PORTAL":
            badge = f"{C_YELLOW}{C_BOLD}🟡 LOGIN REQUIRED{C_RESET}"
        else:
            badge = f"{C_RED}{C_BOLD}🔴 OFFLINE{C_RESET}"

        wifi_name = telemetry["ssid"] or "Disconnected"
        wifi_sig = f"({telemetry['signal']})" if telemetry["signal"] else ""
        active_name = curr_acc.get("name", "None") if curr_acc else "None"
        active_user = curr_acc.get("username", "") if curr_acc else ""

        print(f"\n{C_CYAN}──────────────────────────────────────────────────────────────────────{C_RESET}")
        print(f"  {C_BOLD}Status:{C_RESET} {badge}  │  {C_BOLD}Wi-Fi:{C_RESET} {C_WHITE}{wifi_name} {wifi_sig}{C_RESET}")
        print(f"  {C_BOLD}Active:{C_RESET} {C_CYAN}{active_name}{C_RESET} ({active_user})  │  {C_BOLD}Pool:{C_RESET} {C_GREEN}{stats['available']} Available{C_RESET} / {stats['total']}")
        print(f"{C_CYAN}──────────────────────────────────────────────────────────────────────{C_RESET}")
        print(f"  {C_GREEN}{C_BOLD}[1]{C_RESET} ⚡ {C_BOLD}Connect / Check Status{C_RESET}      (Test internet & auto-login)")
        print(f"  {C_GREEN}{C_BOLD}[2]{C_RESET} 🎲 {C_BOLD}Switch to Random Account{C_RESET}    (Rotate to a random ID from pool)")
        print(f"  {C_GREEN}{C_BOLD}[3]{C_RESET} 👥 {C_BOLD}View Accounts Pool{C_RESET}          (See list of all student IDs)")
        print(f"  {C_GREEN}{C_BOLD}[4]{C_RESET} 📶 {C_BOLD}Best Wi-Fi (Auto-Roam){C_RESET}      (Jump to strongest router in hostel)")
        print(f"  {C_GREEN}{C_BOLD}[5]{C_RESET} 🛠️ {C_BOLD}Fix Wi-Fi / Reset Network{C_RESET}   (Clears stuck IP / restores DHCP)")
        print(f"  {C_YELLOW}{C_BOLD}[6]{C_RESET} ⚙️ {C_BOLD}More Tools{C_RESET}                  (Add IDs, Export ZIP, Dashboard)")
        print(f"  {C_GRAY}{C_BOLD}[0]{C_RESET} ❌ {C_BOLD}Exit{C_RESET}")
        print(f"{C_CYAN}──────────────────────────────────────────────────────────────────────{C_RESET}")

    def print_more_tools_menu(self):
        """Displays advanced tools sub-menu."""
        print(f"\n{C_YELLOW}{C_BOLD}======================================================================{C_RESET}")
        print(f"                        ⚙️ {C_BOLD}Advanced Tools{C_RESET}")
        print(f"{C_YELLOW}{C_BOLD}======================================================================{C_RESET}")
        print(f"  {C_YELLOW}[1]{C_RESET} ➕ Add New Student ID")
        print(f"  {C_YELLOW}[2]{C_RESET} ➖ Remove a Student ID")
        print(f"  {C_YELLOW}[3]{C_RESET} ♻️ Reset Daily Quotas (Reset all exhausted IDs to Available)")
        print(f"  {C_YELLOW}[4]{C_RESET} 📊 Open Live Visual Dashboard")
        print(f"  {C_YELLOW}[5]{C_RESET} 🚀 Start Background Service (System Tray)")
        print(f"  {C_YELLOW}[6]{C_RESET} 🛑 Stop Background Service")
        print(f"  {C_YELLOW}[7]{C_RESET} 📦 Export Standalone ZIP (.zip)")
        print(f"  {C_YELLOW}[8]{C_RESET} 🔄 Cloud Sync & Check Updates")
        print(f"  {C_GRAY}[0]{C_RESET} ⬅️ Back to Main Menu")
        print(f"{C_YELLOW}{C_BOLD}======================================================================{C_RESET}")

    def cmd_status(self):
        """Displays full network telemetry, account pool, and background service status."""
        print(f"\n{C_CYAN}{C_BOLD}[ SYSTEM & NETWORK TELEMETRY ]{C_RESET}")
        telemetry = self.detector.get_telemetry()
        
        status_str = telemetry["status"]
        if status_str == "ONLINE":
            status_badge = f"{C_GREEN}{C_BOLD}ONLINE ({telemetry['latency_ms']}ms){C_RESET}"
        elif status_str == "CAPTIVE_PORTAL":
            status_badge = f"{C_YELLOW}{C_BOLD}CAPTIVE PORTAL (Login Required){C_RESET}"
        else:
            status_badge = f"{C_RED}{C_BOLD}OFFLINE (No Network / Interrupted){C_RESET}"

        print(f"  * Connectivity:    {status_badge}")
        print(f"  * Wi-Fi SSID:      {C_WHITE}{telemetry['ssid'] or 'Ethernet / Disconnected'}{C_RESET} (Signal: {telemetry['signal'] or 'N/A'})")
        print(f"  * Local IPv4:      {C_WHITE}{telemetry['local_ip'] or 'N/A'}{C_RESET} [{'DHCP' if telemetry['is_dhcp'] else 'Static IP'}]")
        print(f"  * Default Gateway: {C_WHITE}{telemetry['gateway_ip'] or 'N/A'}{C_RESET}")

        # Account Pool
        stats = self.acc_mgr.get_stats()
        curr_acc = self.acc_mgr.get_current_account()
        print(f"\n{C_CYAN}{C_BOLD}[ ACCOUNT POOL TELEMETRY ]{C_RESET}")
        print(f"  * Active User:     {C_GREEN}{C_BOLD}{stats['current_user']}{C_RESET} (Index #{stats['current_index']} of {stats['total']})")
        if curr_acc:
            print(f"  * Student Name:    {curr_acc.get('name', 'N/A')} (SC: {curr_acc.get('sc', 'N/A')})")
        print(f"  * Pool Status:     {C_GREEN}{stats['available']} Available{C_RESET} | {C_RED}{stats['exhausted']} Exhausted{C_RESET} | {C_YELLOW}{stats['invalid']} Invalid{C_RESET} (Total: {stats['total']})")

        # Service
        svc_stat = self.svc_ctrl.get_status()
        svc_badge = f"{C_GREEN}{svc_stat['summary']}{C_RESET}" if svc_stat["running"] else f"{C_GRAY}Stopped{C_RESET}"
        print(f"\n{C_CYAN}{C_BOLD}[ BACKGROUND SERVICE ]{C_RESET}")
        print(f"  * Daemon Status:   {svc_badge} [{svc_stat['mode']}]")
        print("")

    def cmd_accounts(self):
        """Displays tabulated view of all accounts in accounts.json."""
        self.acc_mgr.load()
        accounts = self.acc_mgr.accounts
        stats = self.acc_mgr.get_stats()

        print(f"\n{C_CYAN}{C_BOLD}=== MCS ACCOUNT POOL ({len(accounts)} ACCOUNTS) ==={C_RESET}")
        header = f"{'ID':>3} | {'SC':<5} | {'Student Name':<22} | {'Username':<22} | {'Status':<12} | {'Details'}"
        print(f"{C_BOLD}{header}{C_RESET}")
        print("-" * len(header) + "-" * 20)

        for a in accounts:
            a_id = a.get("id", 0)
            sc = a.get("sc", "")
            name = a.get("name", "")[:22]
            user = a.get("username", "")[:22]
            stat = a.get("status", "available")

            stat_color = C_WHITE
            if stat == "in_use":
                stat_color = f"{C_GREEN}{C_BOLD}"
                stat_text = "IN USE *"
            elif stat == "available":
                stat_color = C_GREEN
                stat_text = "AVAILABLE"
            elif stat == "exhausted":
                stat_color = C_RED
                stat_text = "EXHAUSTED"
            elif stat == "invalid":
                stat_color = C_YELLOW
                stat_text = "INVALID"
            else:
                stat_text = stat.upper()

            details = a.get("error_reason") or a.get("last_used") or ""
            if "T" in details and len(details) > 19:
                details = details[:19].replace("T", " ")

            print(f"{a_id:>3} | {sc:<5} | {name:<22} | {user:<22} | {stat_color}{stat_text:<12}{C_RESET} | {C_GRAY}{details}{C_RESET}")

        print("-" * len(header) + "-" * 20)
        print(f"Summary: {C_GREEN}{stats['available']} Available{C_RESET}, {C_RED}{stats['exhausted']} Exhausted{C_RESET}, {C_YELLOW}{stats['invalid']} Invalid{C_RESET}\n")

    def cmd_login(self, target_id=None):
        """Authenticates with captive portal using current or specified account ID."""
        if target_id is not None:
            acc = self.acc_mgr.get_account_by_id(target_id)
            if not acc:
                print(f"{C_RED}[ERROR] Account ID #{target_id} not found in pool.{C_RESET}")
                return
            self.acc_mgr.set_current_account_by_id(target_id)
            print(f"{C_CYAN}[INFO] Switched to account ID #{acc['id']}: {acc['username']} ({acc['name']}){C_RESET}")
        else:
            acc = self.acc_mgr.get_current_account()

        if not acc:
            print(f"{C_RED}[ERROR] No available accounts in pool. Run 'reset' to recycle.{C_RESET}")
            return

        print(f"{C_YELLOW}[...] Probing network connectivity...{C_RESET}")
        conn_stat, data = self.detector.check_connection()

        if conn_stat == "ONLINE":
            print(f"{C_GREEN}{C_BOLD}[ONLINE] Internet is already active and authenticated!{C_RESET}")
            return

        if conn_stat == "OFFLINE":
            print(f"{C_RED}[OFFLINE] No connection to network or gateway. Cannot reach captive portal.{C_RESET}")
            return

        print(f"{C_YELLOW}[!] Captive portal detected! Submitting credentials for {acc['username']}...{C_RESET}")
        portal_url = data.get("portal_url", "")
        html = data.get("html", "")

        ok, code, msg = self.client.login(portal_url, html, acc["username"], acc["password"])

        if ok:
            print(f"{C_GREEN}{C_BOLD}[SUCCESS] Logged in successfully as {acc['username']}! Internet unlocked.{C_RESET}")
            acc["status"] = "in_use"
            self.acc_mgr.save()
        else:
            if code == "QUOTA_EXHAUSTED":
                print(f"{C_RED}[QUOTA LIMIT] {msg}. Marking #{acc['id']} exhausted.{C_RESET}")
                self.acc_mgr.mark_current_exhausted(msg)
            elif code == "INVALID_CREDENTIALS":
                print(f"{C_YELLOW}[AUTH REJECTED] {msg}. Marking #{acc['id']} invalid.{C_RESET}")
                self.acc_mgr.mark_current_invalid(msg)
            else:
                print(f"{C_RED}[LOGIN FAILED] {msg}{C_RESET}")

    def cmd_switch(self):
        """Switches to the next available account, clears active Fortinet session, and authenticates."""
        next_acc = self.acc_mgr.get_next_account()
        if not next_acc:
            print(f"{C_RED}[WARNING] No available accounts remain! All accounts are exhausted or invalid.{C_RESET}")
            print(f"Use {C_YELLOW}reset{C_RESET} to recycle all accounts back to available.")
            return

        print(f"{C_GREEN}{C_BOLD}[OK] Switched to Account #{next_acc['id']}: {next_acc['username']} ({next_acc['name']}){C_RESET}")

        # Execute logout to clear any locked FortiGate session
        print(f"{C_YELLOW}[...] De-authenticating previous Fortinet session (logout)...{C_RESET}")
        gw_ip = self.detector.get_telemetry().get("gateway_ip")
        self.client.logout(gateway_ip=gw_ip)

        # Check connection or fetch portal directly from gateway
        print(f"{C_YELLOW}[...] Probing captive portal for authentication...{C_RESET}")
        portal_url = None
        html = None

        c_stat, data = self.detector.check_connection()
        if c_stat == "CAPTIVE_PORTAL" and (data.get("portal_url") or data.get("html")):
            portal_url = data.get("portal_url", "")
            html = data.get("html", "")

        if not portal_url or not html:
            # When OFFLINE or portal HTML not received via probe, fetch directly from gateway
            gw_candidates = []
            if gw_ip:
                gw_candidates.append(f"https://{gw_ip}:1003/")
            gw_candidates.append("https://172.23.200.254:1003/")
            if portal_url and not is_probe_url(portal_url):
                gw_candidates.insert(0, portal_url)

            unique_gw_candidates = list(dict.fromkeys(gw_candidates))
            for gw_url in unique_gw_candidates:
                try:
                    resp = self.client.session.get(gw_url, timeout=2, allow_redirects=True, verify=False)
                    if resp.status_code in [200, 301, 302, 303, 307] and resp.text:
                        redir = extract_redirect_from_html(resp.text, resp.url or gw_url)
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
                                portal_url = redir or resp.url or gw_url
                                html = resp.text
                            break
                except Exception:
                    pass

        if not portal_url or is_probe_url(portal_url):
            portal_url = f"https://{gw_ip}:1003/" if gw_ip else "https://172.23.200.254:1003/"
            html = html or ""

        print(f"{C_YELLOW}[!] Submitting credentials for {next_acc['username']}...{C_RESET}")
        ok, code, msg = self.client.login(
            portal_url,
            html,
            next_acc["username"],
            next_acc["password"]
        )
        if ok:
            print(f"{C_GREEN}{C_BOLD}[SUCCESS] Logged in successfully as {next_acc['username']}! Internet unlocked.{C_RESET}")
            next_acc["status"] = "in_use"
            self.acc_mgr.save()
        else:
            if code == "QUOTA_EXHAUSTED":
                print(f"{C_RED}[QUOTA LIMIT] {msg}. Marking #{next_acc['id']} exhausted.{C_RESET}")
                self.acc_mgr.mark_current_exhausted(msg)
            elif code == "INVALID_CREDENTIALS":
                print(f"{C_YELLOW}[AUTH REJECTED] {msg}. Marking #{next_acc['id']} invalid.{C_RESET}")
                self.acc_mgr.mark_current_invalid(msg)
            else:
                print(f"{C_RED}[LOGIN FAILED] {msg}{C_RESET}")

    def cmd_add_account(self, args=None):
        """Adds a new student account to accounts.json (CLI arguments or interactive prompts)."""
        args = args or []
        if len(args) >= 1:
            username = args[0].strip()
            password = args[1].strip() if len(args) > 1 else "password123"
            name = args[2].strip() if len(args) > 2 else ""
            sc = args[3].strip() if len(args) > 3 else ""
        else:
            print(f"\n{C_CYAN}{C_BOLD}=== ADD NEW ACCOUNT ==={C_RESET}")
            username = input("Enter Username: ").strip()
            if not username:
                print(f"{C_RED}[ABORTED] Username cannot be empty.{C_RESET}")
                return

            password = input("Enter Password [default: password123]: ").strip()
            if not password:
                password = "password123"

            name = input("Enter Full Name (optional): ").strip()
            sc = input("Enter Identifier / ID (optional): ").strip()

        try:
            acc = self.acc_mgr.add_account(username, password, name=name, sc=sc)
            print(f"{C_GREEN}{C_BOLD}[SUCCESS] Account #{acc['id']} ({acc['username']}) added successfully!{C_RESET}\n")
        except Exception as e:
            print(f"{C_RED}[ERROR] Failed to add account: {e}{C_RESET}\n")

    def cmd_remove_account(self, target_id=None):
        """Removes a student account from accounts.json by ID."""
        if target_id is None:
            val = input("Enter Account ID to remove (or 'c' to cancel): ").strip()
            if not val or val.lower() == "c":
                print(f"{C_YELLOW}[CANCELLED] Account removal aborted.{C_RESET}")
                return
            try:
                target_id = int(val)
            except ValueError:
                print(f"{C_RED}[ERROR] Invalid numeric ID: {val}{C_RESET}")
                return

        acc = self.acc_mgr.get_account_by_id(target_id)
        if not acc:
            print(f"{C_RED}[ERROR] Account ID #{target_id} not found in pool.{C_RESET}")
            return

        ok = self.acc_mgr.remove_account(target_id)
        if ok:
            print(f"{C_GREEN}{C_BOLD}[SUCCESS] Account #{target_id} ({acc['username']}) removed from pool!{C_RESET}")
        else:
            print(f"{C_RED}[ERROR] Failed to remove account #{target_id}.{C_RESET}")

    def cmd_reset(self):
        """Resets all accounts in the pool to Available."""
        self.acc_mgr.reset_all_accounts()
        stats = self.acc_mgr.get_stats()
        print(f"{C_GREEN}{C_BOLD}[SUCCESS] All {stats['total']} accounts have been reset to AVAILABLE!{C_RESET}")

    def cmd_roam(self):
        """Scans for nearby Wi-Fi access points and roams to the strongest one."""
        print(f"{C_YELLOW}[...] Scanning 2.4GHz & 5GHz Wi-Fi access points...{C_RESET}")
        nets = self.wifi_roamer.scan_networks()
        mcs_nets = [n for n in nets if n["is_mcs"]]

        print(f"\n{C_CYAN}{C_BOLD}Detected Access Points:{C_RESET}")
        if not mcs_nets:
            print(f"  {C_GRAY}(No target networks detected in range){C_RESET}")
        else:
            for n in mcs_nets:
                sig = n["signal"]
                sig_col = C_GREEN if sig >= 60 else (C_YELLOW if sig >= 35 else C_RED)
                print(f"  * SSID: {C_WHITE}{n['ssid']:<24}{C_RESET} Signal: {sig_col}{sig}%{C_RESET} [{n['auth']}]")

        print(f"\n{C_YELLOW}[...] Evaluating auto-roam...{C_RESET}")
        curr_ssid = self.detector.get_current_wifi_ssid()
        roamed, msg = self.wifi_roamer.auto_roam(current_ssid=curr_ssid)
        if roamed:
            print(f"{C_GREEN}{C_BOLD}[ROAMED] {msg}{C_RESET}")
        else:
            print(f"{C_CYAN}[OPTIMAL] {msg}{C_RESET}")

    def cmd_fix_ip(self):
        """Detects DHCP failure and self-heals by assigning an available static IP."""
        print(f"{C_YELLOW}[...] Checking IP address & gateway health...{C_RESET}")
        healed, msg = self.ip_cycler.auto_heal_ip()
        if healed:
            print(f"{C_GREEN}{C_BOLD}[HEALED] {msg}{C_RESET}")
        else:
            print(f"{C_CYAN}[INFO] {msg}{C_RESET}")

    def cmd_dhcp(self):
        """Restores Wi-Fi interface back to automatic DHCP."""
        print(f"{C_YELLOW}[...] Restoring interface to automatic DHCP...{C_RESET}")
        ok = self.ip_cycler.revert_to_dhcp()
        if ok:
            print(f"{C_GREEN}{C_BOLD}[SUCCESS] Wi-Fi adapter reverted to DHCP mode.{C_RESET}")
        else:
            print(f"{C_RED}[ERROR] Failed to set DHCP mode. Try running CMD as Administrator.{C_RESET}")

    def cmd_dashboard(self):
        """Launches the real-time visual monitor."""
        from dashboard import run_dashboard
        print(f"{C_CYAN}Starting Live Visual Dashboard... (Press 'q' in dashboard to return){C_RESET}")
        time.sleep(0.5)
        try:
            run_dashboard()
        except KeyboardInterrupt:
            pass
        print(f"{C_CYAN}Returned to Command Centre.{C_RESET}\n")

    def cmd_start_bg(self):
        """Starts the background tray service."""
        print(f"{C_YELLOW}[...] Starting background daemon service...{C_RESET}")
        ok, msg = self.svc_ctrl.start()
        if ok:
            print(f"{C_GREEN}{C_BOLD}[OK] {msg}{C_RESET}")
        else:
            print(f"{C_YELLOW}[INFO] {msg}{C_RESET}")

    def cmd_stop_bg(self):
        """Stops the background tray service."""
        print(f"{C_YELLOW}[...] Stopping background daemon service...{C_RESET}")
        ok, msg = self.svc_ctrl.stop()
        if ok:
            print(f"{C_GREEN}{C_BOLD}[OK] {msg}{C_RESET}")
        else:
            print(f"{C_YELLOW}[INFO] {msg}{C_RESET}")

    def cmd_restart_bg(self):
        """Restarts the background tray service."""
        print(f"{C_YELLOW}[...] Restarting background daemon service...{C_RESET}")
        ok, msg = self.svc_ctrl.restart()
        if ok:
            print(f"{C_GREEN}{C_BOLD}[OK] {msg}{C_RESET}")
        else:
            print(f"{C_RED}[ERROR] {msg}{C_RESET}")

    def cmd_export(self):
        """Runs the standalone packaging builder."""
        print(f"{C_CYAN}{C_BOLD}=== LAUNCHING STANDALONE EXPORT BUILDER ==={C_RESET}")
        import build_package
        try:
            build_package.build_distribution()
        except Exception as e:
            print(f"{C_RED}[ERROR] Packaging failed: {e}{C_RESET}")

    def cmd_sync(self):
        """Checks for software updates and syncs encrypted accounts from GitHub."""
        from updater import check_for_updates, sync_accounts_from_cloud, CURRENT_VERSION, DEFAULT_REPO
        from security import get_local_passkey
        print(f"\n{C_CYAN}[...] Connecting to GitHub ({DEFAULT_REPO})...{C_RESET}")

        # 1. Check software update
        has_update, remote_ver, info = check_for_updates()
        if has_update:
            print(f"{C_YELLOW}{C_BOLD}[UPDATE AVAILABLE] A newer version (v{remote_ver}) is on GitHub!{C_RESET}")
            if info.get("changelog"):
                print(f"  • Changes: {info['changelog']}")
            if info.get("download_url"):
                print(f"  • Download: {info['download_url']}")
        else:
            print(f"{C_GREEN}[OK] Software is up to date (v{CURRENT_VERSION}).{C_RESET}")

        # 2. Sync encrypted accounts
        passkey = get_local_passkey()
        if not passkey:
            passkey = input(f"{C_YELLOW}Enter hostel passkey to sync accounts: {C_RESET}").strip()

        if passkey:
            ok, msg, added = sync_accounts_from_cloud(passkey)
            if ok:
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
                self.acc_mgr.load()
            else:
                print(f"{C_RED}[!] Cloud sync: {msg}{C_RESET}")

    def print_help(self):
        print(f"\n{C_CYAN}{C_BOLD}COMMAND CENTRE REFERENCE:{C_RESET}")
        commands = [
            ("status", "1", "Show full network, account pool, and service status"),
            ("login [id]", "2", "Authenticate captive portal (active account or specific ID)"),
            ("switch", "3", "Advance to next available account & log in"),
            ("accounts", "4", "Tabulate all 29 accounts with status and quotas"),
            ("add", "5", "Add a new student account to pool (interactive or 'add user pass')"),
            ("remove [id]", "rm", "Remove student account from pool by ID"),
            ("reset", "6", "Reset all exhausted accounts back to Available"),
            ("roam", "7", "Scan nearby MCS Wi-Fi APs and connect to strongest signal"),
            ("fix-ip", "8", "Auto-heal DHCP exhaustion / Assign static IP"),
            ("dhcp", "9", "Revert Wi-Fi adapter to automatic DHCP"),
            ("dashboard", "10", "Launch full-screen real-time visual monitor"),
            ("start-bg", "11", "Start background system tray service"),
            ("stop-bg", "12", "Stop background system tray service"),
            ("restart-bg", "13", "Restart background system tray service"),
            ("export", "14", "Build standalone exportable portable package (.zip)"),
            ("help", "h", "Show this command reference"),
            ("exit", "15, q", "Exit Command Centre"),
        ]
        for cmd, num, desc in commands:
            print(f"  {C_GREEN}{cmd:<14}{C_RESET} {C_GRAY}[{num:<5}]{C_RESET} : {desc}")
        print("")

    def dispatch(self, cmd_line):
        """Parses and executes a single command string."""
        parts = shlex.split(cmd_line.strip())
        if not parts:
            return True

        action = parts[0].lower()
        args = parts[1:]

        # Map numbers to command strings
        num_map = {
            "1": "status",
            "2": "login",
            "3": "switch",
            "4": "accounts",
            "5": "add",
            "6": "reset",
            "7": "roam",
            "8": "fix-ip",
            "9": "dhcp",
            "10": "dashboard",
            "11": "start-bg",
            "12": "stop-bg",
            "13": "restart-bg",
            "14": "export",
            "15": "exit"
        }
        if action in num_map:
            action = num_map[action]

        if action in ["exit", "quit", "q"]:
            print(f"\n{C_CYAN}Exiting MCS Command Centre. Goodbye!{C_RESET}\n")
            return False

        elif action in ["status", "stat", "st"]:
            self.cmd_status()

        elif action in ["accounts", "acc", "list"]:
            self.cmd_accounts()

        elif action in ["login", "l"]:
            target_id = int(args[0]) if args and args[0].isdigit() else None
            self.cmd_login(target_id)

        elif action in ["switch", "next", "s"]:
            self.cmd_switch()

        elif action in ["add", "new"]:
            self.cmd_add_account(args)

        elif action in ["remove", "rm", "del", "delete"]:
            target_id = int(args[0]) if args and args[0].isdigit() else None
            self.cmd_remove_account(target_id)

        elif action in ["reset", "r"]:
            self.cmd_reset()

        elif action in ["roam", "wifi", "w"]:
            self.cmd_roam()

        elif action in ["fix-ip", "fixip", "ip", "heal"]:
            self.cmd_fix_ip()

        elif action in ["dhcp", "reset-ip"]:
            self.cmd_dhcp()

        elif action in ["dashboard", "dash", "d", "monitor"]:
            self.cmd_dashboard()

        elif action in ["start-bg", "start"]:
            self.cmd_start_bg()

        elif action in ["stop-bg", "stop"]:
            self.cmd_stop_bg()

        elif action in ["restart-bg", "restart"]:
            self.cmd_restart_bg()

        elif action in ["export", "build", "package", "pack"]:
            self.cmd_export()

        elif action in ["sync", "update", "cloud"]:
            self.cmd_sync()

        elif action in ["help", "?", "h"]:
            self.print_help()

        else:
            print(f"{C_RED}Unknown command: '{action}'. Type 'help' or enter a menu number.{C_RESET}")

        return True

    def run_interactive(self):
        """Runs the clean, user-friendly interactive Command Centre."""
        self.print_banner()
        menu_mode = "main"

        while True:
            try:
                if menu_mode == "main":
                    self.print_friendly_menu()
                    prompt_text = f"{C_CYAN}{C_BOLD}Choose an option (1-6, 0 to exit): {C_RESET}"
                else:
                    self.print_more_tools_menu()
                    prompt_text = f"{C_YELLOW}{C_BOLD}Choose a tool (1-8, 0 to go back): {C_RESET}"

                line = input(prompt_text).strip()
                if not line:
                    continue

                low = line.lower()

                # Handle navigation between main and more menus
                if menu_mode == "main":
                    if low in ["0", "exit", "quit", "q"]:
                        print(f"\n{C_CYAN}Exiting AutoLogin Assistant. Goodbye!{C_RESET}\n")
                        break
                    elif low in ["6", "more", "tools", "advanced"]:
                        menu_mode = "more"
                        continue
                    elif low in ["1", "status", "check"]:
                        self.cmd_status()
                    elif low in ["2", "switch", "next"]:
                        self.cmd_switch()
                    elif low in ["3", "accounts", "list"]:
                        self.cmd_accounts()
                    elif low in ["4", "roam", "wifi"]:
                        self.cmd_roam()
                    elif low in ["5", "fix", "fix-ip", "dhcp"]:
                        print(f"\n{C_CYAN}[...] Refreshing Wi-Fi adapter to clean DHCP...{C_RESET}")
                        self.cmd_dhcp()
                        self.cmd_status()
                    else:
                        # Allow any standard command string (e.g. login 8, remove 4, export, etc.)
                        should_cont = self.dispatch(line)
                        if not should_cont:
                            break

                elif menu_mode == "more":
                    if low in ["0", "back", "b", "menu", "main"]:
                        menu_mode = "main"
                        continue
                    elif low in ["exit", "quit", "q"]:
                        print(f"\n{C_CYAN}Exiting AutoLogin Assistant. Goodbye!{C_RESET}\n")
                        break
                    elif low == "1":
                        self.cmd_add_account([])
                    elif low == "2":
                        tid = input(f"{C_YELLOW}Enter Account ID to remove: {C_RESET}").strip()
                        if tid.isdigit():
                            self.cmd_remove_account(int(tid))
                        else:
                            print(f"{C_RED}Invalid ID.{C_RESET}")
                    elif low == "3":
                        self.cmd_reset()
                    elif low == "4":
                        self.cmd_dashboard()
                    elif low == "5":
                        self.cmd_start_bg()
                    elif low == "6":
                        self.cmd_stop_bg()
                    elif low == "7":
                        self.cmd_export()
                    elif low in ["8", "sync", "update"]:
                        self.cmd_sync()
                    else:
                        should_cont = self.dispatch(line)
                        if not should_cont:
                            break

            except (KeyboardInterrupt, EOFError):
                print(f"\n{C_CYAN}Exiting AutoLogin Assistant. Goodbye!{C_RESET}\n")
                break
            except Exception as e:
                print(f"{C_RED}[ERROR] {e}{C_RESET}")

def main():
    cc = CommandCenter()
    if len(sys.argv) > 1:
        # Non-interactive CLI command execution
        cmd_string = " ".join(sys.argv[1:])
        cc.dispatch(cmd_string)
    else:
        # Interactive REPL mode
        cc.run_interactive()

if __name__ == "__main__":
    main()
