import os
import sys
import time
import msvcrt
from datetime import datetime

# Configure UTF-8 stdout if possible, or fallback safely
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Enable ANSI escape sequences in Windows console
os.system("")

from account_manager import AccountManager
from network_detector import NetworkDetector
from fortinet_client import FortinetClient
from ip_cycler import IPCycler
from wifi_roamer import WiFiRoamer

def get_app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

LOG_FILE = os.path.abspath(os.path.join(get_app_dir(), "mcs_login.log"))

# ANSI Color Codes
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_BLUE = "\033[94m"
C_WHITE = "\033[97m"
C_BG_BLUE = "\033[44m"
C_BG_GREEN = "\033[42m"
C_BG_RED = "\033[41m"

def clear_screen():
    print("\033[H\033[J", end="")

def get_recent_logs(num_lines=6):
    """Reads the last few entries from mcs_login.log."""
    if not os.path.exists(LOG_FILE):
        return ["(No log entries yet)"]
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            return [line.strip() for line in lines[-num_lines:]] if lines else ["(Empty log file)"]
    except Exception:
        return ["(Could not read log file)"]

def draw_progress_bar(val, total, width=28):
    if total <= 0:
        return "[" + " " * width + "]"
    ratio = min(max(val / total, 0.0), 1.0)
    filled = int(ratio * width)
    # Use ASCII characters to ensure 100% compatibility across all Windows code pages
    bar = "=" * filled + "-" * (width - filled)
    pct = int(ratio * 100)
    color = C_GREEN if pct > 40 else (C_YELLOW if pct > 15 else C_RED)
    return f"{color}[{bar}] {pct}%{C_RESET}"

def run_dashboard():
    acc_mgr = AccountManager()
    detector = NetworkDetector()
    client = FortinetClient()
    ip_cycler = IPCycler()
    wifi_roamer = WiFiRoamer()

    status_message = "Ready"
    msg_color = C_GREEN

    # Track how often we do slow Wi-Fi scans
    last_scan_time = 0
    cached_aps = []

    try:
        while True:
            # 1. Gather Telemetry
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            telemetry = detector.get_telemetry()
            stats = acc_mgr.get_stats()
            curr_acc = acc_mgr.get_current_account()

            # Refresh APs every 8 seconds
            if time.time() - last_scan_time > 8:
                all_nets = wifi_roamer.scan_networks()
                cached_aps = [n for n in all_nets if n["is_mcs"]][:4]
                last_scan_time = time.time()

            # Determine State Badges
            net_status = telemetry["status"]
            if net_status == "ONLINE":
                badge = f"{C_BG_GREEN}{C_WHITE}{C_BOLD} ONLINE {C_RESET}"
            elif net_status == "CAPTIVE_PORTAL":
                badge = f"{C_YELLOW}{C_BOLD}[CAPTIVE PORTAL]{C_RESET}"
            else:
                badge = f"{C_BG_RED}{C_WHITE}{C_BOLD} OFFLINE {C_RESET}"

            clear_screen()
            print(f"{C_CYAN}{C_BOLD}╔══════════════════════════════════════════════════════════════════════════════════════╗{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}║                       AUTOLOGIN & QUOTA ROTATOR DASHBOARD                            ║{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}╚══════════════════════════════════════════════════════════════════════════════════════╝{C_RESET}")
            print(f" {C_DIM}Time:{C_RESET} {now_str}  │  {C_DIM}Internet:{C_RESET} {badge}  │  {C_DIM}Latency:{C_RESET} {telemetry['latency_ms'] or '---'} ms")
            print(f"{C_DIM}────────────────────────────────────────────────────────────────────────────────────────{C_RESET}")

            # Active Account Card
            print(f"{C_BOLD}{C_WHITE}► ACTIVE ACCOUNT{C_RESET}")
            if curr_acc:
                print(f"  • {C_BOLD}Name:{C_RESET}       {C_CYAN}{curr_acc.get('name', 'N/A')}{C_RESET}")
                print(f"  • {C_BOLD}Username:{C_RESET}   {C_GREEN}{curr_acc.get('username', 'N/A')}{C_RESET}  (SC: {curr_acc.get('sc', 'N/A')})")
                print(f"  • {C_BOLD}Pool ID:{C_RESET}    #{curr_acc.get('id', 'N/A')} of {stats['total']}")
                print(f"  • {C_BOLD}Status:{C_RESET}     {C_YELLOW}{curr_acc.get('status', 'in_use').upper()}{C_RESET}  │ Last Used: {curr_acc.get('last_used', 'Active now')[:19]}")
            else:
                print(f"  {C_RED}{C_BOLD}No active account! All 29 accounts exhausted.{C_RESET}")

            print(f"{C_DIM}────────────────────────────────────────────────────────────────────────────────────────{C_RESET}")

            # Pool Visualizer
            print(f"{C_BOLD}{C_WHITE}► CREDENTIALS POOL ({stats['total']} Accounts){C_RESET}")
            p_bar = draw_progress_bar(stats['available'], stats['total'])
            print(f"  {p_bar}  ({stats['available']} Available  │  {stats['exhausted']} Exhausted  │  {stats['invalid']} Invalid)")

            print(f"{C_DIM}────────────────────────────────────────────────────────────────────────────────────────{C_RESET}")

            # Network Telemetry
            print(f"{C_BOLD}{C_WHITE}► NETWORK TELEMETRY{C_RESET}")
            ssid_display = telemetry['ssid'] or "Disconnected"
            sig_display = telemetry['signal'] or "---"
            ip_display = telemetry['local_ip'] or "---"
            gw_display = telemetry['gateway_ip'] or "---"
            dhcp_display = "DHCP (Auto)" if telemetry['is_dhcp'] else "STATIC (Manual)"

            print(f"  • {C_BOLD}Wi-Fi SSID:{C_RESET}  {C_CYAN}{ssid_display}{C_RESET} ({sig_display})  │  {C_BOLD}Config:{C_RESET} {dhcp_display}")
            print(f"  • {C_BOLD}Local IPv4:{C_RESET}  {ip_display}  │  {C_BOLD}Default Gateway:{C_RESET} {gw_display}")

            # Nearby MCS APs
            if cached_aps:
                ap_strs = [f"{a['ssid']} ({a['signal']}%)" for a in cached_aps]
                print(f"  • {C_BOLD}Nearby APs:{C_RESET}  " + "  │  ".join(ap_strs))

            print(f"{C_DIM}────────────────────────────────────────────────────────────────────────────────────────{C_RESET}")

            # Live Log Feed
            print(f"{C_BOLD}{C_WHITE}► RECENT ACTIVITY LOG{C_RESET}")
            logs = get_recent_logs(5)
            for l in logs:
                # Colorize log lines
                if "[ERROR]" in l:
                    print(f"  {C_RED}{l}{C_RESET}")
                elif "[WARNING]" in l:
                    print(f"  {C_YELLOW}{l}{C_RESET}")
                elif "Connected" in l or "ONLINE" in l or "success" in l.lower():
                    print(f"  {C_GREEN}{l}{C_RESET}")
                else:
                    print(f"  {C_DIM}{l}{C_RESET}")

            print(f"{C_DIM}════════════════════════════════════════════════════════════════════════════════════════{C_RESET}")

            # Last action status
            if status_message:
                print(f" Status: {msg_color}{status_message}{C_RESET}")

            # Hotkeys Prompt
            print(f" {C_BOLD}HOTKEYS:{C_RESET} [{C_CYAN}S{C_RESET}] Switch ID  │ [{C_CYAN}R{C_RESET}] Reset Pool  │ [{C_CYAN}C{C_RESET}] Check Net  │ [{C_CYAN}W{C_RESET}] Roam Wi-Fi  │ [{C_CYAN}I{C_RESET}] Fix IP  │ [{C_CYAN}Q{C_RESET}] Exit")

            # Non-blocking key check (wait up to 1 second)
            t_start = time.time()
            while time.time() - t_start < 1.0:
                if msvcrt.kbhit():
                    key = msvcrt.getch().decode("utf-8", errors="ignore").lower()
                    if key == "q":
                        clear_screen()
                        print(f"\n{C_CYAN}Exiting MCS Dashboard. Background services remain active in system tray.{C_RESET}\n")
                        return

                    elif key == "s":
                        status_message = "Switching to next account in pool..."
                        msg_color = C_YELLOW
                        next_a = acc_mgr.get_next_account()
                        if next_a:
                            status_message = f"Switched to ID #{next_a['id']}: {next_a['username']}"
                            msg_color = C_GREEN
                            # Trigger login immediately if in captive portal
                            c_stat, data = detector.check_connection()
                            if c_stat == "CAPTIVE_PORTAL":
                                ok, _, msg = client.login(data.get("portal_url", ""), data.get("html", ""), next_a["username"], next_a["password"])
                                status_message = f"Login: {msg}"
                        break

                    elif key == "r":
                        acc_mgr.reset_all_accounts()
                        status_message = "All 29 accounts reset to Available!"
                        msg_color = C_GREEN
                        break

                    elif key == "c":
                        status_message = "Probing connection..."
                        msg_color = C_YELLOW
                        stat, _ = detector.check_connection()
                        status_message = f"Connection probe result: {stat}"
                        msg_color = C_GREEN if stat == "ONLINE" else C_RED
                        break

                    elif key == "w":
                        status_message = "Scanning and roaming to strongest MCS AP..."
                        msg_color = C_YELLOW
                        roamed, r_msg = wifi_roamer.auto_roam()
                        status_message = r_msg
                        msg_color = C_GREEN if roamed else C_YELLOW
                        break

                    elif key == "i":
                        status_message = "Testing IP & Auto-healing..."
                        msg_color = C_YELLOW
                        healed, h_msg = ip_cycler.auto_heal_ip()
                        status_message = h_msg
                        msg_color = C_GREEN if healed else C_YELLOW
                        break

                    elif key == "d":
                        status_message = "Reverting interface to DHCP..."
                        msg_color = C_YELLOW
                        dhcp_ok = ip_cycler.revert_to_dhcp()
                        status_message = "Interface reverted to DHCP" if dhcp_ok else "DHCP command failed"
                        msg_color = C_GREEN if dhcp_ok else C_RED
                        break

                time.sleep(0.05)

    except KeyboardInterrupt:
        clear_screen()
        print(f"\n{C_CYAN}Dashboard closed.{C_RESET}\n")

if __name__ == "__main__":
    run_dashboard()
