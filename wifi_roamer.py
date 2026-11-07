import subprocess
import re
import time
import logging

logger = logging.getLogger("MCS_WiFiRoamer")

DEFAULT_PATTERNS = [
    r"^Campus.*",
    r"^AccessNet.*",
    r"^Hostel.*",
    r"^WLAN.*",
    r"^LC\d*",
    r"^AP.*",
]

class WiFiRoamer:
    def __init__(self, interface_name="Wi-Fi"):
        self.interface = interface_name

    def is_mcs_ssid(self, ssid):
        if not ssid:
            return False
        for pat in DEFAULT_PATTERNS:
            if re.match(pat, ssid, re.IGNORECASE):
                return True
        # Match common prefixes (e.g. matching letters before trailing numbers)
        current = self.get_current_ssid()
        if current:
            clean_curr = re.sub(r"\d+$", "", current).strip()
            if clean_curr and ssid.lower().startswith(clean_curr.lower()):
                return True
        return False

    def scan_networks(self):
        """Scans for all visible Wi-Fi networks and returns a list sorted by signal."""
        networks = []
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            ).decode("utf-8", errors="ignore")

            current_ssid = None
            current_auth = "Open"
            for line in out.splitlines():
                line = line.strip()
                m_ssid = re.match(r"^SSID \d+ : (.*)$", line)
                if m_ssid:
                    current_ssid = m_ssid.group(1).strip()
                    continue

                m_auth = re.match(r"^Authentication\s+: (.*)$", line)
                if m_auth:
                    current_auth = m_auth.group(1).strip()
                    continue

                m_sig = re.match(r"^Signal\s+: (\d+)%", line)
                if m_sig and current_ssid:
                    sig_val = int(m_sig.group(1))
                    networks.append({
                        "ssid": current_ssid,
                        "signal": sig_val,
                        "auth": current_auth,
                        "is_mcs": self.is_mcs_ssid(current_ssid)
                    })
        except Exception as e:
            logger.debug(f"Wi-Fi scan error: {e}")

        # Deduplicate by SSID keeping highest signal
        dedup = {}
        for net in networks:
            ssid = net["ssid"]
            if ssid not in dedup or net["signal"] > dedup[ssid]["signal"]:
                dedup[ssid] = net

        sorted_nets = sorted(dedup.values(), key=lambda x: x["signal"], reverse=True)
        return sorted_nets

    def get_best_mcs_ap(self):
        """Returns the highest signal MCS Wi-Fi network available."""
        nets = self.scan_networks()
        mcs_nets = [n for n in nets if n["is_mcs"]]
        return mcs_nets[0] if mcs_nets else None

    def get_known_profiles(self):
        """Returns list of configured Wi-Fi profiles in Windows."""
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "profiles"],
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            ).decode("utf-8", errors="ignore")

            profiles = []
            for line in out.splitlines():
                if "All User Profile" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        prof = parts[1].strip()
                        if prof:
                            profiles.append(prof)
            return profiles
        except Exception:
            return []

    def connect_to_ssid(self, target_ssid):
        """Attempts to connect to target SSID using an existing profile or SSID name."""
        try:
            profiles = self.get_known_profiles()
            # Find matching profile
            matching_profile = None
            for p in profiles:
                if p == target_ssid or p.startswith(target_ssid):
                    matching_profile = p
                    break
            
            cmd = ["netsh", "wlan", "connect"]
            if matching_profile:
                cmd.extend([f"name={matching_profile}", f"ssid={target_ssid}"])
            else:
                cmd.extend([f"name={target_ssid}", f"ssid={target_ssid}"])

            logger.info(f"Connecting to Wi-Fi: {' '.join(cmd)}")
            res = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            time.sleep(2)
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to connect to {target_ssid}: {e}")
            return False

    def auto_roam(self, current_ssid=None, current_signal=None):
        """
        Evaluates whether roaming to a better MCS AP is warranted.
        Switches if current signal is poor (< 35%) and another MCS AP is > 65%.
        """
        best = self.get_best_mcs_ap()
        if not best:
            return False, "No MCS APs detected"

        if not current_ssid or not self.is_mcs_ssid(current_ssid):
            # Not connected to MCS Wi-Fi, connect to best available
            success = self.connect_to_ssid(best["ssid"])
            return success, f"Connected to {best['ssid']} ({best['signal']}%)"

        sig_val = 0
        if current_signal:
            try:
                sig_val = int(str(current_signal).replace("%", "").strip())
            except Exception:
                sig_val = 0

        # Roam if significant signal improvement
        if sig_val < 35 and best["signal"] >= 60 and best["ssid"] != current_ssid:
            logger.info(f"Roaming from {current_ssid} ({sig_val}%) to stronger AP {best['ssid']} ({best['signal']}%)")
            success = self.connect_to_ssid(best["ssid"])
            return success, f"Roamed to {best['ssid']} ({best['signal']}%)"

        return False, f"Current AP {current_ssid} ({sig_val}%) is optimal"
