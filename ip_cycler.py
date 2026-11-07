import subprocess
import re
import time
import logging

logger = logging.getLogger("MCS_IPCycler")

COMMON_MCS_GATEWAYS = [
    "172.23.210.1",
    "172.23.200.254",
    "172.26.181.173"
]

class IPCycler:
    def __init__(self, interface_name="Wi-Fi"):
        self.interface = interface_name

    def get_current_ip_info(self):
        """Returns (ip, gateway, is_dhcp) for the Wi-Fi interface."""
        try:
            out = subprocess.check_output(
                ["netsh", "interface", "ipv4", "show", "config", self.interface],
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            ).decode("utf-8", errors="ignore")

            m_ip = re.search(r"IP Address:\s+([0-9.]+)", out)
            m_gw = re.search(r"Default Gateway:\s+([0-9.]+)", out)
            m_dhcp = re.search(r"DHCP enabled:\s+(\w+)", out)

            ip = m_ip.group(1).strip() if m_ip else None
            gw = m_gw.group(1).strip() if m_gw else None
            is_dhcp = (m_dhcp.group(1).strip().lower() == "yes") if m_dhcp else True

            return ip, gw, is_dhcp
        except Exception as e:
            logger.debug(f"Could not get IP info: {e}")
            return None, None, True

    def renew_dhcp(self):
        """Restores interface to DHCP and triggers a clean DHCP renewal (ipconfig /renew)."""
        self.revert_to_dhcp()
        try:
            logger.info(f"Renewing DHCP lease via ipconfig /renew {self.interface}...")
            subprocess.run(
                ["ipconfig", "/renew", self.interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            return True
        except Exception as e:
            logger.error(f"Failed to run ipconfig /renew {self.interface}: {e}")
            return False

    def is_dhcp_failed(self):
        """
        Returns True if adapter has APIPA 169.254.x.x, has no gateway while on DHCP,
        has no IP, or if static IP is set but default gateway is unreachable
        (in which case it auto-reverts to DHCP).
        """
        ip, gw, is_dhcp = self.get_current_ip_info()
        if not ip:
            return True
        if ip.startswith("169.254."):
            return True
        if not is_dhcp:
            # Static IP configured: verify default gateway is reachable
            if not gw or not self.is_ip_in_use(gw):
                logger.warning(
                    f"Static IP {ip} is set but gateway {gw} is unreachable. Auto-reverting to DHCP..."
                )
                self.renew_dhcp()
                return True
            return False
        if not gw and is_dhcp:
            return True
        return False

    def is_ip_in_use(self, ip_addr):
        """Pings an IP with a fast 150ms timeout to check if occupied."""
        try:
            res = subprocess.run(
                ["ping", "-n", "1", "-w", "150", ip_addr],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            return res.returncode == 0
        except Exception:
            return False

    def find_available_ip(self, gateway):
        """Scans candidate host IPs in the gateway subnet to find an unused IP."""
        parts = gateway.split(".")
        if len(parts) != 4:
            return None
        subnet_prefix = ".".join(parts[:3])
        gw_last = int(parts[3])

        # Pick a pool away from standard DHCP range (e.g. 150-230)
        candidates = [x for x in range(140, 240) if x != gw_last]
        for host in candidates:
            cand_ip = f"{subnet_prefix}.{host}"
            if not self.is_ip_in_use(cand_ip):
                logger.info(f"Found unused static IP candidate: {cand_ip}")
                return cand_ip
        return f"{subnet_prefix}.188"

    def set_static_ip(self, ip, gateway, subnet_mask="255.255.255.0", dns="1.1.1.1"):
        """Configures a static IP on the interface."""
        try:
            logger.info(f"Setting static IP {ip} (GW: {gateway}) on {self.interface}...")
            cmd1 = [
                "netsh", "interface", "ipv4", "set", "address",
                f"name={self.interface}", "source=static",
                f"addr={ip}", f"mask={subnet_mask}", f"gateway={gateway}"
            ]
            subprocess.run(
                cmd1,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )

            # Set DNS to gateway and 1.1.1.1
            cmd2 = [
                "netsh", "interface", "ipv4", "set", "dns",
                f"name={self.interface}", "source=static", f"addr={gateway}"
            ]
            subprocess.run(
                cmd2,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            time.sleep(1)
            logger.info(f"Successfully configured static IP {ip}")
            return True
        except Exception as e:
            logger.error(f"Failed to set static IP: {e}")
            return False

    def revert_to_dhcp(self):
        """Restores Wi-Fi interface back to automatic DHCP."""
        try:
            logger.info(f"Reverting {self.interface} to DHCP...")
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "address", f"name={self.interface}", "source=dhcp"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "dns", f"name={self.interface}", "source=dhcp"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            time.sleep(1)
            logger.info("Reverted interface to DHCP successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to revert to DHCP: {e}")
            return False

    def auto_heal_ip(self):
        """
        Detects if IP is stuck on APIPA / DHCP timeout and applies an available static IP,
        or triggers clean DHCP renewal if interface is reconnecting without IP or without a verified gateway.
        """
        initial_ip, initial_gw, initial_is_dhcp = self.get_current_ip_info()
        if not self.is_dhcp_failed():
            return False, f"IP is healthy: {initial_ip} (GW: {initial_gw})"

        # If static IP was set and is_dhcp_failed() already reverted it to DHCP,
        # avoid running redundant candidate tests or double renewals.
        if not initial_is_dhcp:
            return True, f"Static IP gateway {initial_gw} unreachable; auto-reverted to DHCP"

        # Refresh IP info after failure check
        ip, gw, is_dhcp = self.get_current_ip_info()
        logger.warning(f"DHCP failure detected (IP: {ip}, GW: {gw}). Starting Auto-Heal...")

        # When interface has IP: None during Wi-Fi reconnect, must NOT guess a static IP
        # or set static IP across different gateway subnets.
        # Instead, trigger a clean DHCP renewal (revert_to_dhcp and ipconfig /renew Wi-Fi).
        if not ip:
            logger.info(f"Interface {self.interface} has no IP (reconnecting). Triggering clean DHCP renewal instead of static assignment.")
            self.renew_dhcp()
            return True, f"Triggered clean DHCP renewal for {self.interface} (reconnecting, IP was None)"

        # If APIPA or no gateway, do NOT guess across subnets or poison interface!
        if ip.startswith("169.254.") or not gw or gw.startswith("169.254."):
            logger.warning("No verified default gateway on DHCP interface. Triggering clean DHCP renewal to prevent subnet poisoning.")
            self.renew_dhcp()
            return True, "Triggered clean DHCP renewal to resolve APIPA / unverified gateway"

        target_gw = gw
        if not self.is_ip_in_use(target_gw):
            logger.warning(f"Gateway {target_gw} is unreachable. Triggering clean DHCP renewal.")
            self.renew_dhcp()
            return True, "Triggered clean DHCP renewal (unreachable gateway)"

        new_ip = self.find_available_ip(target_gw)
        if new_ip:
            success = self.set_static_ip(new_ip, target_gw)
            if success:
                return True, f"Auto-healed: Set static IP {new_ip} with GW {target_gw}"

        self.renew_dhcp()
        return False, "Could not find a valid IP or apply settings; reverted to DHCP"
