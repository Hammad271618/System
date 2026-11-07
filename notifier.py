import logging
import subprocess

logger = logging.getLogger("MCS_Notifier")

class Notifier:
    def __init__(self, tray_icon=None):
        self.tray_icon = tray_icon

    def set_tray_icon(self, tray_icon):
        self.tray_icon = tray_icon

    def notify(self, title, message):
        logger.info(f"Notification: [{title}] {message}")
        # Try pystray first if available
        if self.tray_icon:
            try:
                self.tray_icon.notify(message, title)
                return
            except Exception as e:
                logger.debug(f"pystray notify failed: {e}")

        # Fallback to PowerShell balloon / notification
        try:
            safe_title = str(title).replace("'", "''")
            safe_msg = str(message).replace("'", "''")
            ps_script = f"""
            [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null
            $notify = new-object system.windows.forms.notifyicon
            $notify.icon = [System.Drawing.SystemIcons]::Information
            $notify.visible = $true
            $notify.showballoontip(4000, '{safe_title}', '{safe_msg}', [system.windows.forms.tooltipicon]::Info)
            Start-Sleep -Seconds 1
            $notify.Dispose()
            """
            subprocess.Popen(["powershell", "-WindowStyle", "Hidden", "-Command", ps_script], 
                             creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
        except Exception as e:
            logger.debug(f"PowerShell notification fallback failed: {e}")
