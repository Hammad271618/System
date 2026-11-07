import os
import sys
import winreg
import logging

logger = logging.getLogger("MCS_StartupManager")
APP_NAME = "MCSAutoLogin"

class StartupManager:
    REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"

    @classmethod
    def is_startup_enabled(cls):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_PATH, 0, winreg.KEY_READ) as key:
                val, _ = winreg.QueryValueEx(key, APP_NAME)
                return bool(val)
        except FileNotFoundError:
            return False
        except Exception as e:
            logger.debug(f"Error checking startup key: {e}")
            return False

    @classmethod
    def set_startup(cls, enable=True):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_PATH, 0, winreg.KEY_SET_VALUE) as key:
                if enable:
                    if getattr(sys, "frozen", False):
                        cmd = f'"{sys.executable}"'
                    else:
                        python_exe = sys.executable
                        pythonw_exe = python_exe.replace("python.exe", "pythonw.exe")
                        if not os.path.exists(pythonw_exe):
                            pythonw_exe = python_exe
                        script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "main.py"))
                        cmd = f'"{pythonw_exe}" "{script_path}"'
                    winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, cmd)
                    logger.info(f"Enabled Windows startup: {cmd}")
                else:
                    try:
                        winreg.DeleteValue(key, APP_NAME)
                        logger.info("Disabled Windows startup.")
                    except FileNotFoundError:
                        pass
                return True
        except Exception as e:
            logger.error(f"Failed to modify startup registry: {e}")
            return False
