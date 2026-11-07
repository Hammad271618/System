import sys
import os
import ctypes
from ctypes import wintypes

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tray_app import MCSTrayApp

MUTEX_NAME = "Global\\MCS_AutoLogin_SingleInstance_Mutex"

def acquire_single_instance_mutex():
    """Ensures only one instance of the background daemon runs at a time."""
    kernel32 = ctypes.windll.kernel32
    mutex = kernel32.CreateMutexW(None, wintypes.BOOL(True), MUTEX_NAME)
    last_error = kernel32.GetLastError()
    if last_error == 183:  # ERROR_ALREADY_EXISTS
        print("MCS Auto-Login background service is already running.")
        sys.exit(0)
    return mutex

def main():
    _mutex = acquire_single_instance_mutex()
    app = MCSTrayApp(check_interval_sec=15)
    app.run()

if __name__ == "__main__":
    main()
