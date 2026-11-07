import os
import sys
import time
import json
import subprocess
import logging

logger = logging.getLogger("MCS_ServiceController")

def get_app_dir():
    """Returns directory containing script or executable."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

class ServiceController:
    """Manages background daemon service lifecycle (detection, start, stop, restart)."""

    def __init__(self, app_dir=None):
        self.app_dir = os.path.abspath(app_dir or get_app_dir())

    def find_running_instances(self):
        """
        Scans active processes on Windows to find running instances of MCS Auto-Login service.
        Returns a list of dicts: [{'pid': int, 'name': str, 'cmdline': str}].
        """
        instances = []
        current_pid = os.getpid()

        # Method 1: Try PowerShell Get-CimInstance (structured, fast) via Base64 encoded command
        try:
            import base64
            ps_script = (
                "Get-CimInstance Win32_Process -Filter \"Name LIKE '%python%' OR Name = 'AutoLogin.exe' OR Name = 'MCS-AutoLogin.exe'\" "
                "| Select-Object ProcessId, Name, CommandLine | ConvertTo-Json -Compress"
            )
            b64_cmd = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
            res = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", b64_cmd],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    pid = item.get("ProcessId")
                    name = item.get("Name") or ""
                    cmd = item.get("CommandLine") or ""
                    if pid and pid != current_pid:
                        if self._is_service_process(name, cmd):
                            instances.append({"pid": int(pid), "name": name, "cmdline": cmd})
                return instances
        except Exception as e:
            logger.debug(f"PowerShell process scan error: {e}")

        # Method 2: Fallback to WMIC
        try:
            wmic_cmd = (
                'wmic process where "name like \'%python%\' or name=\'MCS-AutoLogin.exe\'" '
                'get ProcessId,CommandLine /format:csv'
            )
            res = subprocess.run(
                wmic_cmd,
                capture_output=True,
                text=True,
                shell=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            if res.returncode == 0 and res.stdout:
                lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
                for line in lines[1:]:  # skip header
                    parts = line.split(",")
                    if len(parts) >= 3:
                        cmd = parts[1].strip()
                        pid_str = parts[-1].strip()
                        if pid_str.isdigit():
                            pid = int(pid_str)
                            if pid != current_pid and self._is_service_process("", cmd):
                                if not any(x["pid"] == pid for x in instances):
                                    instances.append({"pid": pid, "name": "python", "cmdline": cmd})
                return instances
        except Exception as e:
            logger.debug(f"WMIC process scan error: {e}")

        return instances

    def _is_service_process(self, name, cmdline):
        """Checks if process name or command line belongs to MCS background service."""
        name_lower = (name or "").lower()
        cmd_lower = (cmdline or "").lower()

        if "autologin.exe" in name_lower or "autologin.exe" in cmd_lower:
            return True

        if "main.py" in cmd_lower or "tray_app.py" in cmd_lower:
            excluded = ["command_center", "build_package", "test_", "pyinstaller"]
            if not any(ex in cmd_lower for ex in excluded):
                return True

        return False

    def is_service_running(self):
        """Returns True if at least one background service instance is active."""
        return len(self.find_running_instances()) > 0

    def get_status(self):
        """Returns detailed dictionary about background service state."""
        instances = self.find_running_instances()
        running = len(instances) > 0
        pids = [inst["pid"] for inst in instances]

        summary = f"Running (PID: {', '.join(map(str, pids))})" if running else "Stopped"
        mode = "Standalone EXE" if any("mcs-autologin" in i.get("name", "").lower() for i in instances) else "Python Daemon"

        return {
            "running": running,
            "pids": pids,
            "instances": instances,
            "summary": summary,
            "mode": mode if running else "None"
        }

    def start(self):
        """Starts the background tray service."""
        running_inst = self.find_running_instances()
        if running_inst:
            pids_str = ", ".join(str(i["pid"]) for i in running_inst)
            return False, f"Service is already running (PID: {pids_str})"

        exe_path = os.path.join(self.app_dir, "AutoLogin.exe")
        if not os.path.exists(exe_path):
            exe_path = os.path.join(self.app_dir, "MCS-AutoLogin.exe")
        flags = 0
        if sys.platform == "win32":
            DETACHED_PROCESS = 0x00000008
            CREATE_NO_WINDOW = 0x08000000
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            flags = DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP

        try:
            if getattr(sys, "frozen", False):
                if not os.path.exists(exe_path):
                    return False, f"Could not find MCS-AutoLogin.exe in {self.app_dir}"
                logger.info(f"Launching standalone background executable: {exe_path}")
                proc = subprocess.Popen(
                    [exe_path],
                    cwd=self.app_dir,
                    creationflags=flags,
                    close_fds=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL
                )
            elif os.path.exists(exe_path):
                # Run compiled standalone EXE
                logger.info(f"Launching standalone background executable: {exe_path}")
                proc = subprocess.Popen(
                    [exe_path],
                    cwd=self.app_dir,
                    creationflags=flags,
                    close_fds=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL
                )
            else:
                # Run Python script via pythonw.exe or python.exe
                python_exe = sys.executable
                pythonw_exe = python_exe.replace("python.exe", "pythonw.exe")
                if not os.path.exists(pythonw_exe):
                    pythonw_exe = python_exe

                script_path = os.path.join(self.app_dir, "main.py")
                if not os.path.exists(script_path):
                    return False, f"Could not find main.py or MCS-AutoLogin.exe in {self.app_dir}"

                logger.info(f"Launching script background daemon: {pythonw_exe} main.py")
                proc = subprocess.Popen(
                    [pythonw_exe, "main.py"],
                    cwd=self.app_dir,
                    creationflags=flags,
                    close_fds=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL
                )

            # Wait briefly and verify process is running
            time.sleep(1.5)
            active = self.find_running_instances()
            if active:
                pids_str = ", ".join(str(i["pid"]) for i in active)
                return True, f"Background service started successfully (PID: {pids_str})"
            else:
                return False, "Process started but did not remain running. Check mcs_login.log."

        except Exception as e:
            logger.error(f"Failed to start service: {e}")
            return False, f"Failed to start service: {e}"

    def stop(self):
        """Stops all running instances of the background service."""
        instances = self.find_running_instances()
        if not instances:
            return False, "No background service is currently running."

        stopped_pids = []
        errors = []

        for inst in instances:
            pid = inst["pid"]
            try:
                if sys.platform == "win32":
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid), "/T"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=3,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                else:
                    os.kill(pid, 9)
                stopped_pids.append(pid)
            except Exception as e:
                errors.append(f"PID {pid}: {e}")

        time.sleep(0.8)
        remaining = self.find_running_instances()
        if remaining:
            rem_pids = ", ".join(str(i["pid"]) for i in remaining)
            return False, f"Some instances could not be terminated: PID {rem_pids}"

        return True, f"Service stopped successfully (Terminated PID: {', '.join(map(str, stopped_pids))})"

    def restart(self):
        """Restarts the background service."""
        if self.is_service_running():
            self.stop()
            time.sleep(1.0)
        return self.start()

def main():
    controller = ServiceController()
    action = sys.argv[1].lower() if len(sys.argv) > 1 else "status"

    if action == "status":
        stat = controller.get_status()
        print(f"Service Status: {stat['summary']} [Mode: {stat['mode']}]")
        for i in stat["instances"]:
            print(f"  - PID {i['pid']}: {i['cmdline']}")
    elif action == "start":
        ok, msg = controller.start()
        print(f"[{'OK' if ok else 'FAIL'}] {msg}")
    elif action == "stop":
        ok, msg = controller.stop()
        print(f"[{'OK' if ok else 'FAIL'}] {msg}")
    elif action == "restart":
        ok, msg = controller.restart()
        print(f"[{'OK' if ok else 'FAIL'}] {msg}")
    else:
        print(f"Unknown action: {action}. Usage: service_controller.py [status|start|stop|restart]")

if __name__ == "__main__":
    main()
