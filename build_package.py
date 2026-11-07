import os
import sys
import shutil
import zipfile
import subprocess
import time

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(PROJECT_DIR, "dist")
BUILD_DIR = os.path.join(PROJECT_DIR, "build")
PACKAGE_NAME = "MCS-AutoLogin-v1.0"
STAGE_DIR = os.path.join(DIST_DIR, PACKAGE_NAME)
ZIP_OUTPUT = os.path.join(DIST_DIR, f"{PACKAGE_NAME}.zip")

README_CONTENT = """========================================================================
     MCS FORTINET AUTO-LOGIN & CMD COMMAND CENTRE (PORTABLE)
                 Zero-Interruption Multi-Account Quota Hub
========================================================================

Welcome to the portable distribution of MCS Fortinet Auto-Login!
This package is fully self-contained and runs on Windows 10 & 11 without
requiring Python or manual library installation.

------------------------------------------------------------------------
QUICK START GUIDE
------------------------------------------------------------------------

1. COMMAND CENTRE (Recommended Hub):
   - Double-click 'command_center.bat' or run 'MCS-CommandCenter.exe'
   - Displays real-time Wi-Fi, IP, captive portal status, and account pool.
   - Quick commands:
       * status    : Full system telemetry
       * switch    : Advance to next account & authenticate
       * accounts  : View all 29 accounts and quotas
       * roam      : Roam to strongest MCS Wi-Fi access point
       * fix-ip    : Auto-heal DHCP exhaustion / Assign static IP
       * dhcp      : Revert adapter back to dynamic DHCP
       * start-bg  : Launch background tray daemon
       * stop-bg   : Stop background tray daemon
       * dashboard : Open full-screen real-time visual monitor

2. BACKGROUND SYSTEM TRAY SERVICE:
   - Double-click 'run.bat' or 'MCS-AutoLogin.exe'
   - Sits silently in your Windows System Tray (near clock).
   - Monitors network health every few seconds:
       * Green dot : Online & authenticated
       * Yellow dot: Portal detected / logging in
       * Gray dot  : Offline / disconnected
   - Right-click the tray icon for quick controls, account switching,
     and "Start on Windows Boot".

3. REAL-TIME VISUAL MONITOR:
   - Double-click 'dashboard.bat'
   - Live curses-style dashboard showing latency, active account,
     nearby Wi-Fi APs, and recent activity log.
   - Press 's' to switch account, 'r' to reset, 'w' to roam Wi-Fi.

------------------------------------------------------------------------
ACCOUNT CONFIGURATION
------------------------------------------------------------------------
All accounts are stored in 'accounts.json'. You can add, edit, or customize
credentials directly in 'accounts.json' or interactively via the Command
Centre using the 'add' command. Quotas automatically reset daily at midnight.

------------------------------------------------------------------------
SUPPORT & TROUBLESHOOTING
------------------------------------------------------------------------
- If Wi-Fi is connected but stuck on 'Identifying...', run 'fix-ip' in
  the Command Centre to bypass MCS DHCP pool exhaustion.
- Check 'mcs_login.log' for diagnostic logs and connection history.
========================================================================
"""

def clean_build_artifacts():
    print("[1/5] Cleaning previous build staging directories...")
    if os.path.exists(STAGE_DIR):
        shutil.rmtree(STAGE_DIR, ignore_errors=True)
    if os.path.exists(ZIP_OUTPUT):
        try:
            os.remove(ZIP_OUTPUT)
        except Exception:
            pass
    os.makedirs(STAGE_DIR, exist_ok=True)

def compile_executables(skip_pyinstaller=False):
    if skip_pyinstaller:
        print("[2/5] Skipping PyInstaller compilation (--skip-pyinstaller flag passed).")
        return

    print("[2/5] Compiling standalone Windows executables with PyInstaller...")
    python_exe = sys.executable

    # Check if pyinstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("  -> Installing pyinstaller via pip...")
        subprocess.check_call([python_exe, "-m", "pip", "install", "pyinstaller"])

    # 1. Compile MCS-AutoLogin.exe (Windowless tray daemon)
    print("  -> Compiling MCS-AutoLogin.exe (Tray Service)...")
    cmd_tray = [
        python_exe, "-m", "PyInstaller",
        "--noconsole",
        "--onefile",
        "--clean",
        "--name", "MCS-AutoLogin",
        "--distpath", STAGE_DIR,
        "--workpath", os.path.join(BUILD_DIR, "autologin"),
        "--specpath", BUILD_DIR,
        "--hidden-import", "pystray",
        "--hidden-import", "PIL",
        "--hidden-import", "PIL.Image",
        "--hidden-import", "PIL.ImageDraw",
        "--hidden-import", "requests",
        "--hidden-import", "urllib3",
        "--hidden-import", "bs4",
        "--hidden-import", "soupsieve",
        "--hidden-import", "cryptography",
        "--hidden-import", "security",
        "--hidden-import", "updater",
        os.path.join(PROJECT_DIR, "main.py")
    ]
    t0 = time.time()
    res1 = subprocess.run(cmd_tray, capture_output=True, text=True)
    if res1.returncode != 0:
        print(f"PyInstaller build failed for MCS-AutoLogin:\n{res1.stderr}")
        raise RuntimeError("MCS-AutoLogin build failed")
    print(f"  -> MCS-AutoLogin.exe built in {int(time.time() - t0)}s.")

    # 2. Compile MCS-CommandCenter.exe (Console application)
    print("  -> Compiling MCS-CommandCenter.exe (Command Centre & Dashboard)...")
    cmd_cli = [
        python_exe, "-m", "PyInstaller",
        "--console",
        "--onefile",
        "--clean",
        "--name", "MCS-CommandCenter",
        "--distpath", STAGE_DIR,
        "--workpath", os.path.join(BUILD_DIR, "commandcenter"),
        "--specpath", BUILD_DIR,
        "--hidden-import", "pystray",
        "--hidden-import", "PIL",
        "--hidden-import", "requests",
        "--hidden-import", "urllib3",
        "--hidden-import", "bs4",
        "--hidden-import", "soupsieve",
        "--hidden-import", "cryptography",
        "--hidden-import", "security",
        "--hidden-import", "updater",
        os.path.join(PROJECT_DIR, "command_center.py")
    ]
    t0 = time.time()
    res2 = subprocess.run(cmd_cli, capture_output=True, text=True)
    if res2.returncode != 0:
        print(f"PyInstaller build failed for MCS-CommandCenter:\n{res2.stderr}")
        raise RuntimeError("MCS-CommandCenter build failed")
    print(f"  -> MCS-CommandCenter.exe built in {int(time.time() - t0)}s.")

def copy_distribution_assets():
    print("[3/5] Packaging configuration templates, launchers, and documentation...")
    
    # 1. accounts.json & accounts.enc & version.json
    for f in ["accounts.json", "accounts.enc", "version.json"]:
        src = os.path.join(PROJECT_DIR, f)
        dst = os.path.join(STAGE_DIR, f)
        if os.path.exists(src):
            shutil.copy2(src, dst)

    # 2. Batch launchers
    launchers = ["command_center.bat", "run.bat", "dashboard.bat", "start_silent.vbs", "build_export.bat"]
    for l in launchers:
        src = os.path.join(PROJECT_DIR, l)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(STAGE_DIR, l))

    # 3. Documentation README
    readme_path = os.path.join(STAGE_DIR, "README.txt")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(README_CONTENT)

    print(f"  -> Copied assets to {STAGE_DIR}")

def create_zip_archive():
    print(f"[4/5] Compressing standalone distribution into {ZIP_OUTPUT}...")
    with zipfile.ZipFile(ZIP_OUTPUT, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(STAGE_DIR):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, os.path.dirname(STAGE_DIR))
                zf.write(abs_path, rel_path)

    zip_size_mb = os.path.getsize(ZIP_OUTPUT) / (1024 * 1024)
    print(f"  -> Package created successfully: {ZIP_OUTPUT} ({zip_size_mb:.2f} MB)")

def verify_package():
    print("[5/5] Verifying packaged archive contents...")
    with zipfile.ZipFile(ZIP_OUTPUT, "r") as zf:
        namelist = zf.namelist()
        print(f"  -> Total files in archive: {len(namelist)}")
        for name in sorted(namelist):
            info = zf.getinfo(name)
            size_kb = info.file_size / 1024
            print(f"     - {name} ({size_kb:.1f} KB)")
    print("\n================================================================")
    print("           PORTABLE PACKAGE EXPORT COMPLETED SUCCESSFULLY!       ")
    print(f" Location: {ZIP_OUTPUT}")
    print("================================================================\n")

def build_from_frozen(app_dir):
    """Packages the current portable directory when running inside compiled executable."""
    print("[1/3] Packaging portable distribution from current directory...")
    zip_path = os.path.join(app_dir, f"{PACKAGE_NAME}.zip")
    if os.path.exists(zip_path):
        try:
            os.remove(zip_path)
        except Exception:
            pass

    # Ensure README.txt exists
    readme_path = os.path.join(app_dir, "README.txt")
    if not os.path.exists(readme_path):
        try:
            with open(readme_path, "w", encoding="utf-8") as f:
                f.write(README_CONTENT)
        except Exception:
            pass

    # Files to include in export archive
    target_files = [
        "MCS-AutoLogin.exe",
        "MCS-CommandCenter.exe",
        "accounts.json",
        "command_center.bat",
        "run.bat",
        "dashboard.bat",
        "start_silent.vbs",
        "build_export.bat",
        "README.txt"
    ]

    print(f"[2/3] Compressing into {zip_path}...")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fname in target_files:
            fpath = os.path.join(app_dir, fname)
            if os.path.exists(fpath):
                arcname = f"{PACKAGE_NAME}/{fname}"
                zf.write(fpath, arcname)
                print(f"  + Added: {fname}")

    print("[3/3] Verifying packaged archive...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = zf.namelist()
        print(f"  -> Total files in archive: {len(namelist)}")
        for name in sorted(namelist):
            info = zf.getinfo(name)
            size_kb = info.file_size / 1024
            print(f"     - {name} ({size_kb:.1f} KB)")

    zip_size_mb = os.path.getsize(zip_path) / (1024 * 1024)
    print("\n================================================================")
    print("           PORTABLE PACKAGE EXPORT COMPLETED SUCCESSFULLY!       ")
    print(f" Location: {zip_path} ({zip_size_mb:.2f} MB)")
    print("================================================================\n")
    return zip_path

def build_distribution(skip_pyinstaller=False):
    t_start = time.time()
    if getattr(sys, "frozen", False):
        app_dir = os.path.dirname(os.path.abspath(sys.executable))
        build_from_frozen(app_dir)
        print(f"Export completed in {int(time.time() - t_start)} seconds.")
        return

    clean_build_artifacts()
    compile_executables(skip_pyinstaller=skip_pyinstaller)
    copy_distribution_assets()
    create_zip_archive()
    verify_package()
    print(f"Build completed in {int(time.time() - t_start)} seconds.")

if __name__ == "__main__":
    skip = "--skip-pyinstaller" in sys.argv
    build_distribution(skip_pyinstaller=skip)
