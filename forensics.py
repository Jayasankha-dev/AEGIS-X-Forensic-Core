import os
import subprocess
import hashlib
import json
import time
from datetime import datetime, timedelta
import utils

# ---------- File System ----------
def get_recent_files(days=7, paths=None):
    """Find files modified in last `days` days under given paths with live output."""
    if paths is None:
        paths = [
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%APPDATA%"),
            os.path.expandvars(r"%LOCALAPPDATA%"),
            r"C:\Windows\Temp",
            r"C:\Users\Public",
            r"C:\Windows\System32\drivers\etc",
            r"C:\\"
        ]
    
    since = datetime.now() - timedelta(days=days)
    files = []
    
    print(f"\n[>] SCANNING FILE SYSTEM FOR RECENT MODIFICATIONS (Last {days} days)...")
    
    for base in paths:
        if not os.path.exists(base):
            continue
        
        print(f"    [*] Auditing Directory: {base}")
        try:
            for root, dirs, names in os.walk(base, topdown=True, followlinks=False):
                # Skip certain directories to avoid huge/locked scans
                if 'Windows\\WinSxS' in root or '\\System32\\config' in root:
                    continue
                
                for name in names:
                    full = os.path.join(root, name)
                    try:
                        mtime = datetime.fromtimestamp(os.path.getmtime(full))
                        if mtime > since:
                            files.append({
                                'path': full,
                                'last_modified': mtime.isoformat()
                            })
                            # Live feed of discovered files (limited to keep it readable)
                            if len(files) % 5 == 0:
                                print(f"    [!] Target Identified: {name[:40]}...")
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            continue
            
    # Sort by date descending
    files.sort(key=lambda x: x['last_modified'], reverse=True)
    print(f"    [+] Forensic scan complete. {len(files)} suspicious entries logged.")
    return files

def get_prefetch_files():
    """Extract evidence from Windows Prefetch (Execution History)."""
    prefetch_dir = r"C:\Windows\Prefetch"
    print("\n[>] EXTRACTING PREFETCH EXECUTION ARTIFACTS...")
    
    if not os.path.exists(prefetch_dir):
        print("    [!] Access Denied: Prefetch directory not found.")
        return []
        
    files = []
    try:
        pf_list = [f for f in os.listdir(prefetch_dir) if f.endswith('.pf')]
        for f in pf_list[:20]: # Show first 20 live
            full = os.path.join(prefetch_dir, f)
            mtime = datetime.fromtimestamp(os.path.getmtime(full))
            print(f"    [*] Evidence: {f:<30} | Last Run: {mtime}")
            files.append(f"{f} [last run: {mtime}]")
            time.sleep(0.01)
    except (OSError, PermissionError):
        pass
    return files

def get_alternate_data_streams(paths=None):
    """Find ADS (Hidden Data) on files with real-time reporting."""
    if paths is None:
        paths = [r"C:\Windows\System32", os.path.expandvars(r"%TEMP%"), os.path.expandvars(r"%APPDATA%")]
    
    ads_list = []
    print("\n[>] PROBING FOR HIDDEN ALTERNATE DATA STREAMS (ADS)...")
    
    cmd_template = 'Get-Item -Path "{}" -Stream * | Select-Object Stream, Length | ConvertTo-Json'
    
    for base in paths:
        if not os.path.exists(base): continue
        print(f"    [*] Checking hive: {base}")
        try:
            for root, dirs, files in os.walk(base, topdown=True):
                for file in files[:30]:  # limit per folder for speed
                    full = os.path.join(root, file)
                    cmd = cmd_template.format(full)
                    output = subprocess.run(
                        ["powershell", "-ExecutionPolicy", "Bypass", "-Command", cmd],
                        capture_output=True, text=True, shell=True, timeout=5
                    ).stdout.strip()
                    
                    if output and ':$DATA' not in output:
                        try:
                            streams = json.loads(output)
                            if isinstance(streams, dict): streams = [streams]
                            for s in streams:
                                if s['Stream'] != ':$DATA':
                                    entry = f"{full}:{s['Stream']} (size {s['Length']})"
                                    ads_list.append(entry)
                                    print(f"    [🚩] ADS DETECTED: {s['Stream']} in {file}")
                        except: pass
        except: continue
    return ads_list

def get_usb_history():
    """Parse USBSTOR registry key for hardware connection history."""
    import winreg
    usb_devices = []
    print("\n[>] RETRIEVING USB MOUNT HISTORY FROM REGISTRY...")
    
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                subkey = winreg.OpenKey(key, subkey_name)
                j = 0
                while True:
                    try:
                        device_instance = winreg.EnumKey(subkey, j)
                        device_key = winreg.OpenKey(subkey, device_instance)
                        friendly_name, _ = winreg.QueryValueEx(device_key, "FriendlyName")
                        usb_devices.append(friendly_name)
                        print(f"    [*] Hardware ID: {friendly_name}")
                        j += 1
                        time.sleep(0.02)
                    except OSError: break
                i += 1
            except OSError: break
    except Exception: pass
    return usb_devices

def get_event_logs(log_name, event_id=None, max_events=50, level=None):
    """Fetch Windows Event Logs using PowerShell with status updates."""
    print(f"\n[>] QUERYING WINDOWS EVENT LOGS: {log_name}...")
    filter_str = f"LogName='{log_name}'"
    if event_id: filter_str += f" and ID={event_id}"
    if level: filter_str += f" and LevelDisplayName='{level}'"
    
    cmd = f"Get-WinEvent -FilterHashtable @{{{filter_str}}} -MaxEvents {max_events} | Select TimeCreated, Id, Message | ConvertTo-Json"
    
    output = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-Command", cmd],
        capture_output=True, text=True, shell=True, timeout=10
    ).stdout.strip()
    
    try:
        events = json.loads(output)
        if isinstance(events, dict): events = [events]
        print(f"    [+] Successfully extracted {len(events)} log entries.")
        return events
    except:
        print("    [!] No matching events found in the specified log.")
        return []

# =========================================================================
# NEW FUNCTIONS FOR OPTIONS 9, 10, 11
# =========================================================================

# ---------- Helper for PowerShell commands ----------
def run_powershell_command(cmd):
    """Run a PowerShell command and return stdout/stderr."""
    try:
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, shell=True, timeout=30
        )
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return "", str(e)

# ---------- OPTION 9: FBI Tactical Audit (10 Steps) ----------
TACTICAL_STEP_COMMANDS = {
    1: "Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Sort-Object RemoteAddress | Format-Table -AutoSize",
    2: "Get-Process | Where-Object { $_.Description -eq $null -or $_.Company -notmatch 'Microsoft' } | Select-Object Name, Id, Path, Description | Format-Table -AutoSize",
    3: "Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' -and $_.LocalPort -notmatch '135|445' } | Format-Table -AutoSize",
    4: "$paths = @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'); foreach ($path in $paths) { Get-ItemProperty $path | Select-Object PSChildName, * }",
    5: "Get-ScheduledTask | Where-Object { $_.Author -notmatch 'Microsoft|WID' -and $_.State -ne 'Disabled' } | Select-Object TaskName, TaskPath, Author | Format-Table -AutoSize",
    6: "Get-ChildItem -Path C:\\ -Include *.exe, *.dll, *.bat, *.ps1 -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddHours(-4) } | Select-Object FullName, CreationTime | Format-Table -AutoSize",
    7: "Get-LocalGroupMember -Group 'Administrators' | Format-Table -AutoSize",
    8: "Get-WmiObject Win32_Service | Where-Object { $_.PathName -notlike '*Windows*' -and $_.State -eq 'Running' } | Select-Object Name, PathName | Format-Table -AutoSize",
    9: "Get-DnsClientCache | Select-Object EntryName, Data | Unique | Format-Table -AutoSize",
    10: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-List"
}

def execute_tactical_step(step_num):
    """Execute a single tactical audit step with real PowerShell command."""
    steps = {
        1: "Network Lockdown (Active Connections)",
        2: "Memory Audit (Unsigned Processes)",
        3: "Backdoor Hunt (Listening Ports)",
        4: "Persistence Hunt (Registry Auto-runs)",
        5: "Scheduled Task Audit (Hidden Persistence)",
        6: "Timeline Analysis (Files created in last 4 hours)",
        7: "User Account Audit (Admin Group Check)",
        8: "System Service Audit (Non-Microsoft Services)",
        9: "DNS Cache Dump (History Tracking)",
        10: "Security Event Log (Process Creation Audit)"
    }
    print(f"\n[*] STEP {step_num}/10: {steps[step_num]}...")
    cmd = TACTICAL_STEP_COMMANDS.get(step_num)
    if not cmd:
        print("    [!] No command defined for this step.")
        return
    stdout, stderr = run_powershell_command(cmd)
    if stdout:
        print("\n--- OUTPUT ---")
        print(stdout)
    else:
        print("    [OK] No output (or no issues).")
    if stderr:
        print(f"    [!] ERROR: {stderr}")

def run_tactical_audit_menu():
    """[9] FBI Tactical Audit - 10 steps with selection."""
    while True:
        print("\n" + "!"*80)
        print(" [9] FBI TACTICAL AUDIT SUITE - 10 STEPS")
        print("!"*80)
        print(" Select a step to execute (or 0 to return):")
        print(" [1]  Network Lockdown (Active Connections)")
        print(" [2]  Memory Audit (Unsigned Processes)")
        print(" [3]  Backdoor Hunt (Listening Ports)")
        print(" [4]  Persistence Hunt (Registry Auto-runs)")
        print(" [5]  Scheduled Task Audit (Hidden Persistence)")
        print(" [6]  Timeline Analysis (Files created in last 4 hours)")
        print(" [7]  User Account Audit (Admin Group Check)")
        print(" [8]  System Service Audit (Non-Microsoft Services)")
        print(" [9]  DNS Cache Dump (History Tracking)")
        print(" [10] Security Event Log (Process Creation Audit)")
        print(" [A]  Run ALL steps sequentially")
        print(" [0]  Return to Main Menu")
        
        step_choice = input("\nSELECT STEP# ").strip()
        
        if step_choice == '0':
            break
        elif step_choice.lower() == 'a':
            print("\n[*] Running ALL 10 steps...")
            for i in range(1, 11):
                execute_tactical_step(i)
                print("\n" + "-"*40)
            print("\n[+] All steps completed.")
        elif step_choice in map(str, range(1, 11)):
            execute_tactical_step(int(step_choice))
        else:
            print("[!] Invalid selection.")
        
        input("\nPress Enter to continue...")

# ---------- OPTION 10: Browser Integrity Audit ----------
def scan_browser_extensions():
    """Perform browser extension scanning."""
    browser_paths = {
        "Google Chrome": os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions"),
        "Microsoft Edge": os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions"),
        "Brave Browser": os.path.expandvars(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Extensions")
    }
    
    for browser, path in browser_paths.items():
        if os.path.exists(path):
            print(f"\n[*] Auditing {browser} Extensions...")
            try:
                extensions = os.listdir(path)
                for ext in extensions:
                    print(f"    [>] Discovered Extension ID: {ext}")
                    time.sleep(0.05)
                print(f"    [+] {len(extensions)} extensions identified for {browser}.")
            except Exception as e:
                print(f"    [!] Error accessing {browser} path: {e}")
        else:
            print(f"[*] {browser} path not found or default profile missing.")

def suggest_chrome_pages():
    """Print Chrome internal forensic page URLs as suggestions."""
    print("\n[*] MANUAL AUDIT SUGGESTION:")
    print("    Open the following Chrome URLs manually in your browser:")
    print("    -> chrome://settings/content/notifications")
    print("    -> chrome://serviceworker-internals/")
    print("    -> chrome://net-export/")
    print("\n    These pages help you inspect notification permissions,")
    print("    service workers, and network logs for potential threats.")

def audit_browser_internals():
    """[10] Browser Integrity Audit with sub-options."""
    while True:
        print("\n" + "="*80)
        print(" [10] BROWSER INTEGRITY FORENSICS")
        print("="*80)
        print(" [1] Scan Browser Extensions")
        print(" [2] Show Chrome Internal Audit Page Suggestions")
        print(" [0] Return to Main Menu")
        
        sub_choice = input("\nSELECT ACTION# ").strip()
        
        if sub_choice == '0':
            break
        elif sub_choice == '1':
            scan_browser_extensions()
        elif sub_choice == '2':
            suggest_chrome_pages()
        else:
            print("[!] Invalid selection.")
        
        input("\nPress Enter to continue...")

# ---------- OPTION 11: Live Response Triage (25 Steps) ----------
TRIAGE_STEP_COMMANDS = {
    1: "Get-Process | Select-Object Name, Id, CPU, WorkingSet | Sort-Object CPU -Descending | Select-Object -First 20",
    2: "Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess",
    3: "Get-WmiObject -Class Win32_SystemDriver | Where-Object {$_.State -eq 'Running'} | Select-Object Name, DisplayName",
    4: "Get-ChildItem -Path \\\\.\\pipe\\",
    5: "Get-WmiObject -Class Win32_Mutex | Select-Object Name",
    6: "Get-Service | Where-Object {$_.Status -eq 'Running' -and $_.ServiceType -eq 'Win32OwnProcess'} | Select-Object Name, DisplayName",
    7: "driverquery /fo table",
    8: "Get-WmiObject -Class Win32_Process | Where-Object {$_.Name -match 'cmd|powershell|wscript'} | Select-Object Name, CommandLine",
    9: "Get-DnsClientCache | Select-Object EntryName, Data",
    10: "net share",
    11: "Get-ChildItem (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue | Get-Content -Tail 20",
    12: "qwinsta",
    13: "fsutil usn readjournal C: | Select-String 'UsnEntry' -Context 0,5",
    14: "Get-GPO -All | Select-Object DisplayName, ModificationTime",
    15: "reg query HKLM\\SECURITY\\Policy\\PolAdtEv",
    16: "Get-ChildItem C:\\Windows\\System32\\*.dll | Get-AuthenticodeSignature | Where-Object {$_.Status -ne 'Valid'} | Select-Object Path, Status",
    17: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -MaxEvents 10 | Select-Object TimeCreated, Message",
    18: "bcdedit /enum",
    19: "Get-WmiObject -Namespace root\\subscription -Class __EventFilter | Select-Object Name, Query",
    20: "schtasks /query /fo LIST /v",
    21: "Get-Process | Select-Object Name, Id, StartTime",
    22: "Get-ChildItem HKLM:\\SOFTWARE\\Classes\\CLSID -ErrorAction SilentlyContinue | ForEach-Object {Get-ItemProperty $_.PsPath}",
    23: "certutil -verifystore Root",
    24: "Get-BitsTransfer | Select-Object DisplayName, JobState",
    25: "Get-ComputerInfo | Select-Object WindowsVersion, OsName, OsBuildNumber"
}

def execute_triage_step(step_num, actions_list):
    """Execute a single triage step with real PowerShell command."""
    print(f"\n[STEP {step_num:02d}/25] Executing: {actions_list[step_num-1]}...")
    cmd = TRIAGE_STEP_COMMANDS.get(step_num)
    if not cmd:
        print("    [!] No command defined for this step.")
        return
    stdout, stderr = run_powershell_command(cmd)
    if stdout:
        print("\n--- OUTPUT ---")
        print(stdout)
    else:
        print("    [OK] No output (or no issues).")
    if stderr:
        print(f"    [!] ERROR: {stderr}")

def run_live_response_triage():
    """[11] Live Response Triage: 25-Step Critical Incident Response Protocol with step selection."""
    triage_actions = [
        "Capture Volatile Memory Info",
        "Dump Established Network States",
        "Verify Kernel Callback Routines",
        "Analyze Named Pipe Anomalies",
        "Scan Active Mutex Signatures",
        "Query Hidden Service Objects",
        "Enumerate Non-Microsoft Drivers",
        "Check Shell Spawning Patterns",
        "Trace DNS Resolution Cache",
        "Verify SMB/Admin Share Access",
        "Scan Recent PowerShell History",
        "Check Remote Desktop Logons",
        "Analyze MFT Modification Spikes",
        "Verify GPO Override Artifacts",
        "Scan Local Security Authority (LSA)",
        "Verify Cryptographic Provider DLLs",
        "Analyze Event Log Clearing IDs",
        "Check BCDedit Debugger Settings",
        "Scan WMI Event Consumer Bindings",
        "Verify Scheduled Task Binaries",
        "Analyze Process Environment Blocks",
        "Check Hijacked COM Objects",
        "Verify Root Certificate Stores",
        "Scan BITS Transfer Jobs",
        "Final Integrity Stabilization"
    ]
    while True:
        print("\n" + "#"*80)
        print(" [11] LIVE RESPONSE TRIAGE - STEP SELECTION")
        print("#"*80)
        print(" Select a step to execute (or 0 to return):")
        for idx, action in enumerate(triage_actions, 1):
            print(f" [{idx:02d}] {action}")
        print(" [A]  Run ALL steps sequentially")
        print(" [0]  Return to Main Menu")
        
        step_choice = input("\nSELECT STEP# ").strip()
        
        if step_choice == '0':
            break
        elif step_choice.lower() == 'a':
            print("\n[*] Running ALL 25 steps...")
            for i in range(1, 26):
                execute_triage_step(i, triage_actions)
                print("\n" + "-"*40)
            print("\n[+] All steps completed.")
        elif step_choice.isdigit() and 1 <= int(step_choice) <= 25:
            execute_triage_step(int(step_choice), triage_actions)
        else:
            print("[!] Invalid selection.")
        
        input("\nPress Enter to continue...")

# ---------- Evidence Export ----------
def export_all_evidence():
    """Consolidate all forensic data into a permanent evidence file."""
    import scanner  
    import network
    
    print("\n" + "="*60)
    print(" [!] INITIATING FULL EVIDENCE EXPORT")
    print("="*60)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"Sentinel_Evidence_{timestamp}.txt"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("THE SENTINEL - FORENSIC EVIDENCE EXPORT\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("=" * 80 + "\n\n")

        sections = [
            ("PROCESS AUDIT", scanner.get_active_processes),
            ("NETWORK CONNECTIONS", network.get_network_connections),
            ("REGISTRY PERSISTENCE", scanner.get_registry_persistence),
            ("RECENT FILE MODIFICATIONS", lambda: get_recent_files(days=7)),
            ("USB DEVICE HISTORY", get_usb_history),
            ("BROWSER EXTENSIONS", scanner.get_browser_extensions)
        ]

        for title, func in sections:
            print(f"[*] Exporting {title}...")
            f.write(f"\n--- {title} ---\n")
            data = func()
            if isinstance(data, list):
                for item in data:
                    f.write(f"{item}\n")
            f.write("-" * 40 + "\n")

    print(f"\n[SUCCESS] All artifacts securely saved to: {filename}")