import utils
import scanner
import network
import forensics
import subprocess
import os
import sys
import time
import ctypes
from tabulate import tabulate

# --- TERMINAL OPTIMIZATION CORE ---
def configure_terminal():
    """Adjusts terminal buffer for infinite scrolling and maximizes window."""
    if sys.platform == "win32":
        # Set Window Title
        os.system('title AEGIS-X FORENSIC CORE')
        
        # Initial Window Size (Width=130, Height=40)
        os.system('mode con: cols=130 lines=40')

        # Increase Buffer Size (Scrollback history to 2000 lines)
        kernel32 = ctypes.windll.kernel32
        hOut = kernel32.GetStdHandle(-11) # STD_OUTPUT_HANDLE
        # (Height << 16) | Width -> 2000 lines high, 130 wide
        buf_info = ctypes.c_uint32((2000 << 16) | 130) 
        kernel32.SetConsoleScreenBufferSize(hOut, buf_info)

        # Maximize Window
        user32 = ctypes.windll.user32
        hWnd = kernel32.GetConsoleWindow()
        if hWnd:
            user32.ShowWindow(hWnd, 3) # 3 = SW_MAXIMIZE

def log_to_file(title, table_data, headers):
    if not os.path.exists("logs"): 
        os.makedirs("logs")
    with open("logs/sentinel_session_log.txt", "a", encoding="utf-8") as f:
        f.write(f"\n[ {utils.get_timestamp()} ] - {title}\n")
        f.write(tabulate(table_data, headers=headers, tablefmt="grid") + "\n")

def show_banner():
    configure_terminal() # Apply the scroll and size fix
    utils.clear_screen()
    
    print("=" * 125)
    print(r"""
    █████╗ ███████╗ ██████╗ ██╗███████╗    ██╗  ██╗
    ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ╚██╗██╔╝
    ███████║█████╗  ██║  ███╗██║███████╗     ╚███╔╝ 
    ██╔══██║██╔══╝  ██║   ██║██║╚════██║     ██╔██╗ 
    ██║  ██║███████╗╚██████╔╝██║███████║    ██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝    ╚═╝  ╚═╝
    """)
    print(" " * 25 + "PROJECT: AEGIS-X | CYBER FORENSIC ANALYTICS")
    print(" " * 25 + "[ STATUS: ACTIVE INVESTIGATION | LEVEL: KERNEL ]")
    print("=" * 125)

def stream_log(message, type="info"):
    """Prints messages line by line for that professional terminal feel."""
    prefix = "[*]"
    if type == "warn": prefix = "[!]"
    if type == "success": prefix = "[+]"
    if type == "process": prefix = "    [>]"
    
    print(f"{prefix} {message}")
    time.sleep(0.02) # Faster streaming for high-volume data

def run_analyst_shell():
    """Persistent PowerShell environment for deep manual forensics."""
    print("\n" + "!" * 60)
    print(" [!] EMERGENCY ANALYST SHELL - DIRECT POWERSHELL BYPASS")
    print(" [!] Type 'help' for FBI-standard commands, 'back' to return.")
    print("!" * 60)

    while True:
        cmd = input("SENTINEL-ID# ")

        if cmd.lower() in ['back', 'exit', 'quit']:
            break

        if cmd.lower() == 'help':
            print("\n--- FBI FIELD MANUAL: RECOMMENDED COMMANDS ---")
            print("[NET] Get-NetTCPConnection | Where State -eq 'Established' | Sort RemoteAddress")
            print("[SIG] Get-ChildItem C:\\Windows\\System32\\*.exe | Get-AuthenticodeSignature | Where Status -ne 'Valid'")
            print("[TIM] ls C:\\Windows\\System32\\*.exe | sort LastWriteTime -Descending | select name, LastWriteTime -First 10")
            print("[SVC] tasklist /svc (Map Services to PIDs)")
            print("[DNS] Get-DnsClientCache | Select EntryName, Data")
            print("[LOG] Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 20")
            print("-" * 60 + "\n")
            continue

        try:
            result = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-Command", cmd],
                capture_output=True, text=True, shell=True
            )
            if result.stdout:
                print(f"\n{result.stdout}")
            if result.stderr:
                print(f"\n[!] ERROR: {result.stderr}")
        except Exception as e:
            print(f"[-] Execution Failed: {e}")

def main_menu():
    while True:
        show_banner()
        print("\n[1] QUICK TRIAGE      (Process Audit, Services, Tasks, Drivers)")
        print("[2] NETWORK SNIFFER    (Live IP Tracking, Geo-IP, DNS/ARP)")
        print("[3] PERSISTENCE HUNT  (Registry, Startup, WMI, Browser Extensions)")
        print("[4] FILE SYSTEM FORENSICS (Recent Files, Prefetch, ADS, USB)")
        print("[5] LOG ANALYSIS      (Event Logs: Security, PowerShell, System)")
        print("[6] MANUAL ANALYST    (Interactive Deep-Dive PowerShell)")
        print("[7] TACTICAL PURGE    (Terminate PID & Wipe Executable)")
        print("[8] EVIDENCE EXPORT   (Save All Findings to Timestamped File)")
        print("[9] FBI TACTICAL AUDIT (10-Step Automated PowerShell Audit)")
        print("[10] BROWSER INTEGRITY AUDIT (Extension Scanning & Integrity)")
        print("[11] LIVE RESPONSE TRIAGE (25-Step Critical Incident Protocol)")
        print("[0] EXIT SECURELY")

        choice = input("\nSELECT ACTION# ")

        if choice == '1':
            stream_log("Initializing Fast Triage Protocol...")
            data = {}

            stream_log("Analyzing process signatures and paths...", "info")
            data['processes'] = scanner.get_active_processes()
            for p in data['processes'][:10]:
                stream_log(f"Analyzed PID {p['pid']}: {p['name']} -> {p['status']}", "process")

            stream_log("Building process tree relationship...", "info")
            data['process_tree'] = scanner.get_process_tree()

            stream_log("Querying system services...", "info")
            data['services'] = scanner.get_services()

            stream_log("Enumerating scheduled tasks...", "info")
            data['tasks'] = scanner.get_scheduled_tasks()

            stream_log("Loading kernel driver list...", "info")
            data['drivers'] = scanner.get_drivers()
            
            stream_log("Gathering Process Data...")
            procs = scanner.get_active_processes() 
            headers = ["PID", "Name", "Status"]
            table_data = [[p['pid'], p['name'], p['status']] for p in procs]
            log_to_file("ACTIVE PROCESSES", table_data, headers)
            
            # Display summaries
            print("\n--- PROCESSES (Top 20) ---")
            table = [[p['pid'], p['name'], p['status']] for p in data['processes'][:20]]
            print(tabulate(table, headers=["PID", "Name", "Signature/Path Status"], tablefmt="grid"))

            print("\n--- SERVICES (Non-Microsoft, Running) ---")
            svc_table = [[s['name'], s['display_name'], s['binary_path'], s['start_type'], s['state']] 
                         for s in data['services'] if s['state'] == 'Running' and 'microsoft' not in s['name'].lower()]
            print(tabulate(svc_table, headers=["Name", "Display", "Binary", "Start", "State"], tablefmt="grid"))

            input("\nPress Enter to view Process Tree...")
            print("\n--- PROCESS TREE ---")
            for tree_line in data['process_tree']:
                print(tree_line)
                time.sleep(0.02)
            input("\nPress Enter to return to menu...")

        elif choice == '2':
            stream_log("Mapping live network activity and Geo-IP data...")
            data = {}

            stream_log("Intercepting established connections...", "info")
            data['established'] = network.get_network_connections()
            for c in data['established'][:5]:
                stream_log(f"Active Connection: {c['ip']} ({c['country']}) -> {c['name']}", "process")

            stream_log("Scanning listening ports...", "info")
            data['listening'] = network.get_listening_ports()

            stream_log("Extracting DNS cache...", "info")
            data['dns'] = network.get_dns_cache()

            stream_log("Reading ARP table...", "info")
            data['arp'] = network.get_arp_table()

            stream_log("Acquiring routing table...", "info")
            data['route'] = network.get_routing_table()
            
            stream_log("Mapping Network...")
            conns = network.get_network_connections()
            headers = ["PID", "IP", "Country"]
            table_data = [[c['pid'], c['ip'], c['country']] for c in conns]
            log_to_file("NETWORK CONNECTIONS", table_data, headers)

            if data['established']:
                print("\n--- ESTABLISHED CONNECTIONS ---")
                table = [[c['pid'], c['name'], c['ip'], c['country'], c['owner']] for c in data['established']]
                print(tabulate(table, headers=["PID", "Name", "Remote IP", "Country", "ISP/Owner"], tablefmt="grid"))

            if data['listening']:
                print("\n--- LISTENING PORTS ---")
                l_table = [[l['pid'], l['name'], l['port'], l['protocol']] for l in data['listening']]
                print(tabulate(l_table, headers=["PID", "Process", "Port", "Protocol"], tablefmt="grid"))

            input("\nPress Enter to continue...")

        elif choice == '3':
            stream_log("Hunting for persistence mechanisms...")
            data = {}

            stream_log("Scanning Registry RunKeys (HKLM/HKCU)...", "info")
            data['registry'] = scanner.get_registry_persistence()
            
            stream_log("Auditing Startup folders...", "info")
            data['startup_folders'] = scanner.get_startup_folders()

            stream_log("Querying WMI Event Subscriptions...", "info")
            data['wmi'] = scanner.get_wmi_persistence()

            stream_log("Checking browser extension integrity...", "info")
            data['browser'] = scanner.get_browser_extensions()
            
            # Formatting table_data for persistence logging
            headers = ["Type", "Details"]
            table_data = [["Registry", f"{len(data['registry'])} items"], ["WMI", f"{len(data['wmi'])} items"]]
            log_to_file("FORENSIC ARTIFACTS", table_data, headers)

            if data['registry']:
                print("\n--- REGISTRY PERSISTENCE ---")
                for item in data['registry']:
                    print(f"[{item['hive']}\\{item['key']}] {item['name']} -> {item['value']}")
                    time.sleep(0.02)

            if data['startup_folders']:
                print("\n--- STARTUP FOLDER ITEMS ---")
                for f in data['startup_folders']:
                    print(f"[!] Found: {f}")

            input("\nPress Enter to continue...")

        elif choice == '4':
            stream_log("Commencing File System Forensics...")
            data = {}

            stream_log("Scanning for recently modified system files...", "info")
            data['recent'] = forensics.get_recent_files()

            stream_log("Parsing Windows Prefetch cache...", "info")
            data['prefetch'] = forensics.get_prefetch_files()

            stream_log("Detecting Alternate Data Streams (ADS)...", "info")
            data['ads'] = forensics.get_alternate_data_streams()

            stream_log("Recovering USB device connection history...", "info")
            data['usb'] = forensics.get_usb_history()

            # Truncating path for better log visibility
            headers = ["Time", "Path"]
            table_data = [[f['last_modified'], f['path'][:70]] for f in data['recent'][:50]]
            log_to_file("FILE SYSTEM FORENSICS", table_data, headers)

            if data['recent']:
                print("\n--- RECENT FILES (Key Directories) ---")
                for f in data['recent'][:30]:
                    print(f"[{f['last_modified']}] {f['path']}")
                    time.sleep(0.01)

            input("\nPress Enter to continue...")

        elif choice == '5':
            stream_log("Extracting Windows Event Logs for analysis...")
            data = {}

            stream_log("Parsing Security Logs (Event ID 4688)...", "info")
            data['security_4688'] = forensics.get_event_logs('Security', 4688, 50)

            stream_log("Analyzing PowerShell Operational Logs (Event ID 4104)...", "info")
            data['powershell'] = forensics.get_event_logs('Windows PowerShell', 4104, 50)

            stream_log("Collecting System Errors...", "info")
            data['system_errors'] = forensics.get_event_logs('System', None, 50, level='Error')

            headers = ["Time", "Log Message"]
            table_data = [[ev['time'], ev['message'][:100]] for ev in data['security_4688']]
            log_to_file("LOG ANALYSIS", table_data, headers)

            if data['security_4688']:
                print("\n--- RECENT PROCESS CREATIONS (ID 4688) ---")
                for ev in data['security_4688']:
                    print(f"[{ev['time']}] {ev['message'][:110]}...")
                    time.sleep(0.01)

            input("\nPress Enter to continue...")

        elif choice == '6':
            run_analyst_shell()

        elif choice == '7':
            pid_input = input("\nENTER PID TO TERMINATE (or 'q'): ")
            if pid_input.lower() != 'q' and pid_input.isdigit():
                target_pid = int(pid_input)
                stream_log(f"Targeting PID {target_pid} for neutralization...")
                
                all_procs = scanner.get_active_processes()
                target_path = next((p['path'] for p in all_procs if p['pid'] == target_pid), None)

                if target_path and os.path.exists(target_path):
                    file_hash = utils.hash_file(target_path)
                    stream_log(f"Evidence Hash (SHA256): {file_hash}", "success")

                success, msg = utils.terminate_process(target_pid)
                stream_log(msg, "success" if success else "warn")

                if success and target_path:
                    confirm = input(f"CONFIRM TACTICAL WIPE: Delete {target_path}? (y/n): ")
                    if confirm.lower() == 'y':
                        s, m = utils.delete_suspicious_file(target_path)
                        stream_log(m, "success" if s else "warn")
            input("\nPress Enter to return...")

        elif choice == '8':
            stream_log("Packing evidence into forensic export file...")
            forensics.export_all_evidence()
            stream_log("Export complete. Check the timestamped file.", "success")
            input("\nPress Enter to continue...")

        # ===== NEW OPTIONS 9, 10, 11 =====
        elif choice == '9':
            forensics.run_tactical_audit_menu()
            input("\nPress Enter to return to main menu...")

        elif choice == '10':
            forensics.audit_browser_internals()
            input("\nPress Enter to return to main menu...")

        elif choice == '11':
            forensics.run_live_response_triage()
            input("\nPress Enter to return to main menu...")

        elif choice == '0':
            stream_log("Closing secure session. Vigilance is your best defense.", "warn")
            time.sleep(1)
            break

if __name__ == "__main__":
    utils.initialize_system()
    main_menu()