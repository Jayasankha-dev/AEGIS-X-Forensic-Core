import psutil
import geoip2.database
import os
import subprocess
import json
import time

# Paths to GeoIP Databases
CITY_DB_PATH = os.path.join("database", "GeoLite2-City.mmdb")
ASN_DB_PATH = os.path.join("database", "GeoLite2-ASN.mmdb")

def get_ip_details(ip_address):
    """Provides Geo-IP and ISP data for a given IP."""
    if ip_address in ("127.0.0.1", "::1") or ip_address.startswith(("192.168.", "10.", "172.16.")):
        return "Local Network", "Internal", "Private Range"
    
    country, city, owner = "Unknown", "Unknown", "Unknown"
    try:
        if os.path.exists(CITY_DB_PATH):
            with geoip2.database.Reader(CITY_DB_PATH) as reader:
                response = reader.city(ip_address)
                country = response.country.name if response.country.name else "Unknown"
                city = response.city.name if response.city.name else "N/A"
        if os.path.exists(ASN_DB_PATH):
            with geoip2.database.Reader(ASN_DB_PATH) as asn_reader:
                asn_response = asn_reader.asn(ip_address)
                owner = asn_response.autonomous_system_organization if asn_response.autonomous_system_organization else "Unknown"
    except Exception:
        pass
    return country, city, owner

def get_network_connections():
    """Fetches established connections and streams them to the terminal."""
    connections_list = []
    print("\n[>] INTERCEPTING ESTABLISHED TCP/IP STREAMS...")
    
    for conn in psutil.net_connections(kind='inet'):
        raddr = getattr(conn, 'raddr', None)
        if conn.status == 'ESTABLISHED' and raddr and raddr.ip:
            remote_ip = raddr.ip
            pid = conn.pid
            
            try:
                if pid:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                else:
                    proc_name = "System/Kernel"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "Hidden/Unknown"

            country, city, owner = get_ip_details(remote_ip)
            
            # Real-time Stream Output
            print(f"    [*] Found Connection: {proc_name:<15} | Remote: {remote_ip:<15} | Origin: {country}")
            time.sleep(0.05) # Adds that terminal scrolling effect

            connections_list.append({
                "pid": pid if pid else 0,
                "name": proc_name,
                "ip": remote_ip,
                "country": country,
                "city": city,
                "owner": owner
            })
    return connections_list

def get_listening_ports():
    """Identifies all local ports in a LISTEN state."""
    listening = []
    print("\n[>] SCANNING LOCAL INTERFACES FOR LISTENING PORTS...")
    
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            pid = conn.pid
            try:
                if pid:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                else:
                    proc_name = "System"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "Unknown"
            
            laddr = conn.laddr
            port = laddr.port if laddr else 0
            protocol = 'TCP' if conn.type == 1 else 'UDP'
            
            print(f"    [*] Open Port: {port:<5} | Protocol: {protocol:<4} | Process: {proc_name}")
            
            listening.append({
                "pid": pid if pid else 0,
                "name": proc_name,
                "port": port,
                "protocol": protocol
            })
    return listening

def get_dns_cache():
    """Extracts Windows DNS Client Cache via PowerShell."""
    print("\n[>] DUMPING DNS RESOLVER CACHE...")
    cmd = "Get-DnsClientCache | Select EntryName, Data | ConvertTo-Json"
    try:
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, shell=True, timeout=10
        )
        if not result.stdout:
            return []
            
        data = json.loads(result.stdout)
        if isinstance(data, dict):
            data = [data]
            
        for entry in data[:15]: # Show first 15 entries live
            print(f"    [DNS] Resolving: {entry.get('EntryName', 'Unknown')[:30]:<30} -> {entry.get('Data', 'N/A')}")
            time.sleep(0.02)
            
        return data
    except Exception as e:
        print(f"    [!] DNS Cache Export Failed: {e}")
        return []

def get_arp_table():
    """Retrieves the Address Resolution Protocol (ARP) table."""
    print("\n[>] RETRIEVING ARP NEIGHBOR TABLE...")
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, shell=True)
        lines = result.stdout.split('\n')
        entries = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 3 and '.' in parts[0]:
                entry = {'ip': parts[0], 'mac': parts[1], 'type': parts[2] if len(parts) > 2 else ''}
                entries.append(entry)
                # Live log
                if "192.168" in entry['ip'] or "10." in entry['ip']:
                    print(f"    [ARP] Device Discovered: {entry['ip']:<15} at {entry['mac']}")
        return entries
    except:
        return []

def get_routing_table():
    """Parses the IPv4 Routing Table."""
    print("\n[>] ACQUIRING IPV4 ROUTING HIVE...")
    try:
        result = subprocess.run(['route', 'print', '-4'], capture_output=True, text=True, shell=True)
        lines = result.stdout.split('\n')
        routes = []
        capture = False
        for line in lines:
            if 'Network Destination' in line:
                capture = True
                continue
            if capture and line.strip() and not line.startswith('='):
                parts = line.split()
                if len(parts) >= 5:
                    routes.append({
                        'destination': parts[0],
                        'netmask': parts[1],
                        'gateway': parts[2],
                        'interface': parts[3],
                        'metric': parts[4] if len(parts) > 4 else ''
                    })
        print(f"    [+] Successfully mapped {len(routes)} active routes.")
        return routes
    except:
        return []