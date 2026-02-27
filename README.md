# 🛡️ AEGIS-X Forensic Core

**AEGIS-X** is a professional-grade Live Forensic Triage tool designed for Windows environments. It enables cybersecurity researchers, incident responders, and system administrators to detect suspicious activities, identify persistence mechanisms, and track network threats in real-time.

---

## ✨ Key Features

* **Process Auditing:** Deep-scans active processes, validates **Digital Signatures (Authenticode)**, and flags binaries running from suspicious or hidden paths.
* **Network Triage:** Monitors active TCP/UDP connections and integrates **Geo-IP Intelligence** (Country, City, ISP, and ASN) to pinpoint unauthorized remote communications.
* **Persistence Detection:** Automatically audits Windows Registry "Run" keys, **WMI Event Subscriptions**, and Startup folders to find hidden malware auto-starts.
* **Live Incident Response:** Allows operators to instantly terminate suspicious processes and perform a **"Tactical Wipe"** (secure deletion) of malicious binaries.
* **Browser Integrity:** Scans Chrome and Edge profiles to identify potentially malicious or unauthorized browser extensions.
* **Forensic Export:** Generates comprehensive, timestamped evidence reports (`.txt`) for documentation and further analysis.

---

## 🚀 Installation & Setup

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/Jayasankha-dev/AEGIS-X-Forensic-Core.git](https://github.com/Jayasankha-dev/AEGIS-X-Forensic-Core.git)
    cd AEGIS-X-Forensic-Core
    ```

2.  **Install Dependencies:**
    Ensure you have Python 3.10+ installed. Install the required libraries via pip:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Geo-IP Configuration:**
    To enable the mapping features, place your `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` files inside the `/database` directory.

---

## 🛠️ Usage

> [!IMPORTANT]
> **Administrator Privileges Required:** AEGIS-X requires high-level system access to audit protected registry hives and system processes. Please run your Terminal or CMD as **Administrator**.

```bash
python main.py
