

# Remote Recon Automation Tool

## Overview

**Remote Recon Automation Tool** is a Bash script that automates anonymous network reconnaissance on a target by leveraging a remote VPS as a middleman. It is designed for privacy-focused users who want to perform Nmap and Whois scans through a remote server, with local anonymization measures such as MAC address spoofing, hostname suppression, DNS query blocking, and Tor-based routing (via [Nipe](https://github.com/htrgouvea/nipe)).

> **Author:** Radostin Tonev  
> **Version:** 1.0  
> **Date:** 13/07/2025

---

## Features

- **Automatic installation** of required tools on both local and remote machines.
- **MAC address spoofing** and hostname suppression for local network anonymity.
- **Disables local DNS queries** to prevent DNS leaks.
- **Tor-based proxy chaining** using Nipe to anonymize all outgoing traffic.
- **Firewall rules** to block all non-Tor traffic (handled by Nipe).
- **SSH connection** to a remote server for executing Nmap and Whois scans.
- **Exports scan results** and audit logs to local files.
- **Cleans up traces** on the remote machine after scans.
- **Restores all local configurations** on exit.

---

## Requirements

- **Operating System:** Linux (Debian/Ubuntu recommended)
- **Privileges:** Must be run as root (or with `sudo`)
- **Local Dependencies:**  
  - `sshpass`
  - `cpanminus` (`cpanm`)
  - `git`
  - `macchanger`
  - `isc-dhcp-client` (`dhclient`)
  - `perl`
  - [Nipe](https://github.com/htrgouvea/nipe) (installed automatically)
- **Remote Dependencies:**  
  - `nmap`
  - `whois`
- **Remote Server:**  
  - SSH access (username, password, and IP required)

---

## Usage

1. **Clone or download this script to your Linux machine.**

2. **Make the script executable:**
    ```bash
    chmod +x remote_control_final.sh
    ```

3. **Run the script as root:**
    ```bash
    sudo ./remote_control_final.sh
    ```

4. **Follow the prompts:**
    - Enter remote server SSH details.
    - Enter the target address to scan.
    - Optionally customize Nmap and Whois options.

5. **Results:**
    - Scan results and logs are saved in the current working directory.

---

## What the Script Does

1. **Initializes** and checks for root privileges.
2. **Installs dependencies** on the local machine.
3. **Spoofs MAC address** and disables hostname leaks (if enabled).
4. **Disables DNS queries** locally (if enabled).
5. **Activates Nipe** to route all traffic through Tor.
6. **Performs anonymity checks** (including DNS leak test).
7. **Prompts for remote server details** and connects via SSH.
8. **Installs dependencies** on the remote server.
9. **Executes Whois and Nmap scans** on the target from the remote server.
10. **Cleans up traces** on the remote server.
11. **Restores all local configurations** and exits.

---

## Output Files

- `recon_log_<timestamp>.txt` — Audit log of all actions.
- `whois_results_<timestamp>.txt` — Whois scan results.
- `nmap_results_<timestamp>.txt` — Nmap scan results.

---

## Notes

- **Educational Use Only:**  
  This script is intended for educational and authorized security testing purposes.  
  **Do not scan targets without explicit permission.**

- **Network Disruption:**  
  Changing MAC address and disabling DNS may temporarily disrupt your network connection.

- **Tor/Nipe:**  
  All traffic is routed through Tor while the script is running.  
  Nipe and Tor are stopped and all settings are restored on exit.

---

## Troubleshooting

- If Nipe fails to start, ensure all Perl dependencies are installed.
- If your network connection drops after MAC spoofing, ensure DHCP lease is renewed. Note: if you are running the script from VirtualBox VM MAC address spoofing must be disabled.
- Always run the script as root.

---

## License

MIT License

---

## Credits

- [Nipe](https://github.com/htrgouvea/nipe) by HTRGouvea
