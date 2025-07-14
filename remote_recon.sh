#!/bin/bash

# --- Configuration ---
DISABLE_DNS=true            # Set to true to disable DNS queries on the local machine
MAC_SPOOFING_ENABLED=true   # Set to true to enable MAC address spoofing

# --- Globals ---
WORKING_DIR=$(pwd)  # Store the current working directory
LOG_FILE="$WORKING_DIR/recon_log_$(date +%Y%m%d_%H%M%S).txt"
WHOIS_FILE="$WORKING_DIR/whois_results_$(date +%Y%m%d_%H%M%S).txt"
NMAP_FILE="$WORKING_DIR/nmap_results_$(date +%Ym%d_%H%M%S).txt"
INTERFACE=""
OLD_MAC_ADDRESS=""

DEFAULT_REMOTE_SSH_PORT=22

# --- Default NMAP and Whois Configuration ---
DEFAULT_NMAP_OPTIONS="-Pn -sV"      # Default options for nmap command
DEFAULT_WHOIS_OPTIONS=""            # Default options for whois command
NMAP_OPTIONS="$DEFAULT_NMAP_OPTIONS"  # Use the default options unless overridden   
WHOIS_OPTIONS="$DEFAULT_WHOIS_OPTIONS"  # Use the default options unless overridden 

# Backup file for resolv.conf
RESOLV_CONF_BACKUP="/tmp/resolv.conf.bak_$(date +%Y%m%d_%H%M%S)"

# --- Logging Function ---
# Function to log messages to the console and a log file
log_message() {
    local message="$1"
    echo "$(date +%Y-%m-%d_%H:%M:%S) - $message" | tee -a "$LOG_FILE"
}

# --- Check for root privileges ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "ERROR: This script must be run as root. Please use 'sudo' or switch to the root user."
        exit 1
    fi
}

# --- Show Header ---
show_header() {
    echo "===================================================================================="
    echo ""
    echo "  Remote Recon Automation Tool"
    echo "  Version: 1.0"
    echo "  Author: Radostin Tonev"
    echo "  Date: 13/07/2025"
    echo "  Description: This script automates anonymus network reconnaissance on a target "
    echo "  leveraging remote VPS as a middleman."
    echo ""
    echo "  It will perform the following actions:"
    echo "  1. Automatically install required applications on the local and remote machines."
    echo "  2. Spoof MAC address and Hostname for anonymity within local network."
    echo "  3. Disable local DNS queries."
    echo "  4. Activate Tor-based proxy-chain for connecting to remote server."
    echo "  5. Block all traffic except Tor using firewall rules (handled by Nipe)."
    echo "  6. Connect to the remote server via SSH and execute scans on specified target."
    echo "  7. Export scan results and audit logs."
    echo "  8. Clean up traces on the remote machine so even if it is compromised there will"
    echo "     be no traces of the scans."
    echo "" 
    echo "  The tool currently suports Nmap and Whois scans." 
    echo "" 
    echo "  Note: This script is intended for educational purposes only. Use responsibly and"
    echo "  ensure you have permission to scan the target systems."
    echo ""
    echo "===================================================================================="
    echo ""
    echo ""
}


# --- Disable DNS queries on the local machine ---
disable_dns() {
    log_message "Disabling local DNS queries by backing up and modifying /etc/resolv.conf..."
    if [ -f "/etc/resolv.conf" ]; then
        sudo cp /etc/resolv.conf "$RESOLV_CONF_BACKUP"
        if [ $? -eq 0 ]; then
            log_message "Original /etc/resolv.conf backed up to $RESOLV_CONF_BACKUP"
            # Pointing to loopback to effectively disable external DNS resolution
            echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf > /dev/null
            if [ $? -eq 0 ]; then
                log_message "Local DNS queries disabled (resolv.conf set to 127.0.0.1)."
            else
                log_message "ERROR: Failed to modify /etc/resolv.conf. DNS may not be disabled."
            fi
        else
            log_message "ERROR: Failed to backup /etc/resolv.conf. DNS may not be disabled safely."
        fi
    else
        log_message "WARNING: /etc/resolv.conf not found. Cannot disable DNS queries."
    fi
}

# Restore original DNS configuration on the local machine
restore_dns() {
    log_message "Restoring original local DNS configuration..."
    if [ -f "$RESOLV_CONF_BACKUP" ]; then
        sudo cp "$RESOLV_CONF_BACKUP" /etc/resolv.conf
        if [ $? -eq 0 ]; then
            log_message "Original /etc/resolv.conf restored."
            sudo rm -f "$RESOLV_CONF_BACKUP" # Clean up backup file
            log_message "DNS backup file removed."
        else
            log_message "ERROR: Failed to restore /etc/resolv.conf from backup. Manual intervention may be required."
        fi
    else
        log_message "WARNING: DNS backup file not found. Cannot restore original /etc/resolv.conf."
    fi
}

# Restore original confirugration on local machine
restore_configs() {
    # Restore dhclient configuration
    if [ -f /etc/dhcp/dhclient.conf ]; then
        if grep -q "#send host-name" /etc/dhcp/dhclient.conf; then
            sudo sed -i 's/#send host-name/send host-name/g' /etc/dhcp/dhclient.conf
            log_message "Restored dhclient configuration to default."
        else
            log_message "dhclient is already with default settings."
        fi
    else
        log_message "WARNING: /etc/dhcp/dhclient.conf not found. Cannot restore dhclient configuration."
    fi

    # Restore DNS configuration
    if [ "$DISABLE_DNS" == true ]; then
        restore_dns
    else
        log_message "DNS queries were not disabled, skipping restoration."
    fi   

    # Restore MAC address if MAC spoofing was enabled
    if [ "$MAC_SPOOFING_ENABLED" == true ] && [ -n "$OLD_MAC_ADDRESS" ]; then
        sudo macchanger -p $INTERFACE &> /dev/null       
        log_message "Original MAC address restored to $OLD_MAC_ADDRESS."
    else
        log_message "MAC spoofing was not enabled, skipping MAC address restoration."
    fi                               
    
    # Stop Nipe
    sudo perl nipe.pl stop
    log_message "Nipe stopped. Tor circuit is no longer active."
}

# --- Check and install required applications on the local machine ---
install_dependencies() {
    log_message "Checking and installing required dependencies on local machine..."
    local packages=("sshpass" "cpanm" "git" "macchanger" "dhclient")
    local installed_count=0

    for pkg in "${packages[@]}"; do
        if ! command -v "$pkg" &> /dev/null; then
            log_message "$pkg is not installed locally. Attempting to install..."
            # Check if apt-get is available
            if command -v apt &> /dev/null; then
                # Update package names for compatibility
                if [[ $pkg == "cpanm" ]]; then
                    pkg="cpanminus"
                elif [[ $pkg == "dhclient" ]]; then
                    pkg="isc-dhcp-client"
                fi

                # Install the package
                sudo apt update -y && sudo apt install -y "$pkg"
                if [ $? -eq 0 ]; then
                    log_message "$pkg installed successfully locally."
                    installed_count=$((installed_count + 1))
                else
                    log_message "ERROR: Failed to install $pkg locally. Please install it manually."
                    exit 1
                fi
            else
                log_message "ERROR: apt not found on local machine. Please install $pkg manually."
                exit 1
            fi
        else
            log_message "$pkg is already installed locally."
            installed_count=$((installed_count + 1))
        fi
    done

    if [ "$installed_count" -eq "${#packages[@]}" ]; then
        log_message "All required APT dependencies are already installed on local machine."
    fi

    # Configure dhclient not to leak hostname in DHCP requests
    if [ $MAC_SPOOFING_ENABLED == true ]; then
        if [ -f /etc/dhcp/dhclient.conf ]; then
            if ! grep -q "#send host-name" /etc/dhcp/dhclient.conf; then
                sudo sed -i 's/send host-name/#send host-name/g' /etc/dhcp/dhclient.conf
                log_message "Configured dhclient to not send hostname."
            else
                log_message "dhclient is already configured to not send hostname."
            fi
        else
            log_message "WARNING: /etc/dhcp/dhclient.conf not found. Cannot configure dhclient."
        fi
    fi

    # Install Nipe for Tor chaining of the traffic
    install_nipe
    if [ $? -eq 0 ]; then
        log_message "Nipe installation completed successfully."
    else
        echo "ERROR: Nipe installation failed. Please check logs for details."
        exit 1
    fi
    echo ""
}

# --- Install Nipe ---
install_nipe() {
    local nipe_dir="$HOME/nipe" # Installation directory for Nipe
    
    # If nipe_status.txt contetnts is true then Nipe is already installed
    if [ -f "$nipe_dir/nipe_status.txt" ] && grep -q "true" "$nipe_dir/nipe_status.txt"; then
        log_message "Nipe is already installed and configured in $nipe_dir."
        cd "$nipe_dir"
        return 0
    fi

    echo "Starting Nipe installation..."

    # Clone the Nipe repository
    if [ -d "$nipe_dir" ]; then
        echo "Nipe directory '$nipe_dir' already exists. Skipping cloning."
    else
        echo "Cloning Nipe repository into '$nipe_dir'..."
        if ! git clone https://github.com/htrgouvea/nipe "$nipe_dir"; then
            echo "Error: Failed to clone Nipe repository. Please check your internet connection or GitHub access."
            return 1
        fi
        echo "Nipe repository cloned successfully."
    fi

    # Navigate to Nipe directory and install dependencies
    if cd "$nipe_dir"; then
        echo "Navigating to Nipe directory and installing Perl dependencies..."
        # Using sudo for cpanm as it might need to install modules globally
        if ! sudo cpanm --installdeps .; then
            echo "Error: Failed to install Nipe dependencies. Please check the output above for details."
            return 1
        fi
        
        if ! sudo perl nipe.pl install; then
            return 1
        else 
            echo "true" > nipe_status.txt
        fi

        # Make nipe.pl executable
        echo "Making nipe.pl executable..."
        sudo chmod +x nipe.pl
        echo "nipe.pl is now executable."

        sleep 3 # Give some time for the changes to take effect
    else
        log_message "Error: Failed to navigate to Nipe directory '$nipe_dir'. Aborting installation."
        return 1
    fi

    return 0
}

# --- Check Nipe status ---
check_nipe_status() {
    local nipe_status=$(sudo perl nipe.pl status 2>&1)
    if echo "$nipe_status" | grep -q "Status: true"; then
        return 0
    else
        return 1
    fi
}

# --- Activate Nipe for TOR routing ---
tor_circuit_refresh_attempts=0;
tor_circuit_refreshed=false;
activate_nipe() {
    check_nipe_status
    if [ $? -eq 0 ]; then
        # Check if we need to refresh the Tor circuit
        if [ $tor_circuit_refreshed ]; then
            log_message "Nipe circuit has been refreshed."
            return 0
        fi

        if [ $tor_circuit_refresh_attempts -lt 3 ]; then
            log_message "Restarting Tor circuit to refresh connection... Attempt #$((tor_circuit_refresh_attempts + 1))"
            sudo perl nipe.pl restart 2>&1
            if [ $? -eq 0 ]; then
                log_message "Tor circuit refreshed successfully."
                tor_circuit_refreshed=true
            else
                tor_circuit_refresh_attempts=$((tor_circuit_refresh_attempts + 1))
                sleep 5 # Wait before retrying
                log_message "Failed to refresh Tor circuit. Retrying..."
                activate_nipe            
            fi
        else
            log_message "Maximum Tor circuit refresh attempts reached. Failed to refresh Tor circuit. Exiting..."
            return 1
        fi
    else
        log_message "Nipe is not active. Attempting to start Nipe..."
        nipe_start_output=$(sudo perl nipe.pl restart 2>&1)
        if [ $? -eq 0 ]; then
            sleep 5 # Give Nipe some time to establish connection
            log_message "Nipe started successfully."
        else
            log_message "ERROR: Failed to start Nipe. Output: $nipe_start_output"
            return 1
        fi
    fi
    return 0
}

# --- Change MAC address for local anonymity ---
change_mac_address() {
    log_message "Attempting to change MAC address for local anonymity..."

    # Find an active non-loopback network interface
    # Exclude docker and bridge interfaces which might not be physical
    local interface=$(ip -o link show | awk -F': ' '$2 != "lo" && $2 !~ /^docker/ && $2 !~ /^br-/ && $2 !~ /^veth/ {print $2}' | head -n 1)

    if [ -z "$interface" ]; then
        log_message "WARNING: No suitable network interface found to change MAC address."
        return 1
    fi

    log_message "Found interface: $interface. Changing MAC address..."
    INTERFACE="$interface" # Store the interface for later use

    # Store the current MAC address of the selected adapter for later use
    OLD_MAC_ADDRESS=$(ip link show "$interface" | awk '/ether/ {print $2}')

    # Bring down the interface, change MAC, then bring it up
    sudo ip link set "$interface" down
    if [ $? -ne 0 ]; then
        log_message "ERROR: Failed to bring down interface $interface. MAC change aborted."
        return 1
    fi

    sudo macchanger -r "$interface" &> /dev/null
    if [ $? -ne 0 ]; then
        log_message "ERROR: Failed to change MAC address for $interface. Please check permissions."
        sudo ip link set "$interface" up # Try to bring it back up even if MAC change failed
        return 1
    fi

    sudo ip link set "$interface" up
    if [ $? -ne 0 ]; then
        log_message "ERROR: Failed to bring up interface $interface after MAC change. Manual intervention may be required."
        return 1
    fi

    log_message "Attempting to renew DHCP lease to apply new MAC address..."
    sudo dhclient "$INTERFACE"   # Renew DHCP lease to apply new MAC address
    if [ $? -ne 0 ]; then
        log_message "ERROR: Failed to renew DHCP lease. Please check your network configuration."
        return 1
    fi
    log_message "Renewed DHCP lease for $INTERFACE."
    local_ip=$(ip addr show "$INTERFACE" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    log_message "New local IP address for $INTERFACE: $local_ip"

    if [ -z "$local_ip" ]; then
        log_message "ERROR: Failed to retrieve new local IP address for $INTERFACE. Please check the interface status."
        return 1
    fi

    return 0
}

# Check Nipe status and display spoofed country
check_anonymity() {
    local nipe_status=$(sudo perl nipe.pl status 2>&1)

    if echo "$nipe_status" | grep -q "Status: true"; then
        local ip_address=$(echo "$nipe_status" | grep "Ip" | awk '{print $NF}')
        local country=$(curl -s https://api.country.is/$ip_address | awk 'BEGIN{FS=","} {print $2}' | awk 'BEGIN{FS=":"} {print $2}' | tr -d '"}')

        log_message "Network connection is anonymus via Nipe."
        
        if [ -z "$country" ]; then
            log_message "WARNING: Could not determine spoofed country. https://api.country.is may be down or the IP address is not recognized."
            country="Unknown"
        fi

        log_message "--> Spoofed Country: $country"
        log_message "--> Spoofed IP Address: $ip_address"
        SPOOFED_COUNTRY="$country" # Store for later display
    else
        log_message "ERROR: Network connection is NOT anonymous (Nipe is not active or configured)."
        sudo perl nipe.pl status
        log_message "Please check your connection and try running the script again. Exiting."
        exit 1
    fi

    # Check for dns leaks
    if [ "$DISABLE_DNS" == true ]; then
        local dns_leak=$(dig +short myip.opendns.com @resolver1.opendns.com)
        if [ -z "$dns_leak" ]; then
            log_message "No DNS leaks detected."
         else
            log_message "WARNING: DNS leak detected! DNS queries are not fully anonymous."
            log_message "Detected DNS server: $dns_leak"
            log_message "Please ensure your DNS queries are routed through Tor or disabled. Exiting"
            exit 1
        fi
    else
        log_message "Skipping DNS leak check as local DNS queries are not disabled."
    fi
    
    if [ $MAC_SPOOFING_ENABLED == true ]; then
        # Check if MAC address is changed
        if [ -z "$INTERFACE" ]; then
            log_message "WARNING: No network interface found to check MAC address. MAC address change may not have been applied."
        else
            local mac_address=$(ip link show "$INTERFACE" | awk '/ether/ {print $2}')
            if [ -z "$mac_address" ]; then
                log_message "ERROR: Failed to retrieve MAC address for interface $INTERFACE. Please check the interface status."
            else
                if [[ $mac_address == $OLD_MAC_ADDRESS ]]; then
                    log_message "ERROR: MAC address appears to be reset to default. Please check if macchanger is installed and working correctly."
                else
                    log_message "MAC address for $INTERFACE is successfully changed to $mac_address."
                fi
            fi
        fi
    else
        log_message "Skipping MAC address change check as MAC spoofing is not enabled."  
    fi
}

# --- Install dependencies on remote server ---
install_remote_dependencies() {
    log_message "Checking and installing required dependencies on remote server ($SSH_USER@$SSH_IP)..."
    local remote_packages=("nmap" "whois")
    local install_commands=""
    local check_command=""

    for pkg in "${remote_packages[@]}"; do
        check_command+="command -v $pkg &> /dev/null && echo '${pkg}_INSTALLED' || echo '${pkg}_NOT_INSTALLED';"
    done

    local remote_status=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$DEFAULT_REMOTE_SSH_PORT" "$SSH_USER@$SSH_IP" "$check_command" 2>&1)
    local all_installed=true

    for pkg in "${remote_packages[@]}"; do
        if echo "$remote_status" | grep -q "${pkg}_NOT_INSTALLED"; then
            log_message "$pkg is not installed on remote server. Adding to installation list."
            install_commands+="sudo apt-get install -y $pkg;"
            all_installed=false
        else
            log_message "$pkg is already installed on remote server."
        fi
    done

    if [ "$all_installed" = true ]; then
        log_message "All required dependencies are already installed on remote server."
        return 0
    fi

    if [ -n "$install_commands" ]; then
        log_message "Attempting to install missing packages on remote server..."
        # Update first, then install
        local install_output=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$DEFAULT_REMOTE_SSH_PORT" "$SSH_USER@$SSH_IP" "sudo apt-get update -y && $install_commands" 2>&1)
        if [ $? -eq 0 ]; then
            log_message "Missing packages installed successfully on remote server."
        else
            log_message "ERROR: Failed to install missing packages on remote server. Output: $install_output"
            return 1
        fi
    fi
    return 0
}

# --- Execute Whois on Remote Server ---
execute_remote_whois() {
    log_message "Executing Whois for $TARGET_ADDRESS on remote server ($SSH_USER@$SSH_IP)..."
    local whois_output=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$DEFAULT_REMOTE_SSH_PORT" "$SSH_USER@$SSH_IP" "whois $WHOIS_OPTIONS $TARGET_ADDRESS" 2>&1)

    if [ $? -eq 0 ]; then
        log_message "Whois command executed successfully on remote server."
        echo "$whois_output" > "$WHOIS_FILE"
        log_message "Whois results saved to $WHOIS_FILE"
    else
        log_message "ERROR: Failed to execute Whois on remote server."
        log_message "Whois Error: $whois_output"
    fi
}

# --- Execute Nmap on Remote Server Function ---
execute_remote_nmap() {
    log_message "Executing Nmap scan for open ports on $TARGET_ADDRESS from remote server ($SSH_USER@$SSH_IP)..."
    # Using -F for a fast scan of common ports
    local nmap_output=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$DEFAULT_REMOTE_SSH_PORT" "$SSH_USER@$SSH_IP" "nmap $NMAP_OPTIONS $TARGET_ADDRESS" 2>&1)

    if [ $? -eq 0 ]; then
        log_message "Nmap scan executed successfully on remote server."
        echo "$nmap_output" > "$NMAP_FILE"
        log_message "Nmap results saved to $NMAP_FILE"
    else
        log_message "ERROR: Failed to execute Nmap on remote server."
        log_message "Nmap Error: $nmap_output"
    fi
}

# --- Clean Up Remote Machine Function ---
cleanup_remote_machine() {
    log_message "Clean up traces on remote machine ($SSH_USER@$SSH_IP)..."

    local cleanup_commands="
        # Clear bash history for the current user
        echo '' > ~/.bash_history && history -c && history -w;
        # Clear root's bash history (if accessible)
        sudo sh -c 'echo "" > /root/.bash_history' && sudo history -c && sudo history -w;

        # Clear apt history and term logs
        sudo rm -f /var/log/apt/history.log;
        sudo rm -f /var/log/apt/term.log;

        # Clear journalctl logs (more advanced, might need specific permissions/setup)
        # This command attempts to remove journal logs older than 1 second, effectively clearing recent entries.
        # It then rotates logs and reduces their size.
        sudo journalctl --vacuum-time=1s || true; # '|| true' to prevent script from exiting if this fails
        sudo journalctl --rotate || true;
        sudo journalctl --vacuum-size=1M || true;

        # Remove any temporary files that might have been created (e.g., from apt installations)
        sudo rm -rf /tmp/*;
        sudo rm -rf /var/tmp/*;

        # Flush DNS cache on remote machine (if applicable)
        if command -v systemd-resolve &> /dev/null; then sudo systemd-resolve --flush-caches || true; fi
        if command -v resolvectl &> /dev/null; then sudo resolvectl flush-caches || true; fi

        # Clear common system logs (truncate to 0 bytes)
        sudo truncate -s 0 /var/log/syslog;
        sudo truncate -s 0 /var/log/kern.log;
        sudo truncate -s 0 /var/log/daemon.log;
        sudo truncate -s 0 /var/log/boot.log;
        sudo truncate -s 0 /var/log/wtmp; # Login records
        sudo truncate -s 0 /var/log/btmp; # Failed login records
        sudo truncate -s 0 /var/log/lastlog; # Last login records
        sudo truncate -s 0 /var/log/auth.log;
    "

    local cleanup_output=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$DEFAULT_REMOTE_SSH_PORT" "$SSH_USER@$SSH_IP" "$cleanup_commands" 2>&1)

    if [ $? -eq 1 ]; then
        log_message "ERROR: Failed to clean up remote machine. Output: $cleanup_output"
        return 1
    fi
    return 0
}

# --- Init --- 
init() {
    show_header
    # Ensure the script is run with root privileges
    check_root 
    # Set a trap to ensure DNS and IPTables are restored on script exit (success or failure)
    trap 'restore_configs' EXIT
    echo "" 
    log_message "Starting Recon Automation Tool..."
    echo ""
}

# --- Anonymization Setup ---
setup_anonymization() {
    log_message "Setting up anonymity for local machine..."
    
    # Handle MAC spoofing
    if [ $MAC_SPOOFING_ENABLED == true ]; then
        echo "" 
        change_mac_address          
        if [ $? -eq 0 ]; then
            log_message "MAC address successfully changed for $interface."
        else
            log_message "ERROR: Failed to change MAC address. Please check your network configuration."
            exit 1  
        fi
    else
        log_message "MAC spoofing is disabled. Skipping MAC address change."
    fi

    # Handle DNS queries
    if [ "$DISABLE_DNS" == true ]; then
        echo "" 
        disable_dns                 
        if [ $? -ne 0 ]; then
            log_message "WARNING: Failed to disable DNS."
        fi
    else
        log_message "DNS queries are not disabled. Skipping DNS configuration."
    fi
    
    # Activate Nipe for Tor-based anonymity
    activate_nipe                   
    if [ $? -ne 0 ]; then
        log_message "Anonymity setup failed. Exiting."
        exit 1
    fi
    echo ""
}

# --- Anonymity Check ---
anonymity_check() {
    log_message "Performing mandatory anonymity checks..."
    # Verify that all mandatory anonymity checks are successful
    check_anonymity                 
    if [ $? -ne 0 ]; then
        log_message "Not all mandatory anonymity checks passed. Exiting."
        exit 1
    fi
    log_message "Anonymity checks passed."
    echo ""
}

# --- Attempt to connect to remote server ---
get_remote_server_details() {
    read -p "Enter remote server IP address: " SSH_IP
    read -p "Enter remote server SSH username: " SSH_USER
    read -s -p "Enter remote server SSH password: " SSH_PASS
    echo ""

    # Validate SSH credentials and IP
    if [ -z "$SSH_USER" ] || [ -z "$SSH_PASS" ] || [ -z "$SSH_IP" ]; then
        log_message "ERROR: SSH credentials or IP cannot be empty. Exiting."
        exit 1
    fi
    echo "" 

    log_message "Attempting to connect to remote server: $SSH_USER@$SSH_IP"
    local remote_info=$(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$DEFAULT_REMOTE_SSH_PORT" "$SSH_USER@$SSH_IP" "
        echo 'Remote server IP: $(curl -s ifconfig.me)'
        echo 'Remote server uptime: $(uptime -p)'
    " 2>&1)

    if [ $? -eq 0 ]; then
        log_message "Remote server info: $remote_info"
    else
        log_message "ERROR: Failed to connect to remote server."
        log_message "SSH Error: $remote_info"
        exit 1
    fi
    echo ""
}

# --- Setup Remote Server ---
setup_remote_server() {
    log_message "Setting up remote server for reconnaissance..."
    
    install_remote_dependencies
    if [ $? -ne 0 ]; then
        log_message "Failed to install dependencies on remote server. Exiting."
        exit 1
    fi
    log_message "Remote server setup completed."
    echo ""
}

# --- Perform reconnaissance on the target address ---
do_recon() {
    read -p "Enter the target address (IP or hostname) to scan: " TARGET_ADDRESS

    # Validate target address input
    if [ -z "$TARGET_ADDRESS" ]; then
        log_message "ERROR: Target address cannot be empty. Exiting."
        exit 1
    fi

    if ! [[ "$TARGET_ADDRESS" =~ ^[a-zA-Z0-9._-]+$ ]] && ! [[ "$TARGET_ADDRESS" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_message "ERROR: Invalid target address format. Please enter a valid IP or hostname."
        exit 1
    fi

    log_message "Target address set to: $TARGET_ADDRESS"
    echo "" 

    read -p "Do you want to change the default Nmap options? [$NMAP_OPTIONS]: " changed_nmap_options
    if [ -n "$changed_nmap_options" ]; then
        NMAP_OPTIONS="$changed_nmap_options"
    fi
    read -p "Do you want to change the default Whois options? [$WHOIS_OPTIONS]: " changed_whois_options
    if [ -n "$changed_whois_options" ]; then
        WHOIS_OPTIONS="$changed_whois_options"
    fi

    execute_remote_whois
    execute_remote_nmap
    # -----------------
    # If you want to execute more commands on the remote server
    # you can add them here, for example:
    # sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -p "$DEFAULT_REMOTE_SSH_PORT" "$SSH_USER@$SSH_IP" "your_command_here"
    # -----------------
    
    echo ""
}

# --- Main Script Execution ---
main() {
    # 0. nitialize the script
    init
    # 1. Setup Local Machine
    install_dependencies

    # 2. Anonymization Setup
    setup_anonymization

    # 3. Anonymity Check
    anonymity_check

    # 4. Prompt user for remote server SSH details and connect
    get_remote_server_details
    
    # 5. Setup Remote Server
    setup_remote_server

    # 6. Perform reconnaissance on the target address
    do_recon
     
    # 7. Clean up tracks on the remote machine
    cleanup_remote_machine
    if [ $? -ne 0 ]; then
        log_message "Failed to clean up remote machine. Manual intervention may be required."
    else
        log_message "Remote machine cleanup completed successfully."
    fi

    # 9. Show summary and exit
    echo ""
    log_message "All done."
    echo "" 
    log_message "Whois results saved to: $WHOIS_FILE"
    log_message "Nmap results saved to: $NMAP_FILE"
    log_message "Audit log saved to: $LOG_FILE"
    log_message "Script will now exit and all configurations will be restored to original state..."
    echo "" 
    exit 0
}

# Application entry point
main