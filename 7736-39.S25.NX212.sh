#!/bin/bash

################################################################################
# Student: yonatan avitan nx212 S25 | Class: 7736/39 | Program: ANALYZER
# Project: Automated HDD and Memory Forensic Analyzer | lecturer's name:Zach azoulis
################################################################################


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'


TARGET_FILE=""
CASE_DIR=""
MEM_PROFILE=""


function spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}


function progress_bar() {
    
    echo -ne "${CYAN}[Loading] "
    for i in {1..20}; do
        echo -ne "#"
        sleep 0.1
    done
    echo -e " Done!${NC}"
}


function check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] Error: This script requires root privileges.${NC}"
        echo -e "${RED}[!] Please run with: sudo ./script_name.sh${NC}"
        exit 1
    fi
}


function get_target_file() {
    while true; do
        echo -e "${YELLOW}[?] Enter full path to the forensic image/memory dump:${NC}"
        read -r input_path
        
        
        if [[ -z "$input_path" ]]; then
            continue
        fi

        if [[ -f "$input_path" ]]; then
            TARGET_FILE="$input_path"
            local size=$(du -h "$TARGET_FILE" | cut -f1)
            echo -e "${GREEN}[✓] Target successfully loaded: $TARGET_FILE (Size: $size)${NC}"
            sleep 1
            break
        else
            echo -e "${RED}[!] File not found at: $input_path${NC}"
        fi
    done
}


function install_requirements() {
    echo -e "${BLUE}[*] Verifying forensic environment...${NC}"
    
    
    local tools=("foremost" "binwalk" "bulk_extractor" "volatility" "zip" "bc")
    local missing=0
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${YELLOW}[!] Tool '$tool' is missing. Installing...${NC}"
            
            DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$tool" &>/dev/null &
            spinner $!
            ((missing++))
        fi
    done
    
    if [ $missing -eq 0 ]; then
        echo -e "${GREEN}[✓] Environment is ready. All tools installed.${NC}"
    else
        echo -e "${GREEN}[✓] Installation complete. Installed $missing tool(s).${NC}"
    fi
    sleep 1
}


function run_carvers() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    CASE_DIR="Forensic_Case_$timestamp"
    mkdir -p "$CASE_DIR"
    
    echo -e "\n${BLUE}[*] Phase 1: Artifact Carving Initialized${NC}"
    
    
    echo -e "${YELLOW}[*] Running Foremost (Media/Doc recovery)...${NC}"
    mkdir -p "$CASE_DIR/foremost_output"
    foremost -i "$TARGET_FILE" -o "$CASE_DIR/foremost_output" -q &>/dev/null &
    spinner $!
    echo -e "${GREEN}[✓] Foremost extraction complete${NC}"
    
   
    echo -e "${YELLOW}[*] Running Binwalk (Signature analysis)...${NC}"
    binwalk --extract --directory="$CASE_DIR/binwalk_output" "$TARGET_FILE" --quiet &>/dev/null &
    spinner $!
    echo -e "${GREEN}[✓] Binwalk extraction complete${NC}"
    
    sleep 1
}


function extract_network_artifacts() {
    echo -e "\n${BLUE}[*] Phase 2: Network Traffic Analysis${NC}"
    
    local net_dir="$CASE_DIR/network_analysis"
    mkdir -p "$net_dir"
    
    echo -e "${YELLOW}[*] Scanning for PCAP headers using bulk_extractor...${NC}"
    
    bulk_extractor -o "$net_dir" "$TARGET_FILE" -E packets &>/dev/null &
    spinner $!
    
    local pcap=$(find "$net_dir" -name "*.pcap" 2>/dev/null | head -n 1)
    
    if [[ -n "$pcap" ]]; then
        local size=$(du -h "$pcap" | cut -f1)
        echo -e "${GREEN}[✓] ALERT: Network traffic recovered! Location: $pcap ($size)${NC}"
    else
        echo -e "${CYAN}[-] No significant network packets found in image.${NC}"
    fi
}


function extract_human_readable() {
    echo -e "\n${BLUE}[*] Phase 3: String & Credential Extraction${NC}"
    
    local output="$CASE_DIR/strings_analysis.txt"
    
    echo -e "${YELLOW}[*] Parsing binary data for credentials and executables...${NC}"
    
    {
        echo "=== FORENSIC STRINGS ANALYSIS REPORT ==="
        echo "Source: $TARGET_FILE"
        echo "Date: $(date)"
        echo "========================================"
        echo ""
        
        echo "[POTENTIAL CREDENTIALS]"
        
        strings -n 6 "$TARGET_FILE" | grep -iE "pass|pwd|login|user|admin" | head -50
        echo ""
        
        echo "[WINDOWS EXECUTABLES / DLLs]"
       
        strings "$TARGET_FILE" | grep -iE "\.exe|\.dll|\.bat" | sort -u | head -40
        echo ""
        
        echo "[EMAIL ADDRESSES]"
        
        strings "$TARGET_FILE" | grep -oE "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b" | sort -u | head -40
        
    } > "$output" &
    spinner $!
    
    echo -e "${GREEN}[✓] String analysis report saved to: $output${NC}"
}


function analyze_memory() {
    echo -e "\n${BLUE}[*] Phase 4: Volatility 3 Memory Analysis${NC}"
    
    local vol_dir="$CASE_DIR/volatility_results"
    mkdir -p "$vol_dir"

    # Requirement 2.2: Info/Profile check
    echo -e "${YELLOW}[*] Identifying Image Info (Profile Check)...${NC}"
    volatility -f "$TARGET_FILE" windows.info > "$vol_dir/image_info.txt" 2>/dev/null
    
    # Requirement 2.3: Processes
    echo -e "${YELLOW}[*] Extracting process list (PsList)...${NC}"
    volatility -f "$TARGET_FILE" windows.pslist.PsList > "$vol_dir/processes.txt" 2>/dev/null &
    spinner $!

    # Requirement 2.4: Network Connections
    echo -e "${YELLOW}[*] Extracting network connections (NetScan)...${NC}"
    volatility -f "$TARGET_FILE" windows.netscan.NetScan > "$vol_dir/network_connections.txt" 2>/dev/null &
    spinner $!

    # Requirement 2.5: Registry Hives
    echo -e "${YELLOW}[*] Extracting Registry Hives list...${NC}"
    volatility -f "$TARGET_FILE" windows.registry.hivelist.HiveList > "$vol_dir/registry_hives.txt" 2>/dev/null &
    spinner $!
    
    if [[ -s "$vol_dir/processes.txt" ]]; then
        echo -e "${GREEN}[✓] Memory analysis completed successfully!${NC}"
        echo -e "${CYAN}Preview of running processes:${NC}"
        head -n 10 "$vol_dir/processes.txt"
    else
        echo -e "${RED}[!] Warning: Some Volatility plugins may have failed or no data found.${NC}"
    fi
}


function generate_final_results() {
    echo -e "\n${BLUE}[*] Phase 5: Report Generation & Archiving${NC}"
    
    local report="$CASE_DIR/FORENSIC_SUMMARY_REPORT.txt"
    local total_files=$(find "$CASE_DIR" -type f | wc -l)
    
    {
        echo "============================================================"
        echo "           DIGITAL FORENSIC ANALYSIS REPORT"
        echo "============================================================"
        echo "Analyst: S25 | Class: 7736/39"
        echo "Date: $(date)"
        echo "------------------------------------------------------------"
        echo "Target Evidence: $TARGET_FILE"
        echo "Memory Profile: ${MEM_PROFILE:-N/A (Disk Image or Unsupported)}"
        echo "Total Artifacts Recovered: $total_files"
        echo "Output Directory: $CASE_DIR"
        echo "============================================================"
        echo "MODULES EXECUTED:"
        echo "[+] File Carving (Foremost, Binwalk)"
        echo "[+] Network Traffic Extraction"
        echo "[+] String Analysis (Credentials/PII)"
        if [[ -n "$MEM_PROFILE" ]]; then
            echo "[+] Volatility Memory Forensics (Profile: $MEM_PROFILE)"
        fi
        echo "============================================================"
    } > "$report"
    
    echo -e "${GREEN}[✓] Report generated.${NC}"
    
    
    echo -e "${YELLOW}[*] Compressing case files into ZIP archive...${NC}"
    zip -r "${CASE_DIR}.zip" "$CASE_DIR" &>/dev/null &
    spinner $!
    echo -e "${GREEN}[✓] Archive created: ${CASE_DIR}.zip${NC}"
    
    
    echo -e "\n${BLUE}============================================================${NC}"
    echo -e "${GREEN}                  ANALYSIS SUCCESSFULLY COMPLETED${NC}"
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${CYAN}Total Artifacts:${NC}  $total_files"
    echo -e "${CYAN}Summary Report:${NC}   $report"
    echo -e "${CYAN}Final Archive:${NC}    ${CASE_DIR}.zip"
    echo -e "${BLUE}============================================================${NC}"
}


clear
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}      THINKCYBER FORENSIC ANALYZER - S25/7736/39${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""


check_root
get_target_file
install_requirements
run_carvers
extract_network_artifacts
extract_human_readable
analyze_memory
generate_final_results

echo -e "\n${YELLOW}Press [ENTER] to exit the analyzer...${NC}"
read -r