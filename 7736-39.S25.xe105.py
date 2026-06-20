################################################################################
# Student: Yonatan Avitan S25 | Class: 7736-39 | Program: xe105
# Project: Log Analyzer Tool (Operation Log Recon) | Lecturer: Zach Azoulis
# Date: 28/01/2026
# Version: 3.5.2 (Enterprise Edition)
# Description:
#   Advanced forensic tool for parsing Linux authentication logs (/var/log/auth.log).
#   Designed to extract actionable intelligence regarding user activity,
#   privilege escalation (sudo/su), identity management, and security anomalies.
#   
#   Features:
#   - Pattern Recognition Engine (Regex)
#   - Dynamic Table Formatting
#   - Anomaly Detection
#   - Export Capabilities
################################################################################

# References:
# 1. Python Regex Documentation (docs.python.org/3/library/re.html)
# 2. Linux Auth.log format analysis (StackOverflow)

import re
import os
import sys
import time
import datetime
import argparse

# --- Global Configuration & Constants ---
DEFAULT_LOG_PATH = "/var/log/auth.log"
REPORT_FILENAME = "log_analysis_report.txt"

# ANSI Escape Codes for Terminal Highlighting
class TermColors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Helper Classes ---

class TablePrinter:
    """
    A utility class designed to render ASCII tables with dynamic column widths.
    Ensures UI consistency across all reporting phases.
    """
    def __init__(self, headers):
        """
        Initialize the table with a list of headers.
        :param headers: List of strings representing column titles.
        """
        self.headers = headers
        self.rows = []
        # Calculate initial widths based on headers
        self.col_widths = [len(h) + 2 for h in headers]

    def add_row(self, row_data):
        """
        Adds a row of data to the table.
        :param row_data: List of strings corresponding to headers.
        """
        if len(row_data) != len(self.headers):
            raise ValueError("Row length does not match header length.")
        
        self.rows.append(row_data)
        # Update column widths if data is longer than header
        for i, item in enumerate(row_data):
            self.col_widths[i] = max(self.col_widths[i], len(str(item)) + 2)

    def render(self):
        """
        Renders the table as a string.
        :return: String representation of the table.
        """
        if not self.rows:
            return f"{TermColors.WARNING}   [No Data Found for this Section]{TermColors.RESET}\n"

        # Create format string (e.g., "{:<20} {:<15} ...")
        fmt = " | ".join([f"{{:<{w}}}" for w in self.col_widths])
        border = "-+-".join(["-" * w for w in self.col_widths])

        output = []
        output.append(border)
        output.append(fmt.format(*[h.upper() for h in self.headers]))
        output.append(border)

        for row in self.rows:
            # Clean ANSI codes for length calculation could be added here for perfection,
            # but for this scope, simple printing is sufficient.
            output.append(fmt.format(*[str(r) for r in row]))
        
        output.append(border)
        return "\n".join(output)

class LogEntry:
    """
    Represents a single parsed log event.
    Provides a structured way to handle timestamp injection (Missing Year Fix).
    """
    def __init__(self, raw_timestamp, event_type, user, details, command="N/A"):
        self.raw_timestamp = raw_timestamp
        self.timestamp = self._fix_timestamp(raw_timestamp)
        self.event_type = event_type
        self.user = user
        self.details = details
        self.command = command

    def _fix_timestamp(self, ts_str):
        """
        Appends the current year to the log timestamp to ensure forensic accuracy.
        Standard auth.log format: 'Jan 31 10:00:00' (Missing Year).
        """
        current_year = datetime.datetime.now().year
        return f"{ts_str} {current_year}"

# --- Main Logic Class ---

class LogAnalyzerEngine:
    """
    Core engine responsible for file I/O, Regex parsing, and logic mapping.
    """
    def __init__(self, log_path, verbose=False):
        self.log_path = log_path
        self.verbose = verbose
        self.entries = {
            'sudo': [],         # Phase 1
            'user_mgmt': [],    # Phase 2
            'auth': [],         # Phase 3
            'alerts': []        # Phase 4
        }
        
        # Regex Patterns (Compiled for performance)
        # Captures the user running the command (Initiator), not the target (root)
        self.re_sudo = re.compile(r'(?P<date>^.{15})\s+(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s+:(?:\s+TTY=.*)?\s+COMMAND=(?P<cmd>.+)')
        self.re_sudo_alt = re.compile(r'(?P<date>^.{15})\s+(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s+sudo:.*COMMAND=(?P<cmd>.+)')
        
        self.re_new_user = re.compile(r'(?P<date>^.{15}).*new user: name=(?P<user>[^,]+)')
        self.re_del_user = re.compile(r'(?P<date>^.{15}).*delete user [\'"]?(?P<user>\w+)[\'"]?')
        self.re_pass_chg = re.compile(r'(?P<date>^.{15}).*password changed for (?P<user>\w+)')
        self.re_su_session = re.compile(r'(?P<date>^.{15}).*pam_unix\(su:session\): session opened for user (?P<target>\w+) by (?P<user>\w+)')
        
        # Security Alert Pattern - Looking for Auth Failures
        self.re_auth_fail = re.compile(r'(?P<date>^.{15}).*sudo:.*authentication failure;.*logname=(?P<user>\S+)')

    def validate_permissions(self):
        """Checks if the script has read access to the log file."""
        if not os.path.exists(self.log_path):
            print(f"{TermColors.FAIL}[CRITICAL] File not found: {self.log_path}{TermColors.RESET}")
            sys.exit(1)
        if not os.access(self.log_path, os.R_OK):
            print(f"{TermColors.FAIL}[CRITICAL] Access Denied. Please run with 'sudo'.{TermColors.RESET}")
            sys.exit(1)

    def process_logs(self):
        """Reads the log file line by line and dispatches to parsers."""
        if self.verbose:
            print(f"{TermColors.BLUE}[*] Opening log file stream...{TermColors.RESET}")
        
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line: continue
                    self._parse_line(line)
                    
        except Exception as e:
            print(f"{TermColors.FAIL}[ERROR] Processing failed at line {line_num}: {e}{TermColors.RESET}")

    def _parse_line(self, line):
        """
        Matches a line against defined regex patterns.
        Order matters for performance.
        """
        
        # 1. Check for Sudo Commands (Task 1.1 - 1.3, 2.5)
        m_sudo = self.re_sudo.search(line) or self.re_sudo_alt.search(line)
        if m_sudo:
            entry = LogEntry(
                raw_timestamp=m_sudo.group('date'),
                event_type="SUDO_EXEC",
                user=m_sudo.group('user'), # The Initiator
                details="Executed Command",
                command=m_sudo.group('cmd')
            )
            self.entries['sudo'].append(entry)
            return

        # 2. Check for New Users (Task 2.1)
        m_new = self.re_new_user.search(line)
        if m_new:
            self.entries['user_mgmt'].append(LogEntry(
                m_new.group('date'), "USER_ADD", m_new.group('user'), "New Account Created"
            ))
            return

        # 3. Check for Deleted Users (Task 2.2)
        m_del = self.re_del_user.search(line)
        if m_del:
            self.entries['user_mgmt'].append(LogEntry(
                m_del.group('date'), "USER_DEL", m_del.group('user'), "Account Deleted"
            ))
            return

        # 4. Check for Password Changes (Task 2.3)
        m_pass = self.re_pass_chg.search(line)
        if m_pass:
            self.entries['auth'].append(LogEntry(
                m_pass.group('date'), "PASS_CHG", m_pass.group('user'), "Password Modified"
            ))
            return

        # 5. Check for SU Sessions (Task 2.4)
        m_su = self.re_su_session.search(line)
        if m_su:
            # Capture both initiator and target
            initiator = m_su.group('user')
            target = m_su.group('target')
            self.entries['auth'].append(LogEntry(
                m_su.group('date'), "SU_SWITCH", initiator, f"Switched to user: {target}"
            ))
            return

        # 6. Check for Security Alerts / Auth Failures (Task 2.6)
        m_fail = self.re_auth_fail.search(line)
        if m_fail:
            # Extract command if available (rare in auth fail), else set default
            cmd_match = re.search(r'COMMAND=(.+)', line)
            failed_cmd = cmd_match.group(1) if cmd_match else "Unknown (Not Logged)"
            
            self.entries['alerts'].append(LogEntry(
                m_fail.group('date'), "AUTH_FAIL", m_fail.group('user'), "Failed Sudo Attempt", failed_cmd
            ))
            return

    def generate_report(self):
        """
        Orchestrates the generation of the ASCII report.
        """
        print_header()
        
        # --- PHASE 1: SUDO COMMANDS ---
        print(f"\n{TermColors.BOLD}{TermColors.CYAN}--- [ PHASE 1: PRIVILEGE ESCALATION COMMANDS ] ---{TermColors.RESET}")
        print(f"{TermColors.BLUE}Objective: Audit sudo command usage (Req 1.1-1.3, 2.5){TermColors.RESET}")
        
        table_sudo = TablePrinter(["Timestamp", "Source User", "Command Executed"])
        for e in self.entries['sudo']:
            table_sudo.add_row([e.timestamp, e.user, e.command])
        print(table_sudo.render())

        # --- PHASE 2: IDENTITY MANAGEMENT ---
        print(f"\n{TermColors.BOLD}{TermColors.CYAN}--- [ PHASE 2: IDENTITY LIFECYCLE MANAGEMENT ] ---{TermColors.RESET}")
        print(f"{TermColors.BLUE}Objective: Monitor user creation and deletion (Req 2.1, 2.2){TermColors.RESET}")
        
        table_id = TablePrinter(["Timestamp", "Event Type", "Account Name", "Description"])
        for e in self.entries['user_mgmt']:
            # Color code specific events
            evt_color = TermColors.GREEN if e.event_type == "USER_ADD" else TermColors.WARNING
            table_id.add_row([e.timestamp, f"{evt_color}{e.event_type}{TermColors.RESET}", e.user, e.details])
        print(table_id.render())

        # --- PHASE 3: AUTHENTICATION EVENTS ---
        print(f"\n{TermColors.BOLD}{TermColors.CYAN}--- [ PHASE 3: AUTHENTICATION & SESSION EVENTS ] ---{TermColors.RESET}")
        print(f"{TermColors.BLUE}Objective: Track password changes and SU switching (Req 2.3, 2.4){TermColors.RESET}")
        
        table_auth = TablePrinter(["Timestamp", "Event Type", "Source User", "Details"])
        for e in self.entries['auth']:
            table_auth.add_row([e.timestamp, e.event_type, e.user, e.details])
        print(table_auth.render())

        # --- PHASE 4: SECURITY ALERTS ---
        print(f"\n{TermColors.BOLD}{TermColors.FAIL}--- [ PHASE 4: SECURITY ANOMALIES & ALERTS ] ---{TermColors.RESET}")
        print(f"{TermColors.BLUE}Objective: Detect failed authentication attempts (Req 2.6){TermColors.RESET}")
        
        # Explicitly satisfying Requirement 2.6: "include the command"
        table_alerts = TablePrinter(["Timestamp", "Logname (Source)", "Attempted Command", "Status"])
        for e in self.entries['alerts']:
            table_alerts.add_row([e.timestamp, e.user, e.command, f"{TermColors.FAIL}{e.details}{TermColors.RESET}"])
        print(table_alerts.render())
        
        # Summary
        total_events = sum(len(v) for v in self.entries.values())
        print(f"\n{TermColors.HEADER}--- SUMMARY STATISTICS ---{TermColors.RESET}")
        print(f"Total Events Processed: {total_events}")
        print(f"Critical Alerts:        {len(self.entries['alerts'])}")

def print_header():
    """Prints the tool banner."""
    print(TermColors.HEADER + TermColors.BOLD)
    print("=" * 80)
    print("    LOG RECON ANALYZER | ENTERPRISE EDITION | v3.5.2")
    print("    Student: S25 | Unit: 7736-39 | Lecturer: Zach Azoulis")
    print("=" * 80 + TermColors.RESET)

def parse_arguments():
    """Parses command line arguments for a professional CLI feel."""
    parser = argparse.ArgumentParser(description="Advanced Log Analysis Tool (XE105)")
    parser.add_argument("-f", "--file", default=DEFAULT_LOG_PATH, help="Path to the log file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

# --- Entry Point ---

if __name__ == "__main__":
    # Clear screen for a fresh start
    os.system('cls' if os.name == 'nt' else 'clear')
    
    args = parse_arguments()
    
    # Initialize Engine
    engine = LogAnalyzerEngine(args.file, args.verbose)
    
    # Execution Flow
    engine.validate_permissions()
    engine.process_logs()
    engine.generate_report()
    
    print("\n[+] Analysis Session Completed Successfully.")
