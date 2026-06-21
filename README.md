# Cybersecurity Portfolio & Projects
**Author:** Yonatan Avitan  
**Focus:** SOC Operations, Incident Response, Digital Forensics, Penetration Testing & Automation (Bash/Python)

Welcome to my portfolio! This repository contains the raw source code, technical reports, and certifications from my intensive cybersecurity training (Graduating with High Distinction across 87 hands-on lab modules). 

My core philosophy is that deeply understanding the problem is more crucial than merely finding the answer.

---

## 🛡️ Digital Forensics & Incident Response (DFIR)

### 1. Log Recon Analyzer (Python)
A specialized forensic automation tool developed in Python to parse, analyze, and extract actionable intelligence from Linux authentication logs (`/var/log/auth.log`).
* **Key Features:** Regex-based pattern recognition, tracking privilege escalation (sudo/su), identity lifecycle management, and detecting brute-force/threat anomalies.
* **Files:** `7736-39.S25.xe105.py` | `7736-39.S25.xe105.pdf`

### 2. Forensics Analyzer: HDD & Memory (Bash)
An automated digital forensics script for disk and volatile memory analysis.
* **Key Features:** Automated file carving (Foremost/Binwalk) and Volatility 3 framework integration for precise extraction of process lists, network traffic, and registry hives.
* **Files:** `7736-39.S25.NX212.sh` | `7736-39.S25.NX212.pdf`

---

## ⚔️ Offensive Security & Penetration Testing

### 3. CHECKER: SOC Automated Attack Simulator (Bash)
An automated attack simulation framework designed to validate SOC detection capabilities (SIEM/IDS).
* **Key Features:** Engineered 8 time-boxed offensive modules (ARP Spoofing, SYN Flooding, C2 Beaconing) using Nmap, Metasploit, Hping3, and Hydra. 
* **Files:** `7736-39.s20.NX220.sh` | `7736-39.s20.NX220.pdf`

### 4. Operation Domain Mapper: Automated AD Enumeration (Bash)
A comprehensive framework for automated Active Directory reconnaissance.
* **Key Features:** Integrated Impacket, Enum4linux, and Netexec for SMB password spraying and Kerberoasting attacks. Includes an HTML/PDF reporting mechanism.
* **Files:** `7736-39.s20.zx305.sh`

### 5. TITAN: Network Vulnerability Scanner (Bash)
An automated network discovery and credential testing framework.
* **Key Features:** Dynamic system resource optimization for scalable Nmap and Hydra execution. Integrated Searchsploit to cross-reference services with known CVEs.
* **Files:** `7736-39.S25.zx301.sh`

---

## 🕵️ Reconnaissance & OSINT

### 6. Lightning Remote Scanner (Bash)
An advanced remote reconnaissance tool operating securely through an anonymity layer.
* **Key Features:** Integrates Tor routing, SSH jump hosts, Nmap, Whois, and DNS profiling to safely gather intelligence and generate automated Markdown/HTML reports.
* **Files:** `7736-39.s25.NX201.sh` | `7736-39.s25.NX201.pdf`

### 7. Darknet Crawler Automation (Bash)
An autonomous script that safely crawls the darknet (`.onion` websites), extracts, and indexes links.
* **Key Features:** Manages Tor/proxychains routing automatically, handles connection timeouts gracefully, and ensures anonymity without human intervention.
* **Files:** `7736-39.s20.xe109.sh` | `7736-39.s20.xe109.pdf`

### 8. Net Crafts Automation (Python)
An automated network mapping and external information gathering script.
* **Key Features:** Internal network ARP scanning, gateway/DNS identification, and Shodan analysis for public IP profiling.
* **Files:** `7736-39.S25.xe101.pdf`

---

## 📜 Internal Certifications (THINK CYBER)
This repository also contains subject-matter certificates verifying hands-on completion of specific cybersecurity domains. Feel free to review the attached PDF files prefixed with `Cyberium_Certificate_...` for verification.

---
*Actively seeking full-time roles or shift-based positions as a SOC Analyst / Incident Responder.*
