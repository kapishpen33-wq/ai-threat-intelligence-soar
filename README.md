# AI-Powered Threat Intelligence SOAR Utility

## Objective
To engineer a custom DevSecOps command-line utility that automates the Incident Response lifecycle. The tool extracts network indicators of compromise (IOCs) from raw logs, queries enterprise threat intelligence databases, manages state via a local cache, and leverages Generative AI to automate executive reporting. 

## Tech Stack & Libraries
* **Language:** Python 3
* **APIs:** VirusTotal (v3), Google Gemini (2.5 Flash)
* **Libraries:** `re` (RegEx), `requests`, `sqlite3`, `argparse`, `json`, `google-genai`

## Core Architecture & Features
1. **Regex Extraction Engine:** Parses raw, unstructured firewall/network logs to isolate unique IPv4 addresses.
2. **Threat Intelligence Integration:** Interrogates the VirusTotal REST API to determine the malicious reputation of extracted IPs.
3. **Database Caching (SQLite):** Implements a local `threat_cache.db` to store historical scan results. This drastically reduces API calls, prevents rate-limiting, and drops execution time from minutes to milliseconds on recurring IOCs.
4. **SOAR Automation:** Automatically generates a formatted `blocklist.json` artifact containing confirmed malicious IPs, designed for direct ingestion by enterprise firewalls (e.g., Palo Alto, AWS Network Firewall).
5. **AI Incident Responder:** Integrates the Google Gemini LLM to automatically ingest the threat data and draft a professional, C-Suite ready Markdown Incident Report detailing the findings, automated remediation steps, and recommended threat hunting procedures.

## Usage
The tool is designed with a standard CLI architecture:
```bash
python3 scanner.py -f suspicious_logs.txt
