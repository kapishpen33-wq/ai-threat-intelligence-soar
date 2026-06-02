# AI Threat Intelligence SOAR Utility

## Overview

This project is a Python-based security automation tool that parses raw logs, extracts indicators of compromise, enriches suspicious IP addresses with VirusTotal, caches prior scan results in SQLite, generates firewall-ready blocklists, and produces an analyst-readable incident report.

The goal is to simulate how a SOC analyst could automate early-stage triage while still keeping final security decisions evidence-based and analyst-reviewed.

## What This Project Demonstrates

- Log parsing and IOC extraction with Python and RegEx
- Threat intelligence enrichment using the VirusTotal API
- SQLite caching to reduce duplicate API calls
- Automated blocklist artifact generation
- AI-assisted incident report drafting
- Security automation workflow design
- Analyst-friendly reporting and triage logic

## Workflow

text Raw logs → Extract IP addresses → Deduplicate indicators → Check SQLite cache → Query VirusTotal for unknown IPs → Score threat reputation → Generate blocklist.json → Generate incident_report.md 

## Key Outputs

| Output | Purpose |
|---|---|
| blocklist.json | Firewall-ready list of malicious IPs |
| incident_report.md | Analyst-readable incident report |
| threat_cache.db | Local cache of previous enrichment results |
| suspicious_logs.txt | Sample log input |
| scanner.py | Main automation script |

## Security Value

Manual IOC triage can be slow and repetitive. This project shows how Python automation can reduce analyst workload by extracting indicators, enriching them with threat intelligence, and producing structured outputs for review.

The tool does not replace analyst judgment. It accelerates triage and provides evidence that a security analyst can validate before taking action.

## Tools Used

- Python
- RegEx
- VirusTotal API
- SQLite
- JSON
- Markdown
- Google Gemini API for report drafting

## MITRE ATT&CK Relevance

This project supports investigation workflows related to suspicious network activity, malicious infrastructure, and external threat indicators. It can be used as part of triage for events involving command-and-control infrastructure, brute-force activity, scanning, or suspicious external connections.

## Limitations

- The tool depends on external threat intelligence API results.
- VirusTotal detections should be reviewed before enforcement.
- Blocklists should be validated before use in production.
- AI-generated reports should be treated as drafts, not final security decisions.
- Sample logs are simulated and do not contain real customer or enterprise data.
