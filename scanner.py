import re
import requests
import time
import sqlite3
import argparse
import json
from google import genai

VT_API_KEY = "YOUR_VT_KEY"
GEMINI_API_KEY = "YOU_API_KEY"

# --- DATABASE SETUP ---
def setup_database():
    conn = sqlite3.connect('threat_cache.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip TEXT PRIMARY KEY,
            status TEXT,
            flags INTEGER
        )
    ''')
    conn.commit()
    return conn

# --- CORE LOGIC ---
def extract_ips(filename):
    with open(filename, 'r') as file:
        log_data = file.read()
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return list(set(re.findall(ip_pattern, log_data)))

def check_ip(ip, conn):
    cursor = conn.cursor()
    cursor.execute("SELECT status, flags FROM ip_cache WHERE ip = ?", (ip,))
    cached_result = cursor.fetchone()
    
    if cached_result:
        print(f"[CACHE HIT] {ip} is already known: {cached_result[0]} ({cached_result[1]} flags)")
        return cached_result[0], cached_result[1]

    print(f"[API CALL] Querying VirusTotal for {ip}...")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        malicious_votes = data['data']['attributes']['last_analysis_stats']['malicious']
        status = "MALICIOUS" if malicious_votes > 0 else "CLEAN"
        
        cursor.execute("INSERT INTO ip_cache (ip, status, flags) VALUES (?, ?, ?)", (ip, status, malicious_votes))
        conn.commit()
        
        print(f" -> Result: {status} ({malicious_votes} flags)")
        time.sleep(15) 
        return status, malicious_votes
    else:
        print(f" -> Result: ERROR/PRIVATE IP")
        return "ERROR", 0

# --- AI INCIDENT RESPONDER ---
# --- AI INCIDENT RESPONDER ---
def generate_ai_report(threat_data):
    print("\n🧠 AI is analyzing the threat data and writing the Executive Report...")
    
    # Initialize the new Gemini client
    client = genai.Client(api_key=GEMINI_API_KEY)
    
    prompt = f"""
    Act as an expert Security Operations Center (SOC) Lead.
    We just ran an automated threat intelligence scan on our raw network logs.
    We found the following malicious IP addresses:
    {threat_data}

    Write a brief, highly professional incident report for the C-Suite.
    Include:
    1. An Executive Summary.
    2. Technical Findings (mentioning the IPs and that they were verified via the VirusTotal API).
    3. Automated Remediation Taken (IPs were successfully exported to blocklist.json for immediate firewall ingestion).
    4. Recommended Next Steps for the security team.
    
    Format the report beautifully in Markdown. Keep it concise and authoritative.
    """
    
    try:
        # Using the new SDK syntax and current model
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        with open('incident_report.md', 'w') as f:
            f.write(response.text)
        print("✅ AI Incident Report successfully generated: incident_report.md")
    except Exception as e:
        print(f"⚠️ Failed to generate AI report: {e}")
# --- CLI ARCHITECTURE ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-Powered Threat Intel SOAR Utility")
    parser.add_argument("-f", "--file", required=True, help="Path to the log file to scan")
    args = parser.parse_args()

    print("\n🚀 Initiating AI-Powered Threat Intel Scan...\n")
    
    db_conn = setup_database()
    target_ips = extract_ips(args.file)
    
    malicious_ips = []
    threat_details = []

    for ip in target_ips:
        status, flags = check_ip(ip, db_conn)
        if status == "MALICIOUS":
            malicious_ips.append(ip)
            threat_details.append(f"IP: {ip} | VirusTotal Malicious Flags: {flags}")

    db_conn.close()

    # --- SOAR AUTOMATION: EXPORT BLOCKLIST & TRIGGER AI ---
    if malicious_ips:
        with open('blocklist.json', 'w') as f:
            json.dump({"action": "block", "target_ips": malicious_ips}, f, indent=4)
        print(f"\n✅ Scan Complete! Exported {len(malicious_ips)} malicious IP(s) to blocklist.json")
        
        # Pass the data to Gemini to write the report
        generate_ai_report(threat_details)
    else:
        print("\n✅ Scan Complete! No malicious IPs found. No report needed.")