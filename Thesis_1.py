import os
import time
import requests
import hashlib
import yara
from datetime import datetime
import math
import subprocess
from flask import Flask, request, jsonify
from flask_cors import CORS


VT_API_KEY = '3191a24b8ffc5bd98a521cc66e360495568031d07dfe39fb43075f974b010347'
MD_API_KEY = '50f019dc9e7135bcf5f79a9211c9fe85'
APIVOID_API_KEY = 'fdd74a07e60c4a119d2ef050d635443d9b1fe566'
YARA_RULES_PATH = r"/home/kali/Desktop/yara_rules.yar"
UPLOAD_FOLDER = '/tmp/uploads'


if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


app = Flask(__name__)
CORS(app)


def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def upload_file_to_virustotal(api_key, file_path):
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    with open(file_path, "rb") as file:
        files = {"file": (os.path.basename(file_path), file, "application/octet-stream")}
        response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
        response.raise_for_status()
        return response.json()


def get_vt_scan_report(api_key, analysis_id):
    headers = {"accept": "application/json", "x-apikey": api_key}
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    while True:
        response = requests.get(analysis_url, headers=headers)
        response.raise_for_status()
        result = response.json()
        if result['data']['attributes']['status'] == 'completed':
            return result
        print("Waiting for VirusTotal scan to complete...")
        time.sleep(10)


def upload_file_to_metadefender(api_key, file_path):
    headers = {"apikey": api_key}
    with open(file_path, "rb") as file:
        files = {"file": (os.path.basename(file_path), file, "application/octet-stream")}
        response = requests.post("https://api.metadefender.com/v4/file", headers=headers, files=files)
        response.raise_for_status()
        return response.json()


def get_md_scan_report(api_key, data_id):
    headers = {"apikey": api_key}
    analysis_url = f"https://api.metadefender.com/v4/file/{data_id}"
    while True:
        response = requests.get(analysis_url, headers=headers)
        response.raise_for_status()
        result = response.json()
        if result['scan_results']['progress_percentage'] == 100:
            return result
        print("Waiting for MetaDefender scan to complete...")
        time.sleep(10)


def extract_relevant_results_vt(report):
    stats = report['data']['attributes']['stats']
    total_scans = stats.get('malicious', 0) + stats.get('suspicious', 0) + stats.get('undetected', 0) + stats.get('harmless', 0)
    
    malicious_details = [
        scan['result'] for scan in report['data']['attributes']['results'].values()
        if scan['category'] == 'malicious'
    ]
    
    return {
        'malicious': stats.get('malicious', 0),
        'suspicious': stats.get('suspicious', 0),
        'undetected': stats.get('undetected', 0),
        'harmless': stats.get('harmless', 0),
        'total_scans': total_scans,
        'malicious_details': malicious_details
    }


def extract_relevant_results_md(report):
    stats = report.get('scan_results', {}).get('scan_details', {})
    malicious = sum(1 for _, value in stats.items() if value.get('threat_found'))
    harmless = sum(1 for _, value in stats.items() if not value.get('threat_found'))
    total_scans = len(stats) if stats else 0  

    malicious_details = [
        value['threat_found'] for value in stats.values() if value.get('threat_found')
    ]

    return {
        'malicious': malicious,
        'harmless': harmless,
        'suspicious': 0,   
        'undetected': total_scans - (malicious + harmless),
        'total_scans': total_scans,
        'malicious_details': malicious_details
    }


def scan_file_with_clamscan(file_path):
    result = subprocess.run(['clamscan', file_path], capture_output=True, text=True)
    output = result.stdout
    if 'FOUND' in output:
        return {'malicious': 1, 'harmless': 0, 'suspicious': 0, 'undetected': 0, 'total_scans': 1, 'malicious_details': ['FOUND']}
    elif 'OK' in output:
        return {'malicious': 0, 'harmless': 1, 'suspicious': 0, 'undetected': 0, 'total_scans': 1, 'malicious_details': []}
    else:
        return {'malicious': 0, 'harmless': 0, 'suspicious': 0, 'undetected': 1, 'total_scans': 1, 'malicious_details': []}


def scan_file_with_yara(file_path, rules_path):
    rules = yara.compile(filepath=rules_path)
    matches = rules.match(file_path)
    yara_results = {'malicious': len(matches), 'harmless': 0, 'suspicious': 0, 'undetected': 0, 'total_scans': len(matches), 'malicious_details': [match.rule for match in matches]}
    yara_scores = {'total_score': 0, 'details': []}
    
    yara_rule_weights = {
        'malware_sig1': 15,
        'malware_sig2': 20,
        'dos_mode_error': 5,
        'win32_string': 25,
        'registry_key': 30,
        
    }
    
    for match in matches:
        rule = match.rule
        if rule in yara_rule_weights:
            score = yara_rule_weights[rule]
            yara_scores['total_score'] += score
            yara_scores['details'].append(f'YARA: Rule {rule} detected (Score: {score})')
    
    return yara_results, yara_scores


def check_url_reputation(api_key, url):
    response = requests.get(f"https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key={api_key}&host={url}")
    response.raise_for_status()
    result = response.json()
    if 'data' in result and 'report' in result['data']:
        detected_engines = result['data']['report']['detected_by_engines']
        return detected_engines
    return 0


def analyze_file_metadata(file_path):
    metadata = os.stat(file_path)
    file_age = (datetime.now() - datetime.fromtimestamp(metadata.st_ctime)).days
    return {
        'creation_date': datetime.fromtimestamp(metadata.st_ctime),
        'modification_date': datetime.fromtimestamp(metadata.st_mtime),
        'file_age_days': file_age
    }


def get_historical_data(api_key, file_hash):
    headers = {"accept": "application/json", "x-apikey": api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
    response.raise_for_status()
    result = response.json()
    first_seen = result['data']['attributes']['first_submission_date']
    last_seen = result['data']['attributes']['last_submission_date']
    times_seen = result['data']['attributes']['times_submitted']
    
    return {
        'previously_seen': times_seen > 0,
        'times_seen': times_seen,
        'first_seen': datetime.fromtimestamp(first_seen).strftime('%Y-%m-%d'),
        'last_seen': datetime.fromtimestamp(last_seen).strftime('%Y-%m-%d')
    }


def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    if len(data) == 0:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy
