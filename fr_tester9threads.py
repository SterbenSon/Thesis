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
import threading
import tempfile
import shutil

# API Keys and file path
VT_API_KEY = '3191a24b8ffc5bd98a521cc66e360495568031d07dfe39fb43075f974b010347'
MD_API_KEY = '50f019dc9e7135bcf5f79a9211c9fe85'
APIVOID_API_KEY = 'fdd74a07e60c4a119d2ef050d635443d9b1fe566'
YARA_RULES_PATH = r"/home/kali/Desktop/yara_rules.yar"
UPLOAD_FOLDER = '/tmp/uploads'

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Function to calculate file hash
def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Upload file to VirusTotal
def upload_file_to_virustotal(api_key, file_path, results):
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    with open(file_path, "rb") as file:
        files = {"file": (os.path.basename(file_path), file, "application/octet-stream")}
        response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
        response.raise_for_status()
        results['vt_report'] = response.json()

# Retrieve the scan report from VirusTotal
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

# Upload file to MetaDefender Cloud
def upload_file_to_metadefender(api_key, file_path, results):
    headers = {"apikey": api_key}
    with open(file_path, "rb") as file:
        files = {"file": (os.path.basename(file_path), file, "application/octet-stream")}
        response = requests.post("https://api.metadefender.com/v4/file", headers=headers, files=files)
        response.raise_for_status()
        results['md_report'] = response.json()

# Retrieve the scan report from MetaDefender Cloud
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

# Extract relevant results from VirusTotal's report
def extract_relevant_results_vt(report):
    try:
        stats = report['data']['attributes']['stats']
    except KeyError:
        return {'malicious': 0, 'suspicious': 0, 'undetected': 0, 'harmless': 0, 'total_scans': 0, 'malicious_details': []}

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

# Extract relevant results from MetaDefender's report
def extract_relevant_results_md(report):
    stats = report.get('scan_results', {}).get('scan_details', {})
    malicious = sum(1 for _, value in stats.items() if value.get('threat_found'))
    harmless = sum(1 for _, value in stats.items() if not value.get('threat_found'))
    total_scans = len(stats) if stats else 0  # Make sure to set a default value if stats is empty

    malicious_details = [
        value['threat_found'] for value in stats.values() if value.get('threat_found')
    ]

    return {
        'malicious': malicious,
        'harmless': harmless,
        'suspicious': 0,  # Assume MetaDefender does not differentiate 'suspicious'
        'undetected': total_scans - (malicious + harmless),
        'total_scans': total_scans,
        'malicious_details': malicious_details
    }

# Scan file using clamscan
def scan_file_with_clamscan(file_path, results):
    result = subprocess.run(['clamscan', file_path], capture_output=True, text=True)
    output = result.stdout
    if 'FOUND' in output:
        results['clamav_results'] = {'malicious': 1, 'harmless': 0, 'suspicious': 0, 'undetected': 0, 'total_scans': 1, 'malicious_details': ['FOUND']}
    elif 'OK' in output:
        results['clamav_results'] = {'malicious': 0, 'harmless': 1, 'suspicious': 0, 'undetected': 0, 'total_scans': 1, 'malicious_details': []}
    else:
        results['clamav_results'] = {'malicious': 0, 'harmless': 0, 'suspicious': 0, 'undetected': 1, 'total_scans': 1, 'malicious_details': []}

# Scan file using YARA rules
def scan_file_with_yara(file_path, rules_path, results):
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
        # Add more rules with their respective weights
    }
    
    for match in matches:
        rule = match.rule
        if rule in yara_rule_weights:
            score = yara_rule_weights[rule]
            yara_scores['total_score'] += score
            yara_scores['details'].append(f'YARA: Rule {rule} detected (Score: {score})')
    
    results['yara_results'] = yara_results
    results['yara_scores'] = yara_scores

# Check URL reputation using APIVoid
def check_url_reputation(api_key, url, results):
    response = requests.get(f"https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key={api_key}&host={url}")
    response.raise_for_status()
    result = response.json()
    if 'data' in result and 'report' in result['data']:
        detected_engines = result['data']['report']['detected_by_engines']
        results['url_reputation_score'] = detected_engines
    else:
        results['url_reputation_score'] = 0

# Analyze file metadata
def analyze_file_metadata(file_path, results, original_creation_date, original_modification_date):
    metadata = os.stat(file_path)
    file_age = (datetime.now() - datetime.fromtimestamp(metadata.st_ctime)).days
    results['metadata_analysis'] = {
        'creation_date': original_creation_date,
        'modification_date': original_modification_date,
        'file_age_days': file_age
    }

# Retrieve historical data from VirusTotal using the file hash
def get_historical_data(api_key, file_hash, results):
    headers = {"accept": "application/json", "x-apikey": api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
    response.raise_for_status()
    result = response.json()
    first_seen = result['data']['attributes']['first_submission_date']
    last_seen = result['data']['attributes']['last_submission_date']
    times_seen = result['data']['attributes']['times_submitted']
    
    results['historical_data'] = {
        'previously_seen': times_seen > 0,
        'times_seen': times_seen,
        'first_seen': datetime.fromtimestamp(first_seen).strftime('%Y-%m-%d'),
        'last_seen': datetime.fromtimestamp(last_seen).strftime('%Y-%m-%d')
    }

# Calculate entropy
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

def heuristic_analysis(vt_results, md_results, clamav_results, yara_scores, url_reputation_score, metadata_analysis, historical_data, file_path):
    score = 0
    detailed_scores = []

    # Heuristic rules for VirusTotal results
    if vt_results['malicious'] > 2:
        score += 20
        detailed_scores.append('VirusTotal: High number of malicious detections (Score: 20)')
    elif vt_results['malicious'] > 0:
        score += 10
        detailed_scores.append('VirusTotal: Some malicious detections (Score: 10)')
    if vt_results['suspicious'] > 1:
        score += 5
        detailed_scores.append('VirusTotal: Suspicious detections (Score: 5)')

    # Heuristic rules for MetaDefender results
    if md_results['malicious'] > 2:
        score += 20
        detailed_scores.append('MetaDefender: High number of malicious detections (Score: 20)')
    elif md_results['malicious'] > 0:
        score += 10
        detailed_scores.append('MetaDefender: Some malicious detections (Score: 10)')

    # Heuristic rules for ClamAV results
    if clamav_results['malicious'] > 0:
        score += 15
        detailed_scores.append('ClamAV: Malicious detection (Score: 15)')

    # Heuristic rules for YARA results
    if yara_scores['total_score'] > 0:
        score += yara_scores['total_score']
        detailed_scores.extend(yara_scores['details'])

    # Heuristic rules for URL reputation
    if url_reputation_score > 0:
        score += 10 * url_reputation_score  # Multiply by number of detected engines
        detailed_scores.append(f'URLVoid: Malicious URL detected by {url_reputation_score} engines (Score: {10 * url_reputation_score})')

    # Heuristic rules for file metadata
    if metadata_analysis['file_age_days'] < 30:
        score += 10
        detailed_scores.append('Metadata: New file (Score: 10)')
    if metadata_analysis['file_age_days'] > 365:
        score += 5
        detailed_scores.append('Metadata: Old file, potentially less suspicious (Score: 5)')

    # Heuristic rules for historical data
    if historical_data['previously_seen']:
        score += 10
        detailed_scores.append('Historical: File previously seen and flagged (Score: 10)')
        if historical_data['times_seen'] > 10:
            score += 5
            detailed_scores.append('Historical: File frequently seen (Score: 5)')

    # Heuristic rules for file size
    file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB
    if file_size < 1:
        score += 10
        detailed_scores.append('File size: Very small file, potentially suspicious (Score: 10)')

   # Heuristic rules for file extension
    file_extension = os.path.splitext(file_path)[1].lower()
    if file_extension in ['.exe', '.dll', '.sys']:
        score += 15
        detailed_scores.append(f'File extension: Suspicious file extension ({file_extension}) (Score: 15)')

    # Heuristic rules for entropy
    entropy = calculate_entropy(file_path)
    if entropy > 7:
        score += 10
        detailed_scores.append('Entropy: High entropy, potentially compressed or encrypted content (Score: 10)')

    return score, detailed_scores

def anomaly_detection(vt_results, md_results, clamav_results, yara_scores, metadata_analysis):
    score = 0
    detailed_scores = []

    # Anomaly detection based on deviation from expected norms
    if vt_results['total_scans'] > 0 and vt_results['malicious'] / vt_results['total_scans'] > 0.5:
        score += 20
        detailed_scores.append('Anomaly: High ratio of malicious detections in VirusTotal (Score: 20)')
    if md_results['total_scans'] > 0 and md_results['malicious'] / md_results['total_scans'] > 0.5:
        score += 20
        detailed_scores.append('Anomaly: High ratio of malicious detections in MetaDefender (Score: 20)')
    if metadata_analysis['file_age_days'] < 1:
        score += 15
        detailed_scores.append('Anomaly: Very new file (Score: 15)')

    return score, detailed_scores

def behavioral_analysis(file_path):
    score = 0
    detailed_scores = []

    # Basic behavioral analysis for Unix-like systems
    if file_path.startswith('.'):
        score += 10
        detailed_scores.append('Behavioral: Hidden file detected (Score: 10)')

    # Check file attributes on Windows (stub, not fully implemented)
    if os.name == 'nt':
        import ctypes
        FILE_ATTRIBUTE_HIDDEN = 0x02
        FILE_ATTRIBUTE_SYSTEM = 0x04
        attributes = ctypes.windll.kernel32.GetFileAttributesW(file_path)
        if attributes & FILE_ATTRIBUTE_HIDDEN:
            score += 10
            detailed_scores.append('Behavioral: Hidden file detected (Score: 10)')
        if attributes & FILE_ATTRIBUTE_SYSTEM:
            score += 10
            detailed_scores.append('Behavioral: System file detected (Score: 10)')

    return score, detailed_scores

def complex_algorithm(vt_results, md_results, clamav_results, yara_scores, url_reputation_score, metadata_analysis, historical_data, file_path):
    heuristic_score, heuristic_details = heuristic_analysis(vt_results, md_results, clamav_results, yara_scores, url_reputation_score, metadata_analysis, historical_data, file_path)
    anomaly_score, anomaly_details = anomaly_detection(vt_results, md_results, clamav_results, yara_scores, metadata_analysis)
    behavioral_score, behavioral_details = behavioral_analysis(file_path)

    total_score = heuristic_score + anomaly_score + behavioral_score
    details = heuristic_details + anomaly_details + behavioral_details

    # Normalize the final score to [0, 100]
    max_score = 100
    normalized_score = min((total_score / max_score) * 100, 100)

    return normalized_score, details

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:
        temp_dir = tempfile.mkdtemp()
        temp_file_path = os.path.join(temp_dir, file.filename)
        file.save(temp_file_path)

        original_creation_date = datetime.fromtimestamp(os.path.getctime(temp_file_path))
        original_modification_date = datetime.fromtimestamp(os.path.getmtime(temp_file_path))

        download_url = request.form.get('download_url', '')
        result = main(temp_file_path, download_url, original_creation_date, original_modification_date)
        
        shutil.rmtree(temp_dir)  # Clean up the temporary directory

        return jsonify(result)

def main(file_path, download_url, original_creation_date, original_modification_date):
    try:
        start_time = datetime.now()
        results = {}

        threads = [
            threading.Thread(target=upload_file_to_virustotal, args=(VT_API_KEY, file_path, results)),
            threading.Thread(target=upload_file_to_metadefender, args=(MD_API_KEY, file_path, results)),
            threading.Thread(target=scan_file_with_clamscan, args=(file_path, results)),
            threading.Thread(target=scan_file_with_yara, args=(file_path, YARA_RULES_PATH, results)),
            threading.Thread(target=check_url_reputation, args=(APIVOID_API_KEY, download_url, results)),
            threading.Thread(target=analyze_file_metadata, args=(file_path, results, original_creation_date, original_modification_date)),
            threading.Thread(target=get_historical_data, args=(VT_API_KEY, calculate_file_hash(file_path), results))
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        vt_results = extract_relevant_results_vt(results.get('vt_report', {}))
        md_results = extract_relevant_results_md(results.get('md_report', {}))
        clamav_results = results.get('clamav_results', {})
        yara_results = results.get('yara_results', {})
        yara_scores = results.get('yara_scores', {})
        url_reputation_score = results.get('url_reputation_score', 0)
        metadata_analysis = results.get('metadata_analysis', {})
        historical_data = results.get('historical_data', {})

        final_score, details = complex_algorithm(vt_results, md_results, clamav_results, yara_scores, url_reputation_score, metadata_analysis, historical_data, file_path)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()  # Convert timedelta to seconds
        print(f"\nTotal time taken for analysis: {duration} seconds")

        return {
            'vt_results': vt_results,
            'md_results': md_results,
            'clamav_results': clamav_results,
            'yara_results': yara_results,
            'yara_scores': yara_scores,
            'url_reputation_score': url_reputation_score,
            'metadata_analysis': metadata_analysis,
            'historical_data': historical_data,
            'final_score': final_score,
            'details': details,
            'duration': duration
        }

    except FileNotFoundError:
        print("Error: The file was not found.")
    except requests.exceptions.RequestException as e:
        print(f"HTTP request failed: {e}")
    except subprocess.CalledProcessError as e:
        print(f"Clamscan failed: {e}")
    except yara.Error as e:
        print(f"YARA scan failed: {e}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
