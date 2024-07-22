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


VT_API_KEY = '3191a24b8ffc5bd98a521cc66e360495568031d07dfe39fb43075f974b010347'
MD_API_KEY = '50f019dc9e7135bcf5f79a9211c9fe85'
IPQS_API_KEY = 'EYtM9MgnoLkjVLGUz1vWxBOEBVuokS2H'
YARA_RULES_PATH = r"/home/kali/Desktop/yara_rules7.yar"
UPLOAD_FOLDER = '/tmp/uploads'


if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


app = Flask(__name__)
CORS(app)


ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mkv', 'mp3', 'wav', 'flac', 'mov', 'wmv', 'jpg', 'jpeg', 'png', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


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
        results['vt_analysis_id'] = results['vt_report']['data']['id']
        print("VirusTotal file uploaded. Analysis ID:", results['vt_analysis_id'])


def get_vt_scan_report(api_key, analysis_id):
    headers = {"accept": "application/json", "x-apikey": api_key}
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    while True:
        response = requests.get(analysis_url, headers=headers)
        response.raise_for_status()
        result = response.json()
        if result['data']['attributes']['status'] == 'completed':
            print("VirusTotal scan completed.")
            return result
        print("Waiting for VirusTotal scan to complete...")
        time.sleep(10)


def upload_file_to_metadefender(api_key, file_path, results):
    headers = {"apikey": api_key}
    with open(file_path, "rb") as file:
        files = {"file": (os.path.basename(file_path), file, "application/octet-stream")}
        response = requests.post("https://api.metadefender.com/v4/file", headers=headers, files=files)
        response.raise_for_status()
        results['md_report'] = response.json()
        results['md_data_id'] = results['md_report']['data_id']
        print("MetaDefender file uploaded. Data ID:", results['md_data_id'])


def get_md_scan_report(api_key, data_id):
    headers = {"apikey": api_key}
    analysis_url = f"https://api.metadefender.com/v4/file/{data_id}"
    while True:
        response = requests.get(analysis_url, headers=headers)
        response.raise_for_status()
        result = response.json()
        if result['scan_results']['progress_percentage'] == 100:
            print("MetaDefender scan completed.")
            return result
        print("Waiting for MetaDefender scan to complete...")
        time.sleep(10)


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


def scan_file_with_clamscan(file_path, results):
    result = subprocess.run(['clamscan', file_path], capture_output=True, text=True)
    output = result.stdout
    if 'FOUND' in output:
        results['clamav_results'] = {'malicious': 1, 'harmless': 0, 'suspicious': 0, 'undetected': 0, 'total_scans': 1, 'malicious_details': ['FOUND']}
    elif 'OK' in output:
        results['clamav_results'] = {'malicious': 0, 'harmless': 1, 'suspicious': 0, 'undetected': 0, 'total_scans': 1, 'malicious_details': []}
    else:
        results['clamav_results'] = {'malicious': 0, 'harmless': 0, 'suspicious': 0, 'undetected': 1, 'total_scans': 1, 'malicious_details': []}


def scan_file_with_yara(file_path, rules_path, results):
    rules = yara.compile(filepath=rules_path)
    matches = rules.match(file_path)
    yara_results = {'malicious': len(matches), 'harmless': 0, 'suspicious': 0, 'undetected': 0, 'total_scans': len(matches), 'malicious_details': [match.rule for match in matches]}
    yara_scores = {'total_score': 0, 'details': []}
    
    yara_rule_weights = {
        'malware_sig1': 10,
        'malware_sig2': 15,
        'dos_mode_error': 5,
        'win32_string': 20,
        'image_malware1': 25,
        'image_malware2': 25,
        'exif_payload': 30,
    }
    
    for match in matches:
        rule = match.rule
        if rule in yara_rule_weights:
            score = yara_rule_weights[rule]
            yara_scores['total_score'] += score
            yara_scores['details'].append(f'YARA: Rule {rule} detected (Score: {score})')
    
    results['yara_results'] = yara_results
    results['yara_scores'] = yara_scores


def check_url_reputation(api_key, url, results):
    headers = {"accept": "application/json", "x-apikey": api_key}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
    response.raise_for_status()
    analysis_id = response.json()['data']['id']

    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    while True:
        response = requests.get(analysis_url, headers=headers)
        response.raise_for_status()
        result = response.json()
        if result['data']['attributes']['status'] == 'completed':
            print("VirusTotal URL scan completed.")
            data = result['data']['attributes']['results']

            print(f"URL scan result: {data}")
            malicious_count = sum(1 for entry in data.values() if entry['category'] == 'malicious')
            if malicious_count > 0:
                results['url_reputation_score'] = "url is not safe"
                results['url_malicious_count'] = malicious_count
            else:
                results['url_reputation_score'] = "clean"
                results['url_malicious_count'] = malicious_count


            ip_geolocation, ip_fraud_score = analyze_ip(request.remote_addr)
            results['ip_geolocation'] = ip_geolocation
            results['ip_fraud_score'] = ip_fraud_score
            
            return
        print("Waiting for VirusTotal URL scan to complete...")
        time.sleep(10)


def analyze_file_metadata(file_path, results):
    try:
        from hachoir.parser import createParser
        from hachoir.metadata import extractMetadata
    except ImportError:
        print("Hachoir library is not installed.")
        return

    parser = createParser(file_path)
    if not parser:
        print(f"Unable to parse file {file_path}")
        return

    metadata = extractMetadata(parser)
    if not metadata:
        print(f"No metadata found for file {file_path}")
        return

    metadata_dict = {}
    for line in metadata.exportPlaintext():
        parts = line.split(":", 1)
        if len(parts) == 2:
            metadata_dict[parts[0].strip()] = parts[1].strip()
    

    stat = os.stat(file_path)
    metadata_dict['File creation date'] = datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
    
    results['metadata_analysis'] = metadata_dict


def get_historical_data(api_key, file_hash, results):
    headers = {"accept": "application/json", "x-apikey": api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
    if response.status_code == 404:
        results['historical_data'] = {
            'previously_seen': False,
            'times_seen': 0,
            'first_seen': None,
            'last_seen': None
        }
        return
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


def analyze_ip(ip_address):
    try:
        response = requests.get(f"https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip_address}")
        data = response.json()
        return data.get('country_code', 'Unknown'), data.get('fraud_score', 'Unknown')
    except Exception as e:
        print(f"IP analysis failed: {e}")
        return 'Unknown', 'Unknown'

def heuristic_analysis(vt_results, md_results, clamav_results, yara_scores, url_reputation_score, metadata_analysis, historical_data, file_path, results, ip_geolocation, ip_fraud_score):
    score = 0
    detailed_scores = []


    if vt_results['malicious'] > 2:
        score += 20
        detailed_scores.append('VirusTotal: High number of malicious detections (Score: 20)')
    elif vt_results['malicious'] > 0:
        score += 10
        detailed_scores.append('VirusTotal: Some malicious detections (Score: 10)')
    if vt_results['suspicious'] > 1:
        score += 5
        detailed_scores.append('VirusTotal: Suspicious detections (Score: 5)')


    if md_results['malicious'] > 2:
        score += 20
        detailed_scores.append('MetaDefender: High number of malicious detections (Score: 20)')
    elif md_results['malicious'] > 0:
        score += 10
        detailed_scores.append('MetaDefender: Some malicious detections (Score: 10)')


    if clamav_results['malicious'] > 0:
        score += 15
        detailed_scores.append('ClamAV: Malicious detection (Score: 15)')


    if yara_scores['total_score'] > 0:
        score += yara_scores['total_score']
        detailed_scores.extend(yara_scores['details'])


    if url_reputation_score == "url is not safe":
        if results.get('url_malicious_count', 0) > 5:
            score += 10
            detailed_scores.append('URL Reputation: High number of malicious detections (Score: 10)')
        else:
            score += 5
            detailed_scores.append('URL Reputation: Some malicious detections (Score: 5)')
    elif url_reputation_score == "clean":
        score += 0
        detailed_scores.append('URL Reputation: URL seems fine (Score: 0)')
    else:
        detailed_scores.append('URL Reputation: URL reputation could not be determined')


    if metadata_analysis.get('File size') and float(metadata_analysis['File size'].split()[0]) < 1:
        score += 10
        detailed_scores.append('Metadata: Very small file size (Score: 10)')
    if metadata_analysis.get('File extension') and metadata_analysis['File extension'] not in ALLOWED_EXTENSIONS:
        score += 15
        detailed_scores.append(f'Metadata: Suspicious file extension ({metadata_analysis["File extension"]}) (Score: 15)')


    file_size = os.path.getsize(file_path) / (1024 * 1024)  
    if file_size < 0.1:
        score += 10
        detailed_scores.append('File size: Very small file, potentially suspicious (Score: 10)')
    elif 0.1 <= file_size < 1:
        score += 5
        detailed_scores.append('File size: Small file, potentially suspicious (Score: 5)')
    elif file_size > 100:
        score += 15
        detailed_scores.append('File size: Very large file, potentially suspicious (Score: 15)')


    entropy = calculate_entropy(file_path)
    if entropy > 7:
        score += 10
        detailed_scores.append('Entropy: High entropy, potentially compressed or encrypted content (Score: 10)')
    elif 5 < entropy <= 7:
        score += 5
        detailed_scores.append('Entropy: Moderately high entropy, could be suspicious (Score: 5)')

    results['entropy'] = entropy


    if ip_geolocation == 'Unknown':
        score += 5
        detailed_scores.append('IP Geolocation: Unknown location (Score: 5)')
    if ip_fraud_score != 'Unknown' and int(ip_fraud_score) > 70:
        score += 10
        detailed_scores.append(f'IP Reputation: High fraud score ({ip_fraud_score}) (Score: 10)')

    return score, detailed_scores


def anomaly_detection(vt_results, md_results, clamav_results, yara_scores, metadata_analysis):
    score = 0
    detailed_scores = []


    if vt_results['total_scans'] > 0 and vt_results['malicious'] / vt_results['total_scans'] > 0.5:
        score += 20
        detailed_scores.append('Anomaly: High ratio of malicious detections in VirusTotal (Score: 20)')
    if md_results['total_scans'] > 0 and md_results['malicious'] / md_results['total_scans'] > 0.5:
        score += 20
        detailed_scores.append('Anomaly: High ratio of malicious detections in MetaDefender (Score: 20)')
    if metadata_analysis.get('File age (days)') and int(metadata_analysis['File age (days)']) < 1:
        score += 15
        detailed_scores.append('Anomaly: Very new file (Score: 15)')

    return score, detailed_scores

def behavioral_analysis(file_path):
    score = 0
    detailed_scores = []


    if file_path.startswith('.'):
        score += 10
        detailed_scores.append('Behavioral: Hidden file detected (Score: 10)')


    execution_behavior = False
    try:
        result = subprocess.run(['file', file_path], capture_output=True, text=True)
        if 'executable' in result.stdout:
            execution_behavior = True
            score += 20
            detailed_scores.append('Behavioral: File is an executable (Score: 20)')
    except Exception as e:
        detailed_scores.append(f'Behavioral: Execution behavior check failed ({str(e)})')


    fs_changes_detected = False
    monitored_directory = '/tmp'
    before = set(os.listdir(monitored_directory))
    try:
        subprocess.run(['cat', file_path])
        after = set(os.listdir(monitored_directory))
        if before != after:
            fs_changes_detected = True
            score += 15
            detailed_scores.append('Behavioral: File system changes detected (Score: 15)')
    except Exception as e:
        detailed_scores.append(f'Behavioral: File system changes check failed ({str(e)})')

    results = {
        'execution_behavior': execution_behavior,
        'fs_changes_detected': fs_changes_detected
    }

    return score, detailed_scores, results


def complex_algorithm(vt_results, md_results, clamav_results, yara_scores, url_reputation_score, metadata_analysis, historical_data, file_path, results, ip_geolocation, ip_fraud_score):
    heuristic_score, heuristic_details = heuristic_analysis(vt_results, md_results, clamav_results, yara_scores, url_reputation_score, metadata_analysis, historical_data, file_path, results, ip_geolocation, ip_fraud_score)
    anomaly_score, anomaly_details = anomaly_detection(vt_results, md_results, clamav_results, yara_scores, metadata_analysis)
    behavioral_score, behavioral_details, behavioral_results = behavioral_analysis(file_path)

    total_score = heuristic_score + anomaly_score + behavioral_score
    details = heuristic_details + anomaly_details + behavioral_details

    results['behavioral_analysis'] = behavioral_results


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
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed. Please upload a multimedia file.'}), 400
    if file:
        temp_dir = tempfile.mkdtemp()
        temp_file_path = os.path.join(temp_dir, file.filename)
        file.save(temp_file_path)

        download_url = request.form.get('download_url', '')
        result = main(temp_file_path, download_url)
        
        shutil.rmtree(temp_dir)  

        return jsonify(result)

def main(file_path, download_url):
    try:
        start_time = datetime.now()
        results = {}

        threads = [
            threading.Thread(target=upload_file_to_virustotal, args=(VT_API_KEY, file_path, results)),
            threading.Thread(target=upload_file_to_metadefender, args=(MD_API_KEY, file_path, results)),
            threading.Thread(target=scan_file_with_clamscan, args=(file_path, results)),
            threading.Thread(target=scan_file_with_yara, args=(file_path, YARA_RULES_PATH, results)),
            threading.Thread(target=check_url_reputation, args=(VT_API_KEY, download_url, results)),
            threading.Thread(target=analyze_file_metadata, args=(file_path, results)),
            threading.Thread(target=get_historical_data, args=(VT_API_KEY, calculate_file_hash(file_path), results))
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


        if 'vt_analysis_id' in results:
            results['vt_scan_report'] = get_vt_scan_report(VT_API_KEY, results['vt_analysis_id'])
        if 'md_data_id' in results:
            results['md_scan_report'] = get_md_scan_report(MD_API_KEY, results['md_data_id'])

        vt_results = extract_relevant_results_vt(results.get('vt_scan_report', {}))
        md_results = extract_relevant_results_md(results.get('md_scan_report', {}))
        clamav_results = results.get('clamav_results', {})
        yara_results = results.get('yara_results', {})
        yara_scores = results.get('yara_scores', {})
        url_reputation_score = results.get('url_reputation_score', '')
        metadata_analysis = results.get('metadata_analysis', {})
        historical_data = results.get('historical_data', {})
        ip_geolocation = results.get('ip_geolocation', 'N/A')
        ip_fraud_score = results.get('ip_fraud_score', 'N/A')

        final_score, details = complex_algorithm(
            vt_results, md_results, clamav_results, yara_scores, 
            url_reputation_score, metadata_analysis, historical_data, 
            file_path, results, ip_geolocation, ip_fraud_score
        )

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()  
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
            'duration': duration,
            'entropy': results.get('entropy', 0),
            'ip_geolocation': ip_geolocation,
            'ip_fraud_score': ip_fraud_score,
            'behavioral_analysis': results.get('behavioral_analysis', {})
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

