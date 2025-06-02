import pickle
import re
import requests
import time
import pymysql
import subprocess
import pandas as pd
import joblib
import os
import hashlib
import json
from flask import Flask, request, jsonify, send_from_directory
from sklearn.svm import SVC
from sklearn.feature_extraction.text import TfidfVectorizer

app = Flask(__name__)

# ==================== Configuration ====================
# Database connection
db = pymysql.connect(
    host="localhost",
    user="test",
    password="123456789cg.com",
    database="cyberguard"
)

# VirusTotal API key (shared between both services)
VIRUSTOTAL_API_KEY = "31367d58d206378dd5d95d866b4693e96b8bb818046e3b9d207a7e1836d5b9f0"

# File paths
UPLOAD_FOLDER = './uploads'
CACHE_FILE = 'apk_cache.json'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ==================== Model Loading ====================
def load_models():
    """Load ML models for text/spam detection"""
    with open('tfidf_vectorizer.pkl', 'rb') as f:
        tfidf = pickle.load(f)
    with open('svm_model.pkl', 'rb') as f:
        svc_classifier = pickle.load(f)
    return tfidf, svc_classifier

tfidf, svc_classifier = load_models()
apk_model = joblib.load('apk_model.pkl')  # APK detection model

# ==================== Utility Functions ====================
def check_url_virustotal(url, max_wait=30):
    """Check URL against VirusTotal"""
    base_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post(base_url, headers=headers, data={"url": url})
    if response.status_code != 200:
        return "UNKNOWN"

    result = response.json()
    url_id = result.get("data", {}).get("id")
    if not url_id:
        return "UNKNOWN"

    report_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
    elapsed_time = 0

    while elapsed_time < max_wait:
        report_response = requests.get(report_url, headers=headers)
        if report_response.status_code == 200:
            report_data = report_response.json()
            status = report_data.get("data", {}).get("attributes", {}).get("status", "")
            if status == "completed":
                stats = report_data.get("data", {}).get("attributes", {}).get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                return "SPAM" if malicious > 0 or suspicious > 0 else "SAFE"
        time.sleep(3)
        elapsed_time += 3

    return "UNKNOWN"

def extract_urls(text):
    """Extract URLs from text using regex"""
    url_pattern = r"(https?://[^\s]+)"
    return re.findall(url_pattern, text)

# ==================== APK Scanning Functions ====================
def load_cache():
    """Load cached APK scan results"""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_cache(cache):
    """Save APK scan results to cache"""
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f)

def get_cached_result(file_hash):
    """Get cached result for a file hash"""
    cache = load_cache()
    return cache.get(file_hash)

def store_result_in_cache(file_hash, result):
    """Store result in cache"""
    cache = load_cache()
    cache[file_hash] = result
    save_cache(cache)

def get_sha256(file_path):
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan_with_virustotal(file_hash):
    """Check APK hash against VirusTotal"""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)

    if response.status_code == 200:
        data = response.json()
        malicious_votes = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        return "Malware" if malicious_votes > 0 else "Benign"
    return "Unknown"

# ==================== API Endpoints ====================
@app.route('/check_url', methods=['POST'])
def check_url():
    """Check if a URL is malicious"""
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "Missing 'url' in request body"}), 400
    result = check_url_virustotal(url)
    return jsonify({"status": result})

@app.route('/predict_spam', methods=['POST'])
def predict_spam():
    """Predict if text contains spam"""
    data = request.get_json()
    email = data.get('email', '')

    if not email:
        return jsonify({"error": "No email provided"}), 400

    email_vector = tfidf.transform([email]).toarray()
    ml_prediction = svc_classifier.predict(email_vector)
    is_ml_spam = ml_prediction[0] == 1

    urls = extract_urls(email)
    is_url_spam = any(check_url_virustotal(url) == "SPAM" for url in urls)

    final_prediction = "spam" if is_ml_spam or is_url_spam else "ham"
    return jsonify({"prediction": final_prediction})

@app.route('/apk_scan', methods=['POST'])
def apk_scan():
    """Scan uploaded APK for malware"""
    try:
        apk_file = request.files['apk_file']
        apk_path = os.path.join(UPLOAD_FOLDER, apk_file.filename)
        apk_file.save(apk_path)

        file_hash = get_sha256(apk_path)

        # Check cache first
        cached_result = get_cached_result(file_hash)
        if cached_result:
            os.remove(apk_path)
            return jsonify({
                "result": cached_result,
                "sha256": file_hash,
                "cached": True
            }), 200

        # Run scans
        vt_result = scan_with_virustotal(file_hash)
        
        # ML Scan
        ml_result = "Unknown"
        try:
            subprocess.run(['python', 'features_extractor.py', apk_path], check=True)
            if os.path.exists('features.csv'):
                new_data = pd.read_csv('features.csv')
                X_new = new_data.drop(columns=['NAME'], errors='ignore')
                predictions = apk_model.predict(X_new)
                ml_result = 'Malware' if predictions[0] == 1 else 'Benign'
                os.remove('features.csv')
        except Exception as e:
            print(f"[ML Scan Error]: {str(e)}")

        # Determine final result
        if ml_result == "Malware" and vt_result == "Malware":
            final_result = "Malware"
        elif ml_result == "Benign" and vt_result == "Benign":
            final_result = "Benign"
        else:
            final_result = vt_result if ml_result == "Unknown" else ml_result

        # Cache and cleanup
        store_result_in_cache(file_hash, final_result)
        os.remove(apk_path)

        return jsonify({
            "result": final_result,
            "sha256": file_hash,
            "ml_result": ml_result,
            "vt_result": vt_result,
            "cached": False
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== User Management Endpoints ====================
@app.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required"}), 400

    cursor = db.cursor()
    query = "SELECT id, username FROM users WHERE email = %s AND password = %s"
    cursor.execute(query, (email, password))
    user = cursor.fetchone()

    if user:
        return jsonify({"success": True, "message": "Login successful", "id": user[0], "username": user[1]}), 200
    else:
        return jsonify({"success": False, "message": "Invalid email or password"}), 401

@app.route('/register', methods=['POST'])
def register():
    """User registration endpoint"""
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"success": False, "message": "All fields are required"}), 400

    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    if cursor.fetchone():
        return jsonify({"success": False, "message": "Email already registered"}), 409

    try:
        cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", 
                       (username, email, password))
        db.commit()
        return jsonify({"success": True, "message": "User registered successfully"}), 201
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

# ==================== Result Storage Endpoints ====================
@app.route('/store_url_result', methods=['POST'])
def store_url_result():
    """Store URL scan results"""
    data = request.get_json()
    user_id = data.get('userId')
    url = data.get('url')
    result = data.get('result')

    if not all([user_id, url, result]):
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO url_result (id, url, result) VALUES (%s, %s, %s)",
                       (user_id, url, result))
        db.commit()
        return jsonify({"success": True, "message": "URL result stored"}), 201
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/store_text_result', methods=['POST'])
def store_text_result():
    """Store text scan results"""
    data = request.get_json()
    user_id = data.get('userId')
    text = data.get('text')
    result = data.get('result')

    if not all([user_id, text, result]):
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO text_result (id, text, result) VALUES (%s, %s, %s)",
                       (user_id, text, result))
        db.commit()
        return jsonify({"success": True, "message": "Text result stored"}), 201
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/store_apk_result', methods=['POST'])
def store_apk_result():
    """Store APK scan results"""
    data = request.get_json()
    user_id = data.get('userId')
    apk_name = data.get('apk_name')
    apk_hash = data.get('hash')
    result = data.get('result')

    if not all([user_id, apk_name, apk_hash, result]):
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO malware_result (id, apk_name, hash, result) VALUES (%s, %s, %s, %s)",
                       (user_id, apk_name, apk_hash, result))
        db.commit()
        return jsonify({"success": True, "message": "APK result stored"}), 201
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

# ==================== History Endpoints ====================
@app.route('/history', methods=['POST'])
def get_history():
    """Get user scan history"""
    data = request.get_json()
    user_id = data.get('userId')

    if not user_id:
        return jsonify({"success": False, "message": "User ID required"}), 400

    cursor = db.cursor()
    history = []
    
    try:
        cursor.execute("SELECT url, result FROM url_result WHERE id = %s", (user_id,))
        for url, res in cursor.fetchall():
            history.append({"tool": "URL Scanning", "input": url, "result": res, "resultType": "URL Scan"})
        
        cursor.execute("SELECT text, result FROM text_result WHERE id = %s", (user_id,))
        for text, res in cursor.fetchall():
            history.append({"tool": "Text Scanning", "input": text, "result": res, "resultType": "Text Scan"})

        cursor.execute("SELECT apk_name, result FROM malware_result WHERE id = %s", (user_id,))
        for apk_name, res in cursor.fetchall():
            history.append({"tool": "APK Scanning", "input": apk_name, "result": res, "resultType": "Malware Scan"})
        
        return jsonify({"success": True, "history": history}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/delete_history', methods=['POST'])
def delete_history():
    """Delete specific history record"""
    data = request.get_json()
    user_id = data.get('userId')
    tool = data.get('tool')
    input_val = data.get('input')

    if not all([user_id, tool, input_val]):
        return jsonify({"success": False, "message": "Missing parameters"}), 400

    table_map = {
        "URL Scanning": ("url_result", "url"),
        "Text Scanning": ("text_result", "text"),
        "APK Scanning": ("malware_result", "apk_name")
    }

    if tool not in table_map:
        return jsonify({"success": False, "message": "Invalid tool"}), 400

    table, column = table_map[tool]
    cursor = db.cursor()
    
    try:
        cursor.execute(f"DELETE FROM {table} WHERE id = %s AND {column} = %s", 
                      (user_id, input_val))
        db.commit()
        
        if cursor.rowcount > 0:
            return jsonify({"success": True, "message": "Record deleted"}), 200
        else:
            return jsonify({"success": False, "message": "Record not found"}), 404
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

# ==================== Main Execution ====================
if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=6000)