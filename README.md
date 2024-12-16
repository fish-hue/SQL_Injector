# SQL Injection Testing Script

This script is designed to perform **SQL Injection** testing on a target URL by injecting a series of predefined SQL payloads into specified URL parameters. It checks for potential SQL injection vulnerabilities based on different detection methods, including error messages, unusually large response sizes, and HTTP status codes.

### Features:
- **SQL Payloads**: A list of common SQL injection payloads that target different types of vulnerabilities.
- **Logging**: Logs each test result to `sql_injection_tests.log` for review.
- **Error Detection**: Checks for errors or unusual behavior indicative of SQL injection vulnerabilities.
- **Response Size Detection**: Flags unusually large responses that may suggest a vulnerability.
- **Customizable Delay & Threshold**: Allows customization of request delay and response size threshold to prevent flooding the server and adjust anomaly detection.

---

## Prerequisites

Before running the script, you need to install the `requests` library:

```bash
pip install requests
```

Ensure that you have Python 3.x or later installed.

---

## How to Use

### 1. Run the Script:
Once the prerequisites are set up, you can run the script with the following command:

- White Hat Ethical Testing:

```bash
python3 WhiteHat_SQL_injection.py
```

- Red Hat for Pentesting: **WARNING: RedHat_SQL_Injection.py is a very dangerous tool, only use with permission for testing purposes!

```bash
RedHat_SQL_injection.py 
```

### 2. Provide User Input:
The script will prompt you for the following inputs:

- **Target URL**: The URL to test for SQL injection (e.g., `https://example.com`).
- **Parameters to Test**: A comma-separated list of parameters you want to test for SQL injection (e.g., `id, name`).
- **Delay Between Requests**: The number of seconds to wait between each request (default is `1` second).
- **Response Size Threshold**: The response size threshold (in characters) to flag unusually large responses as potential indicators of SQL injection (default is `1000` characters).

Example input:
```
Enter the target URL (e.g., https://example.com): https://example.com/search
Enter the parameters to test (comma-separated, e.g., 'id,name'): id, name
Enter the delay (in seconds) between requests (default 1 second): 1
Enter the response size threshold for anomaly detection (default 1000 characters): 1000
```

### 3. Review the Results:
The script will test each URL parameter with each SQL payload and log the results. Any detected vulnerabilities will be printed to the console and logged in the `sql_injection_tests.log` file.

Example output:
```
Testing for potential SQL Injection vulnerabilities...

[Vulnerability Found] id with payload '' OR '1'='1' caused server error (status code 500).
[Vulnerability Found] id with payload '' OR '1'='2' returned an error message indicative of a SQL injection vulnerability.
...

SQL Injection testing completed.
Total tests conducted: 10
Vulnerabilities found: 3
```

The log file (`sql_injection_tests.log`) will contain detailed information about each test, including URLs, payloads, and any detected vulnerabilities.

---

## Example Log File (`sql_injection_tests.log`)

```
2024-12-16 16:00:00 - [Vulnerability Found] id with payload '' OR '1'='1' caused server error (status code 500).
2024-12-16 16:01:05 - [Vulnerability Found] name with payload '' OR '1'='2' returned an error message indicative of a SQL injection vulnerability.
2024-12-16 16:02:45 - [Vulnerability Found] id with payload '' UNION SELECT NULL-- returned an unusually large response size > 1000 characters.
...
```

---

## Troubleshooting

### "Invalid URL" error
- Ensure that the URL you enter starts with `http://` or `https://` and is formatted correctly.

### "Error occurred during request"
- This can happen if the server is unavailable, or if there is a network issue. Check the server's availability and try again.

### "No vulnerabilities found"
- This means that the injected payloads did not trigger any SQL errors, response size anomalies, or server errors. This is a positive outcome indicating the absence of SQL injection vulnerabilities, but it's always good to conduct manual testing or use more advanced techniques.

---

## License

This script is provided for educational and testing purposes only. Use it responsibly on applications you own or have explicit permission to test.

