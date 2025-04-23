# XSSCrawl - A Web Crawler for XSS and SQLi Vulnerability Detection

XSSCrawl is a Python-based web crawler designed to detect Cross-Site Scripting (XSS) and SQL Injection (SQLi) vulnerabilities in web applications. It crawls a target website, tests forms and URL parameters with predefined payloads, and identifies potential vulnerabilities by checking for payload reflections (for XSS) and error patterns or time delays (for SQLi). This tool is intended for **ethical security testing** on websites where explicit permission has been granted, such as deliberately vulnerable applications.

## Features
- Crawls websites to discover pages and forms up to a specified depth.
- Tests forms and URL query parameters for XSS and SQLi vulnerabilities.
- Detects both reflected and stored XSS by revisiting pages.
- Supports time-based SQLi detection through response delay analysis.
- Allows authentication via session cookies for testing protected pages.
- Supports customizable payloads and testing modes (XSS, SQLi, or both).
- Logs vulnerabilities to both a file and the console.

## Prerequisites
- **Python 3.6 or higher**: Ensure Python 3 is installed.
- **pip**: Python’s package manager for installing dependencies.
- **Docker (Optional)**: For setting up vulnerable test applications (e.g., DVWA, Mutillidae).

## Installation

### 1. Download the Script
Obtain the `xssCrawl.py` script and `requirements.txt` file. These can be downloaded from the repository or copied into a working directory.

### 2. Set Up a Virtual Environment (Recommended)
To avoid dependency conflicts, create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

To deactivate the virtual environment later, run:

```bash
deactivate
```

### 3. Install Dependencies
Install the required Python libraries using the provided `requirements.txt`:

```bash
pip install -r requirements.txt
```

The `requirements.txt` includes:

- `Scrapy==2.11.2`: For web crawling and HTTP requests.
- `lxml==5.3.0`: For HTML parsing.

#### Additional Setup for Linux
On some Linux systems, you may need to install system dependencies for `lxml`:

```bash
sudo apt update
sudo apt install libxml2-dev libxslt1-dev python3-dev zlib1g-dev
```

### 4. Verify Installation
Confirm that the dependencies are installed:

```bash
pip list
```

Look for `Scrapy` (2.11.2) and `lxml` (5.3.0) in the output.

## Usage
XSSCrawl is a command-line tool that accepts several arguments to configure its behavior. The basic syntax is:

```bash
python xssCrawl.py -u <target-url> [options]
```

### Command-Line Arguments
- `-u, --url` (required): The starting URL to crawl (e.g., `http://example.com`).
- `-o, --output` (default: `vulnerabilities.txt`): File to save detected vulnerabilities.
- `-d, --depth` (default: 5): Maximum crawl depth to limit the scope.
- `-c, --concurrency` (default: 10): Number of concurrent requests.
- `--cookie` (optional): Session cookie for authenticated requests (e.g., `"session=abc123"`).
- `--xss-payloads` (optional): Space-separated custom XSS payloads.
- `--sqli-payloads` (optional): Space-separated custom SQLi payloads.
- `--no-xss` (optional): Disable XSS testing.
- `--no-sqli` (optional): Disable SQLi testing.

### Basic Example
Crawl a public website without authentication:

```bash
python xssCrawl.py -u http://example.com -o results.txt -d 5 -c 5
```

### Example with Authentication
Crawl a site requiring login. First, obtain the session cookie:

1. Open your browser’s developer tools (F12).
2. Log in to the target site.
3. Go to the “Network” tab, refresh the page, and find the `Cookie` header (e.g., `session=abc123`).

Run the script with the cookie:

```bash
python xssCrawl.py -u http://example.com -o results.txt -d 5 -c 5 --cookie "session=abc123"
```

### Example with Custom Payloads
Test with custom XSS payloads:

```bash
python xssCrawl.py -u http://example.com -o results.txt -d 5 -c 5 --xss-payloads "<iframe onload=alert(1)>" "<div onfocus=alert(1)>"
```

### Example with Only SQLi Testing
Disable XSS testing to focus on SQLi:

```bash
python xssCrawl.py -u http://example.com -o results.txt -d 5 -c 5 --no-xss
```

## Output
The script logs vulnerabilities to both the console and the specified output file. Example output:

```
2025-04-23 07:30:00 [INFO] Starting crawl on http://example.com with max depth 5
2025-04-23 07:30:05 [WARNING] [XSS] Payload '<script>alert(1)</script>' reflected in http://example.com/page?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E (from http://example.com/page)
2025-04-23 07:30:10 [WARNING] [SQLi] Potential SQL injection in http://example.com/login?id=%27+OR+%271%27%3D%271 with payload '' OR '1'='1' (from http://example.com/login)
2025-04-23 07:30:15 [INFO] Saved 2 vulnerabilities to results.txt
```

The `results.txt` file will contain:

```
[XSS] Payload '<script>alert(1)</script>' reflected in http://example.com/page?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E (from http://example.com/page)
[SQLi] Potential SQL injection in http://example.com/login?id=%27+OR+%271%27%3D%271 with payload '' OR '1'='1' (from http://example.com/login)
```

## Setting Up Test Environments
XSSCrawl should only be used on websites where explicit permission has been granted. Below are some deliberately vulnerable applications for testing:

### 1. Damn Vulnerable Web Application (DVWA)
```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```
- Access: `http://localhost/dvwa`
- Default credentials: `admin`/`password`
- Set security to “Low” for easier vulnerability detection.

### 2. OWASP Mutillidae II
```bash
docker run -d -p 80:80 citizenstig/owasp-mutillidae-ii
```
- Access: `http://localhost/mutillidae`
- No authentication required by default.

### 3. OWASP Juice Shop
```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
```
- Access: `http://localhost:3000`
- No authentication required for most features.

### 4. Google Gruyere
- Access: `https://google-gruyere.appspot.com/`
- Start a new instance to get a unique URL.
- Default credentials: `kdot`/`password`

## Ethical Considerations
- **Permission**: Only scan websites you own or have explicit permission to test. Unauthorized scanning is illegal and unethical.
- **Responsible Use**: This tool is for educational and ethical security testing. Do not use it to harm systems or networks.
- **Bug Bounties**: If using XSSCrawl in a bug bounty program, ensure compliance with the program’s rules (e.g., rate limiting, scope).

## Troubleshooting

### 1. No Vulnerabilities Found
- **Authentication**: If the site requires login, ensure a valid session cookie is provided via `--cookie`.
- **Depth**: Increase the crawl depth (e.g., `-d 7`) to explore more pages.
- **Payloads**: Use custom payloads via `--xss-payloads` or `--sqli-payloads` to test for specific vulnerabilities.
- **Site Setup**: Verify the target site has vulnerabilities (e.g., set DVWA security to “Low”).

### 2. HTTP Errors (e.g., 403 Forbidden)
- **User-Agent**: Some sites may block the default User-Agent. Modify the `USER_AGENT` in the script if needed.
- **Rate Limiting**: Reduce concurrency (e.g., `-c 5`) to avoid overwhelming the server.
- **Cookies**: Ensure the session cookie is valid and not expired.

### 3. Installation Issues
- **Linux Dependencies**: Install system libraries for `lxml` if errors occur:
  ```bash
  sudo apt install libxml2-dev libxslt1-dev python3-dev zlib1g-dev
  ```
- **Python Version**: Ensure Python 3.6 or higher is installed (`python3 --version`).
- **Virtual Environment**: Use a virtual environment to avoid dependency conflicts.

### 4. Script Errors
- **Traceback**: Check the error message for details and ensure all dependencies are installed.
- **Logging**: Add debug logging to the script (e.g., `logger.debug`) to diagnose issues.
