import argparse
import asyncio
import aiohttp
from aiohttp import ClientSession, ClientTimeout
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from tqdm.asyncio import tqdm
import re
import signal
import sys
import logging
import json
import time
import robotsparser
import builtwith
import ssl
import socket
from datetime import datetime
from playwright.async_api import async_playwright

console = Console()
logging.basicConfig(
    filename='enhanced_crawler.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

api_pattern = re.compile(r'["\'](\/api\/[^\'"<>]+|\/graphql[^\'"<>]*)["\']', re.IGNORECASE)
json_pattern = re.compile(r'\.(json|xml|csv)[^\s\'"<>]+')
websocket_pattern = re.compile(r'(ws://|wss://)[^\s\'"<>]+')
fetch_xhr_pattern = re.compile(
    r'(fetch|XMLHttpRequest)\(.*?["\'](\/api\/[^\'"<>]+|\/graphql[^\'"<>]*)["\']',
    re.IGNORECASE
)
form_pattern = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.IGNORECASE)
hidden_field_pattern = re.compile(r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\']', re.IGNORECASE)

xss_pattern = re.compile(r'<script>alert\(1\)</script>', re.IGNORECASE)
sqli_pattern = re.compile(r"('.+--)|(--)|(%27)|(%23)", re.IGNORECASE)
open_redirect_pattern = re.compile(r'(https?://)', re.IGNORECASE)

security_headers = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Feature-Policy",
    "Permissions-Policy"
]

class CrawlerData:
    def __init__(self):
        self.visited_urls = set()
        self.all_api_urls = set()
        self.all_js_files = set()
        self.all_xhr_urls = set()
        self.all_form_actions = set()
        self.all_json_urls = set()
        self.all_websockets = set()
        self.all_hidden_fields = set()
        self.vulnerabilities = {
            'XSS': set(),
            'SQLi': set(),
            'Open Redirects': set()
        }
        self.security_headers = {}
        self.technologies = {}
        self.cookies = {}
        self.ssl_info = {}
        self.sensitive_files_found = set()
        self.errors = []

data = CrawlerData()
semaphore = None

def display_logo():
    logo = """
     \_______/
 `.,-'\_____/`-.,'
  /`..'\ _ /`.,'\
 /  /`.,' `.,'\  \
/__/__/     \__\__\__
\  \  \     /  /  /
 \  \,'`._,'`./  /
  \,'`./___\,'`./
 ,'`-./_____\,-'`.
     /       \
     Ly0kha                     
    """
    console.print(logo, style="bold red")

def get_args():
    parser = argparse.ArgumentParser(description="Advanced Web Crawler for Pentesters")
    parser.add_argument("url", help="The target URL", type=str)
    parser.add_argument("-d", "--depth", help="Crawling depth level", type=int, default=5)
    parser.add_argument("-b", "--breadth", help="Use breadth-first crawling (default is depth-first)", action="store_true")
    parser.add_argument("-t", "--timeout", help="Timeout for HTTP requests in seconds", type=int, default=10)
    parser.add_argument("-o", "--output", help="Save found data to an HTML, JSON, and CSV file", type=str, default=None)
    parser.add_argument("-r", "--rate", help="Max concurrent requests", type=int, default=10)
    parser.add_argument("-u", "--username", help="Username for authentication", type=str, default=None)
    parser.add_argument("-p", "--password", help="Password for authentication", type=str, default=None)
    parser.add_argument("-f", "--file-wordlist", help="Path to wordlist for sensitive file detection", type=str, default="common_files.txt")
    parser.add_argument("-j", "--js-render", help="Enable JavaScript rendering with Playwright", action="store_true")
    return parser.parse_args()

async def fetch_robots_txt(session: ClientSession, base_url: str):
    robots_url = urljoin(base_url, '/robots.txt')
    try:
        async with session.get(robots_url, timeout=ClientTimeout(total=10)) as response:
            if response.status == 200:
                text = await response.text()
                rp = robotsparser.RobotFileParser()
                rp.parse(text.splitlines())
                return rp
    except Exception as e:
        logging.warning(f"Failed to fetch robots.txt: {e}")
    return None

def is_allowed(url, rp):
    if rp:
        return rp.can_fetch("*", url)
    return True

async def fetch_page(session: ClientSession, url: str, timeout: int, render_js=False, playwright=None):
    try:
        if render_js and playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(url, timeout=timeout*1000)
            content = await page.content()
            await browser.close()
            return content
        else:
            async with session.get(url, timeout=ClientTimeout(total=timeout)) as response:
                if response.status == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                    return await response.text()
    except Exception as e:
        logging.error(f"Error fetching {url}: {e}")
        data.errors.append(f"Error fetching {url}: {e}")
    return None

async def fetch_js(session: ClientSession, js_url: str, timeout: int):
    try:
        async with session.get(js_url, timeout=ClientTimeout(total=timeout)) as response:
            if response.status == 200 and ('application/javascript' in response.headers.get('Content-Type', '') or 'text/javascript' in response.headers.get('Content-Type', '')):
                return await response.text()
    except Exception as e:
        logging.error(f"Error fetching JS file {js_url}: {e}")
        data.errors.append(f"Error fetching JS file {js_url}: {e}")
    return None

def analyze_js(js_content: str, base_url: str):
    api_matches = api_pattern.findall(js_content)
    for match in api_matches:
        full_url = urljoin(base_url, match)
        data.all_api_urls.add(full_url)

    xhr_matches = fetch_xhr_pattern.findall(js_content)
    for method, endpoint in xhr_matches:
        full_url = urljoin(base_url, endpoint)
        data.all_xhr_urls.add(full_url)

def extract_content(html: str, base_url: str):
    soup = BeautifulSoup(html, "html.parser")
    api_urls = set()
    js_files = set()
    xhr_requests = set()
    form_actions = set()
    json_urls = set()
    websocket_urls = set()
    hidden_fields = set()

    scripts = soup.find_all("script")
    for script in scripts:
        if script.string:
            api_matches = api_pattern.findall(script.string)
            for match in api_matches:
                full_url = urljoin(base_url, match)
                api_urls.add(full_url)
                data.all_api_urls.add(full_url)

            xhr_matches = fetch_xhr_pattern.findall(script.string)
            for method, endpoint in xhr_matches:
                full_url = urljoin(base_url, endpoint)
                xhr_requests.add(full_url)
                data.all_xhr_urls.add(full_url)

    js_files = {urljoin(base_url, script['src']) for script in soup.find_all("script", src=True)}
    data.all_js_files.update(js_files)

    forms = soup.find_all("form", action=True)
    for form in forms:
        action = urljoin(base_url, form['action'])
        form_actions.add(action)
        data.all_form_actions.add(action)
        hidden_inputs = form.find_all("input", {'type': 'hidden'})
        for inp in hidden_inputs:
            name = inp.get('name')
            value = inp.get('value', '')
            hidden_fields.add(f"{name}: {value}")
            data.all_hidden_fields.add(f"{name}: {value}")

    websocket_urls = set(websocket_pattern.findall(str(soup)))
    data.all_websockets.update(websocket_urls)

    links = soup.find_all("a", href=True)
    for link in links:
        href = link['href']
        if json_pattern.search(href):
            full_url = urljoin(base_url, href)
            json_urls.add(full_url)
            data.all_json_urls.add(full_url)

    page_text = soup.get_text()
    if xss_pattern.search(page_text):
        data.vulnerabilities['XSS'].add(base_url)
    if sqli_pattern.search(page_text):
        data.vulnerabilities['SQLi'].add(base_url)
    if open_redirect_pattern.search(page_text):
        data.vulnerabilities['Open Redirects'].add(base_url)

    return api_urls, js_files, xhr_requests, form_actions, json_urls, websocket_urls, hidden_fields

def analyze_security_headers(headers: dict, url: str):
    missing_headers = []
    for header in security_headers:
        if header not in headers:
            missing_headers.append(header)
    data.security_headers[url] = {
        'present': list(set(headers.keys()) & set(security_headers)),
        'missing': missing_headers
    }

def fingerprint_technologies(url: str):
    try:
        tech = builtwith.parse(url)
        data.technologies[url] = tech
    except Exception as e:
        logging.error(f"Error fingerprinting technologies for {url}: {e}")
        data.errors.append(f"Error fingerprinting technologies for {url}: {e}")

def analyze_cookies(cookies: aiohttp.CookieJar, url: str):
    parsed_url = urlparse(url)
    for cookie in cookies:
        cookie_details = {
            'domain': cookie['domain'],
            'path': cookie['path'],
            'secure': cookie['secure'],
            'httponly': cookie['httponly'],
            'samesite': cookie.get('samesite', 'None')
        }
        data.cookies[f"{cookie['name']}@{parsed_url.netloc}"] = cookie_details

def analyze_ssl(url: str):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssl_info = ssock.getpeercert()
                data.ssl_info[url] = ssl_info
    except Exception as e:
        logging.error(f"Error analyzing SSL for {url}: {e}")
        data.errors.append(f"Error analyzing SSL for {url}: {e}")

async def detect_sensitive_files(session: ClientSession, base_url: str, wordlist: list, timeout: int):
    tasks = []
    for word in wordlist:
        sensitive_url = urljoin(base_url, word)
        tasks.append(check_sensitive_file(session, sensitive_url, timeout))
    results = await asyncio.gather(*tasks)
    for result in results:
        if result and result not in data.sensitive_files_found:
            logging.info(f"Sensitive file found: {result}")
            data.sensitive_files_found.add(result)

async def check_sensitive_file(session: ClientSession, url: str, timeout: int):
    try:
        async with session.get(url, timeout=ClientTimeout(total=timeout)) as response:
            if response.status == 200 and 'text' in response.headers.get('Content-Type', ''):
                return url
    except Exception as e:
        pass
    return None

async def test_forms(session: ClientSession, forms: list, base_url: str, timeout: int):
    payloads = {
        'xss': '<script>alert(1)</script>',
        'sqli': "' OR '1'='1' -- "
    }
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        data_dict = {}
        for inp in inputs:
            name = inp.get('name')
            if not name:
                continue
            data_dict[name] = payloads.get('xss', 'test')
        target_url = urljoin(base_url, action)
        try:
            if method == 'post':
                async with session.post(target_url, data=data_dict, timeout=ClientTimeout(total=timeout)) as response:
                    content = await response.text()
                    if payloads['xss'] in content:
                        data.vulnerabilities['XSS'].add(target_url)
            else:
                async with session.get(target_url, params=data_dict, timeout=ClientTimeout(total=timeout)) as response:
                    content = await response.text()
                    if payloads['xss'] in content:
                        data.vulnerabilities['XSS'].add(target_url)
        except Exception as e:
            logging.error(f"Error testing form at {target_url}: {e}")
            data.errors.append(f"Error testing form at {target_url}: {e}")

async def async_fingerprint_technologies(urls: list):
    loop = asyncio.get_event_loop()
    for url in urls:
        await loop.run_in_executor(None, fingerprint_technologies, url)

async def async_ssl_analysis(urls: list):
    loop = asyncio.get_event_loop()
    for url in urls:
        await loop.run_in_executor(None, analyze_ssl, url)

def extract_links(html: str, base_url: str, base_netloc: str):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all(["a", "link"], href=True):
        href = tag['href']
        parsed_href = urlparse(href)
        if parsed_href.scheme in ['http', 'https', '']:
            full_url = urljoin(base_url, href)
            full_url = full_url.split('#')[0]
            if is_valid_url(full_url):
                full_url_parsed = urlparse(full_url)
                if full_url_parsed.netloc == base_netloc:
                    links.add(full_url)
    return links

def is_valid_url(url: str):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def save_results(output_prefix: str):
    timestamp = int(time.time())
    html_file = f"{output_prefix}_{timestamp}.html"
    json_file = f"{output_prefix}_{timestamp}.json"
    csv_file = f"{output_prefix}_{timestamp}.csv"

    html_content = f"""
    <html>
    <head>
        <title>Scan Results for {output_prefix}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #1e1e1e;
                color: #dcdcdc;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                background-color: #2e2e2e;
            }}
            th, td {{
                border: 1px solid #444;
                padding: 10px;
                text-align: left;
            }}
            th {{
                background-color: #3e3e3e;
                color: #dcdcdc;
            }}
            td {{
                color: #f5f5f5;
            }}
        </style>
    </head>
    <body>
        <h1>Scan Results for {output_prefix}</h1>
        {generate_html_section("API URLs Found", ["No.", "API URL"], data.all_api_urls)}
        {generate_html_section("JavaScript Files Found", ["No.", "JS File"], data.all_js_files)}
        {generate_html_section("XHR/Fetch Requests", ["No.", "Request"], data.all_xhr_urls)}
        {generate_html_section("Form Actions Found", ["No.", "Action URL"], data.all_form_actions)}
        {generate_html_section("WebSocket Connections", ["No.", "WebSocket URL"], data.all_websockets)}
        {generate_html_section("Hidden Form Fields", ["No.", "Field"], data.all_hidden_fields)}
        {generate_html_section("Sensitive Files Found", ["No.", "File URL"], data.sensitive_files_found)}
        {generate_vulnerability_section()}
        {generate_security_headers_section()}
        {generate_technology_section()}
        {generate_cookies_section()}
        {generate_ssl_section()}
    </body>
    </html>
    """

    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    console.print(f"[green]HTML report saved to {html_file}[/green]")

    json_data = {
        'api_urls': list(data.all_api_urls),
        'js_files': list(data.all_js_files),
        'xhr_requests': list(data.all_xhr_urls),
        'form_actions': list(data.all_form_actions),
        'json_urls': list(data.all_json_urls),
        'websockets': list(data.all_websockets),
        'hidden_fields': list(data.all_hidden_fields),
        'sensitive_files_found': list(data.sensitive_files_found),
        'vulnerabilities': {k: list(v) for k, v in data.vulnerabilities.items()},
        'security_headers': data.security_headers,
        'technologies': data.technologies,
        'cookies': data.cookies,
        'ssl_info': data.ssl_info,
        'errors': data.errors
    }

    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=4)
    console.print(f"[green]JSON report saved to {json_file}[/green]")

    with open(csv_file, 'w', encoding='utf-8') as f:
        f.write("Type,Detail\n")
        for api in data.all_api_urls:
            f.write(f"API URL,{api}\n")
        for js in data.all_js_files:
            f.write(f"JS File,{js}\n")
        for xhr in data.all_xhr_urls:
            f.write(f"XHR Request,{xhr}\n")
        for action in data.all_form_actions:
            f.write(f"Form Action,{action}\n")
        for ws in data.all_websockets:
            f.write(f"WebSocket,{ws}\n")
        for hidden in data.all_hidden_fields:
            f.write(f"Hidden Field,{hidden}\n")
        for sensitive in data.sensitive_files_found:
            f.write(f"Sensitive File,{sensitive}\n")
    console.print(f"[green]CSV report saved to {csv_file}[/green]")

def generate_html_section(title: str, headers: list, data_set: set):
    table_html = f"<h2>{title}</h2><table><tr>"
    for header in headers:
        table_html += f"<th>{header}</th>"
    table_html += "</tr>"
    for i, item in enumerate(sorted(data_set), 1):
        table_html += f"<tr><td>{i}</td><td>{item}</td></tr>"
    table_html += "</table>"
    return table_html

def generate_vulnerability_section():
    section = "<h2>Vulnerabilities Found</h2>"
    for vuln, urls in data.vulnerabilities.items():
        section += f"<h3>{vuln}</h3><ul>"
        for url in urls:
            section += f"<li>{url}</li>"
        section += "</ul>"
    return section

def generate_security_headers_section():
    section = "<h2>Security Headers Analysis</h2>"
    for url, headers in data.security_headers.items():
        section += f"<h3>{url}</h3><ul>"
        section += f"<li>Present Headers: {', '.join(headers['present']) if headers['present'] else 'None'}</li>"
        section += f"<li>Missing Headers: {', '.join(headers['missing']) if headers['missing'] else 'None'}</li>"
        section += "</ul>"
    return section

def generate_technology_section():
    section = "<h2>Technology Fingerprinting</h2>"
    for url, tech in data.technologies.items():
        section += f"<h3>{url}</h3><ul>"
        for category, items in tech.items():
            section += f"<li><strong>{category}:</strong> {', '.join(items)}</li>"
        section += "</ul>"
    return section

def generate_cookies_section():
    section = "<h2>Cookie Analysis</h2>"
    for cookie, details in data.cookies.items():
        section += f"<h3>{cookie}</h3><ul>"
        for key, value in details.items():
            section += f"<li><strong>{key}:</strong> {value}</li>"
        section += "</ul>"
    return section

def generate_ssl_section():
    section = "<h2>SSL/TLS Configuration</h2>"
    for url, ssl_info in data.ssl_info.items():
        section += f"<h3>{url}</h3><pre>{json.dumps(ssl_info, indent=4)}</pre>"
    return section

def display_results():
    def create_table(title, headers, data_set):
        table = Table(title=title, show_lines=True)
        for header in headers:
            table.add_column(header, style="cyan")
        for i, item in enumerate(sorted(data_set), 1):
            table.add_row(str(i), item)
        return table

    console.print(create_table("API URLs Found", ["No.", "API URL"], data.all_api_urls))
    console.print(create_table("JavaScript Files Found", ["No.", "JS File"], data.all_js_files))
    console.print(create_table("XHR/Fetch Requests", ["No.", "Request"], data.all_xhr_urls))
    console.print(create_table("Form Actions Found", ["No.", "Action URL"], data.all_form_actions))
    console.print(create_table("WebSocket Connections", ["No.", "WebSocket URL"], data.all_websockets))
    console.print(create_table("Hidden Form Fields", ["No.", "Field"], data.all_hidden_fields))
    console.print(create_table("Sensitive Files Found", ["No.", "File URL"], data.sensitive_files_found))

    vuln_table = Table(title="Vulnerabilities Found", show_lines=True)
    vuln_table.add_column("Type", style="red")
    vuln_table.add_column("Affected URLs", style="magenta")
    for vuln, urls in data.vulnerabilities.items():
        vuln_table.add_row(vuln, ', '.join(urls) if urls else 'None')
    console.print(vuln_table)

    headers_table = Table(title="Security Headers Analysis", show_lines=True)
    headers_table.add_column("URL", style="green")
    headers_table.add_column("Present Headers", style="blue")
    headers_table.add_column("Missing Headers", style="yellow")
    for url, headers in data.security_headers.items():
        headers_table.add_row(
            url,
            ', '.join(headers['present']) if headers['present'] else 'None',
            ', '.join(headers['missing']) if headers['missing'] else 'None'
        )
    console.print(headers_table)

    tech_table = Table(title="Technology Fingerprinting", show_lines=True)
    tech_table.add_column("URL", style="green")
    tech_table.add_column("Technologies", style="blue")
    for url, tech in data.technologies.items():
        tech_list = []
        for category, items in tech.items():
            tech_list.append(f"{category}: {', '.join(items)}")
        tech_table.add_row(url, '\n'.join(tech_list))
    console.print(tech_table)

    cookies_table = Table(title="Cookie Analysis", show_lines=True)
    cookies_table.add_column("Cookie", style="green")
    cookies_table.add_column("Attributes", style="blue")
    for cookie, details in data.cookies.items():
        attrs = ', '.join([f"{k}={v}" for k, v in details.items()])
        cookies_table.add_row(cookie, attrs)
    console.print(cookies_table)

    ssl_table = Table(title="SSL/TLS Configuration", show_lines=True)
    ssl_table.add_column("URL", style="green")
    ssl_table.add_column("SSL Info", style="blue")
    for url, ssl_info in data.ssl_info.items():
        ssl_details = json.dumps(ssl_info, indent=2)
        ssl_table.add_row(url, ssl_details)
    console.print(ssl_table)

def shutdown_handler(signal_num, frame):
    console.print("[bold yellow]Crawling interrupted! Shutting down...[/bold yellow]")
    sys.exit(0)

async def main_async(args):
    global semaphore
    semaphore = asyncio.Semaphore(args.rate)

    timeout = args.timeout
    base_url = args.url
    depth_limit = args.depth
    breadth_first = args.breadth
    render_js = args.js_render

    parsed_base_url = urlparse(base_url)
    base_netloc = parsed_base_url.netloc

    try:
        with open(args.file_wordlist, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except Exception as e:
        console.print(f"[bold red]Failed to load wordlist from {args.file_wordlist}: {e}[/bold red]")
        sys.exit(1)

    auth = None
    if args.username and args.password:
        auth = aiohttp.BasicAuth(args.username, args.password)

    playwright = None
    if render_js:
        try:
            playwright = await async_playwright().start()
        except Exception as e:
            console.print(f"[bold red]Failed to start Playwright: {e}[/bold red]")
            sys.exit(1)

    async with aiohttp.ClientSession(auth=auth) as session:
        rp = await fetch_robots_txt(session, base_url)
        if not is_allowed(base_url, rp):
            console.print(f"[bold red]Crawling disallowed by robots.txt for {base_url}[/bold red]")
            return

        if breadth_first:
            queue = deque([(base_url, 0)])
        else:
            queue = deque([(base_url, 0)])

        if render_js and playwright:
            browser = await playwright.chromium.launch(headless=True)
            page = await browser.new_page()

        progress = Progress()
        progress_task = progress.add_task("Crawling Progress", total=depth_limit * 100)
        progress.start()

        while queue:
            current_url, depth = queue.popleft()
            if current_url in data.visited_urls or depth > depth_limit:
                continue

            if not is_allowed(current_url, rp):
                logging.info(f"Disallowed by robots.txt: {current_url}")
                continue

            async with semaphore:
                if render_js and playwright:
                    try:
                        await page.goto(current_url, timeout=timeout*1000)
                        html = await page.content()
                        cookies = await page.context.cookies()
                        for cookie in cookies:
                            data.cookies[f"{cookie['name']}@{urlparse(current_url).netloc}"] = {
                                'domain': cookie['domain'],
                                'path': cookie['path'],
                                'secure': cookie['secure'],
                                'httponly': cookie['httponly'],
                                'samesite': cookie.get('samesite', 'None')
                            }
                    except Exception as e:
                        logging.error(f"Error rendering {current_url} with Playwright: {e}")
                        data.errors.append(f"Error rendering {current_url} with Playwright: {e}")
                        html = await fetch_page(session, current_url, timeout, render_js=False)
                else:
                    html = await fetch_page(session, current_url, timeout, render_js=False)

                if not html:
                    continue

                data.visited_urls.add(current_url)

                try:
                    async with session.get(current_url, timeout=ClientTimeout(total=timeout)) as response:
                        headers = response.headers
                        analyze_security_headers(headers, current_url)
                except Exception as e:
                    logging.error(f"Error fetching headers for {current_url}: {e}")
                    data.errors.append(f"Error fetching headers for {current_url}: {e}")

                api_urls, js_files, xhr_requests, form_actions, json_urls, websocket_urls, hidden_fields = extract_content(html, current_url)

                tasks = [fetch_js(session, js_url, timeout) for js_url in js_files]
                js_contents = await asyncio.gather(*tasks)
                for js_content in js_contents:
                    if js_content:
                        analyze_js(js_content, current_url)

                fingerprint_technologies(current_url)
                analyze_ssl(current_url)
                await detect_sensitive_files(session, current_url, wordlist, timeout)
                soup = BeautifulSoup(html, "html.parser")
                forms = soup.find_all("form")
                await test_forms(session, forms, current_url, timeout)

                new_links = extract_links(html, current_url, base_netloc)
                for link in new_links:
                    if link not in data.visited_urls:
                        if breadth_first:
                            queue.append((link, depth + 1))
                        else:
                            queue.appendleft((link, depth + 1))

                progress.update(progress_task, advance=1)

        progress.stop()

        if render_js and playwright:
            await browser.close()
            await playwright.stop()

    await async_fingerprint_technologies(list(data.technologies.keys()))
    await async_ssl_analysis(list(data.technologies.keys()))

    if args.output:
        save_results(args.output)
    else:
        display_results()

def main():
    display_logo()
    args = get_args()
    signal.signal(signal.SIGINT, shutdown_handler)
    console.print(f"Starting advanced recon for [bold blue]{args.url}[/bold blue] up to depth {args.depth}")
    asyncio.run(main_async(args))

if __name__ == "__main__":
    main()
