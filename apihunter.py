import argparse
import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse
from collections import deque
from rich.console import Console
from rich.table import Table
from tqdm import tqdm
import re
import signal
import sys

console = Console()
visited_urls = set()
all_api_urls = set()
all_js_files = set()
all_xhr_urls = set()
all_form_actions = set()
all_json_urls = set()
all_websockets = set()
all_hidden_fields = set()
progress_bar = None


api_pattern = re.compile(r'["\'](\/api\/[^\'"<>]+|\/graphql[^\'"<>]*)["\']', re.IGNORECASE)
json_pattern = re.compile(r'\.(json|xml|csv)[^\s\'"<>]+')
websocket_pattern = re.compile(r'(ws://|wss://)[^\s\'"<>]+')
fetch_xhr_pattern = re.compile(r'(fetch|XMLHttpRequest)\(.*?["\'](\/api\/[^\'"<>]+|\/graphql[^\'"<>]*)["\']', re.IGNORECASE)
form_pattern = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.IGNORECASE)
hidden_field_pattern = re.compile(r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\']', re.IGNORECASE)

def accessi_logo():
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
    parser = argparse.ArgumentParser(description="Happy Hunting")
    parser.add_argument("url", help="the target URL", type=str)
    parser.add_argument("-d", "--depth", help="Scraping depth level", type=int, default=5)
    parser.add_argument("-b", "--breadth", help="Use breadth-first scraping", action="store_true")
    parser.add_argument("-t", "--timeout", help="Timeout for HTTP requests", type=int, default=10)
    parser.add_argument("-o", "--output", help="Save found API URLs to an HTML file", type=str, default=None)
    return parser.parse_args()

def fetch_page(url, timeout):
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return response.content
    except requests.RequestException as e:
        console.print(f"[bold red]Error fetching {url}: {e}")
        return None

def fetch_js_file_content(js_file_url, timeout):
    try:
        response = requests.get(js_file_url, timeout=timeout)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        console.print(f"[bold red]Error fetching JS file {js_file_url}: {e}")
        return None

def analyze_js_file_content(js_content, base_url):
    api_urls = set()
    
    
    api_matches = api_pattern.findall(js_content)
    api_urls.update([urljoin(base_url, match) for match in api_matches])

    
    xhr_matches = fetch_xhr_pattern.findall(js_content)
    for match in xhr_matches:
        api_urls.add(f"XHR/Fetch Request: {match}")

    return api_urls

def extract_content(html, base_url):
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
            
            matches = api_pattern.findall(script.string)
            api_urls.update([urljoin(base_url, match) for match in matches])

            
            xhr_matches = fetch_xhr_pattern.findall(script.string)
            for match in xhr_matches:
                xhr_requests.add(f"XHR/Fetch Request: {match}")

    
    js_files.update([urljoin(base_url, script['src']) for script in soup.find_all("script", src=True)])

   
    forms = soup.find_all("form", action=True)
    for form in forms:
        form_action = urljoin(base_url, form['action'])
        form_actions.add(form_action)
        hidden_inputs = form.find_all("input", {'type': 'hidden'})
        hidden_fields.update({f"{inp.get('name')}: {inp.get('value')}" for inp in hidden_inputs})

    
    websocket_urls.update([match for match in websocket_pattern.findall(str(soup))])

    
    json_urls.update([urljoin(base_url, link['href']) for link in soup.find_all("a", href=True) if json_pattern.search(link['href'])])

    return api_urls, js_files, xhr_requests, form_actions, json_urls, websocket_urls, hidden_fields

def save_results_to_html(output_file):
    html_content = f"""
    <html>
    <head>
        <title>API URLs Found</title>
        <style>
            body {{
                font-family: "Courier New", Courier, monospace;
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
        <h1>API URLs Found</h1>
        <table>
            <tr><th>No.</th><th>API URL</th></tr>
    """
    
    for i, api_url in enumerate(all_api_urls, 1):
        html_content += f'<tr><td>{i}</td><td>{api_url}</td></tr>'
    
    html_content += "</table><h2>JavaScript Files</h2><table><tr><th>No.</th><th>JS File</th></tr>"
    for i, js_file in enumerate(all_js_files, 1):
        html_content += f'<tr><td>{i}</td><td>{js_file}</td></tr>'

    html_content += "</table><h2>XHR/Fetch Requests</h2><table><tr><th>No.</th><th>Request</th></tr>"
    for i, xhr in enumerate(all_xhr_urls, 1):
        html_content += f'<tr><td>{i}</td><td>{xhr}</td></tr>'

    html_content += "</table><h2>Form Actions</h2><table><tr><th>No.</th><th>Action URL</th></tr>"
    for i, action in enumerate(all_form_actions, 1):
        html_content += f'<tr><td>{i}</td><td>{action}</td></tr>'

    html_content += "</table><h2>WebSocket Connections</h2><table><tr><th>No.</th><th>WebSocket URL</th></tr>"
    for i, ws in enumerate(all_websockets, 1):
        html_content += f'<tr><td>{i}</td><td>{ws}</td></tr>'

    html_content += "</table><h2>Hidden Form Fields</h2><table><tr><th>No.</th><th>Field</th></tr>"
    for i, hidden in enumerate(all_hidden_fields, 1):
        html_content += f'<tr><td>{i}</td><td>{hidden}</td></tr>'

    html_content += "</table></body></html>"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    console.print(f"Results saved to {output_file}")

def display_results_in_terminal():
    
    table = Table(title="API URLs Found")
    table.add_column("No.", justify="center")
    table.add_column("API URL", justify="left")
    for i, api_url in enumerate(all_api_urls, 1):
        table.add_row(str(i), api_url)
    console.print(table)

    
    table = Table(title="JavaScript Files Found")
    table.add_column("No.", justify="center")
    table.add_column("JS File", justify="left")
    for i, js_file in enumerate(all_js_files, 1):
        table.add_row(str(i), js_file)
    console.print(table)

    
    table = Table(title="XHR/Fetch Requests")
    table.add_column("No.", justify="center")
    table.add_column("Request", justify="left")
    for i, xhr in enumerate(all_xhr_urls, 1):
        table.add_row(str(i), xhr)
    console.print(table)

    
    table = Table(title="Form Actions Found")
    table.add_column("No.", justify="center")
    table.add_column("Action URL", justify="left")
    for i, action in enumerate(all_form_actions, 1):
        table.add_row(str(i), action)
    console.print(table)

    
    table = Table(title="WebSocket Connections")
    table.add_column("No.", justify="center")
    table.add_column("WebSocket URL", justify="left")
    for i, ws in enumerate(all_websockets, 1):
        table.add_row(str(i), ws)
    console.print(table)

    
    table = Table(title="Hidden Form Fields")
    table.add_column("No.", justify="center")
    table.add_column("Field", justify="left")
    for i, hidden in enumerate(all_hidden_fields, 1):
        table.add_row(str(i), hidden)
    console.print(table)

def crawl(url, depth_limit, timeout, args):
    global progress_bar  
    queue = deque([(url, 0)])
    if args.output:
        progress_bar = tqdm(total=depth_limit, desc="Crawling Progress")

    while queue:
        current_url, depth = queue.popleft()
        if depth > depth_limit or current_url in visited_urls:
            continue

        html = fetch_page(current_url, timeout)
        if not html:
            continue

        api_urls, js_files, xhr_requests, form_actions, json_urls, websocket_urls, hidden_fields = extract_content(html, current_url)

        
        all_api_urls.update(api_urls)
        all_js_files.update(js_files)
        all_xhr_urls.update(xhr_requests)
        all_form_actions.update(form_actions)
        all_json_urls.update(json_urls)
        all_websockets.update(websocket_urls)
        all_hidden_fields.update(hidden_fields)

        visited_urls.add(current_url)

        for js_file_url in js_files:
            js_content = fetch_js_file_content(js_file_url, timeout)
            if js_content:
                api_urls_in_js = analyze_js_file_content(js_content, current_url)
                all_api_urls.update(api_urls_in_js)

        if args.output and progress_bar:
            progress_bar.update(1)

    if args.output and progress_bar:
        progress_bar.close()

def main():
    global args
    accessi_logo()
    args = get_args()

    signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(0))

    console.print(f"Starting recon for {args.url} up to depth {args.depth}")
    
    crawl(args.url, args.depth, args.timeout, args)

    if args.output:
        save_results_to_html(args.output)
    else:
        display_results_in_terminal()

if __name__ == "__main__":
    main()
