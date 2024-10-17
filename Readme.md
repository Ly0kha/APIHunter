## APIHunter
APIHunter is a script that crawls websites to potentially find hidden API URLs. It looks through JavaScript files, form actions, WebSocket connections, and other parts of the site to spot API endpoints. APIHunter checks different areas like fetch requests, hidden fields, and JSON/XML files to give a better picture of how a website might use its APIs 
## usage :
``` bash 
python3 apihunter.py <url> --depth <depth> --output <output_file>
or 
python3 apihunter.py <url> 
```
## requirements :
``` bash 
pip install argparse aiohttp beautifulsoup4 rich tqdm urllib3 signal logging json robots.txt builtwith ssl socket datetime playwright
```

