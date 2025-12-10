from colorama import Fore, Style, init
init(autoreset=True)
import argparse
import requests
from urllib.parse import urlparse
import concurrent.futures
import json
import logging
import os
from datetime import datetime
import time
import random
import sys


RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"


DEFAULT_ORIGINS_STATIC = [
    "https://evil.com",
    "https://random-origin-test.xyz",
    "https://attacker.site",
    "https://example.attacker"  
]

DEFAULT_TEST_PREFIXES = ["sub", "test", "dev", "stage", "api", "m", "beta"]
DEFAULT_TEST_SUFFIXES = ["-test", "-dev", ".evil.com", "-evil", ".staging"]


logger = logging.getLogger("CORS_Hunter")
logger.setLevel(logging.DEBUG)


ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch_formatter = logging.Formatter('%(message)s')
ch.setFormatter(ch_formatter)
logger.addHandler(ch)





def extract_domain(url: str) -> str:
    
    parsed = urlparse(url)
    netloc = parsed.netloc
    
    if '@' in netloc:
        netloc = netloc.split('@')[-1]
    
    if ':' in netloc:
        hostname = netloc.split(':')[0]
    else:
        hostname = netloc
    return hostname


def domain_variations(domain: str) -> list:
    
    variations = set()
    
    for p in DEFAULT_TEST_PREFIXES:
        variations.add(f"{p}.{domain}")
    
    variations.add(f"{domain}")
    
    for s in DEFAULT_TEST_SUFFIXES:
        
        variations.add(f"{domain}{s}")
        variations.add(f"{domain.replace('.', '-')}{s}")
    
    parts = domain.split('.')
    if len(parts) >= 2:
        left = parts[0]
        rest = '.'.join(parts[1:])
        variations.add(f"{left}-dev.{rest}")
        variations.add(f"{left}_dev.{rest}")
     
    if parts:
        left = parts[0]
        rest = '.'.join(parts[1:]) if len(parts) > 1 else ''
        variations.add(f"{left}0.{rest}".strip('.'))
        variations.add(f"{left}1.{rest}".strip('.'))
    
    rand_label = ''.join(random.choices('abcd0123', k=4))
    variations.add(f"{rand_label}.{domain}")


    variations.add(f"www.{domain}")
    variations.add(f"api.{domain}")

    return list(variations)


def build_origin_list(target_url: str, extra_static=None, custom_file: str = None) -> list:
    
    domain = extract_domain(target_url)
    origins = []

    
    dyn = domain_variations(domain)
    for d in dyn:
        origins.append(f"https://{d}")

    
    origins.extend([
        f"https://{domain}.evil.com",
        f"https://evil-{domain}",
        f"https://{domain}-test.com",
    ])

    
    if custom_file and os.path.isfile(custom_file):
        try:
            with open(custom_file, 'r', encoding='utf-8') as f:
                for line in f:
                    s = line.strip()
                    if s:
                        origins.append(s)
        except Exception as e:
            logger.warning(f"Could not read origins file: {e}")

    
    origins.extend(DEFAULT_ORIGINS_STATIC)

    
    seen = set()
    ordered = []
    for o in origins:
        if o not in seen:
            seen.add(o)
            ordered.append(o)
    
    ordered.append("null")
    return ordered



def analyze_headers(origin: str, headers: dict) -> dict:
    
    acao = headers.get('Access-Control-Allow-Origin') or headers.get('access-control-allow-origin') or None
    acac = headers.get('Access-Control-Allow-Credentials') or headers.get('access-control-allow-credentials') or None
    acam = headers.get('Access-Control-Allow-Methods') or headers.get('access-control-allow-methods') or None
    acah = headers.get('Access-Control-Allow-Headers') or headers.get('access-control-allow-headers') or None

    findings = []
    severity = 'info'

    if acao:
        if acao.strip() == '*':
            findings.append('Wildcard ACAO (*) detected')
            severity = 'high'

        if acao.strip() == origin:
            findings.append('Reflected Origin (ACAO matches request Origin)')
            if severity != 'high':
                severity = 'high'

        if acac and acac.lower() == 'true':
            findings.append('Credentials allowed (Access-Control-Allow-Credentials: true)')
            
            if acao and acao.strip() == '*':
                findings.append('CREDENTIALS + WILDCARD -> CRITICAL')
                severity = 'critical'
            elif acao and acao.strip() == origin:
                findings.append('CREDENTIALS + REFLECTION -> CRITICAL')
                severity = 'critical'
            else:
                if severity != 'critical':
                    severity = 'high'

    else:
        findings.append('No ACAO header present')

    
    if acam is None and acah is None:
        findings.append('Missing ACA-Methods and/or ACA-Headers in preflight responses (if OPTIONS returns 200 without them)')
        if severity == 'info':
            severity = 'low'

    return {
        'acao': acao,
        'acac': acac,
        'acam': acam,
        'acah': acah,
        'findings': findings,
        'severity': severity
    }


def send_single_request(method: str, target: str, origin: str, timeout=7, retries=1) -> dict:
    
    headers = {'Origin': origin}

    if method.upper() == 'OPTIONS':
        headers.update({
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'X-Test-Header'
        })

    attempt = 0
    last_error = None

    while attempt <= retries:
        attempt += 1

        try:
            print(Fore.CYAN + "\n==============================================")
            print(Fore.MAGENTA + f"[Request] {method.upper()} -> {target}")
            print(Fore.CYAN + f"[Origin] {origin}")
            print(Fore.YELLOW + "[Request Headers]:")
            
            for k, v in headers.items():
                print(Fore.YELLOW + f"  {k}: {v}")

            print(Fore.CYAN + "==============================================")

            
            response = requests.request(
                method.upper(),
                target,
                headers=headers,
                timeout=timeout,
                allow_redirects=True
            )

            
            status_color = (
                Fore.GREEN if 200 <= response.status_code < 300 else
                Fore.YELLOW if 300 <= response.status_code < 400 else
                Fore.RED
            )

            print(f"\n{status_color}[Response Status] {response.status_code}")
            print(Fore.CYAN + "[Response Headers]:")

            
            for k, v in response.headers.items():
                key_lower = k.lower()

                if key_lower in [
                    "access-control-allow-origin",
                    "access-control-allow-credentials",
                    "access-control-allow-methods",
                    "access-control-allow-headers"
                ]:
                    print(Fore.RED + f"  {k}: {v}")
                else:
                    print(Fore.CYAN + f"  {k}: {v}")

            
            print(Fore.MAGENTA + "\n[Response Body Preview]:")
            body = response.text[:600]
            print(body if body else "<EMPTY>")

            
            result = {
                'method': method.upper(),
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'elapsed_ms': int(response.elapsed.total_seconds() * 1000)
            }

            
            analysis = analyze_headers(origin, response.headers)
            result.update({'analysis': analysis})

            print(Fore.MAGENTA + "\n[Analysis]:")
            for f in analysis["findings"]:
                sev_color = (
                    Fore.RED if "CRITICAL" in f.upper() else
                    Fore.YELLOW if "REFLECT" in f.upper() or "WILDCARD" in f.upper() else
                    Fore.CYAN
                )
                print(sev_color + f" - {f}")

            
            sev = analysis['severity'].lower()
            sev_color = {
                'critical': Fore.RED,
                'high': Fore.YELLOW,
                'low': Fore.BLUE,
                'info': Fore.WHITE
            }.get(sev, Fore.WHITE)

            print(sev_color + f"[Severity] {analysis['severity']}")
            print(Fore.CYAN + "==============================================\n")

            return result

        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"[Error] Attempt {attempt} failed: {e}")
            last_error = str(e)
            time.sleep(0.15)
            continue

    return {
        'method': method.upper(),
        'error': last_error
    }



def scan_origin(target: str, origin: str, timeout=7, retries=1) -> dict:
    """Scan both GET and OPTIONS for a single origin and return results."""
    get_res = send_single_request('GET', target, origin, timeout=timeout, retries=retries)
    options_res = send_single_request('OPTIONS', target, origin, timeout=timeout, retries=retries)
    combined = {
        'origin': origin,
        'get': get_res,
        'options': options_res
    }
    return combined



def summarize_and_print(report: list, verbose=False):
    
    print(CYAN + "\n===== CORS HUNTER SUMMARY =====\n" + RESET)
    critical_count = 0
    high_count = 0
    low_count = 0

    for entry in report:
        origin = entry.get('origin')
        analysis_get = entry.get('get', {}).get('analysis') if entry.get('get') else None
        analysis_options = entry.get('options', {}).get('analysis') if entry.get('options') else None

        
        severities = []
        for a in (analysis_get, analysis_options):
            if a:
                s = a.get('severity')
                if s:
                    severities.append(s)
        worst = 'info'
        order = ['info', 'low', 'high', 'critical']
        for s in order[::-1]:
            if s in severities:
                worst = s
                break

        if worst == 'critical':
            color = RED
            critical_count += 1
        elif worst == 'high':
            color = YELLOW
            high_count += 1
        elif worst == 'low':
            color = MAGENTA
            low_count += 1
        else:
            color = GREEN

        print(f"{color}{origin}{RESET} -> {worst.upper()}")
        if verbose:
            if analysis_get:
                print(f"  GET findings: {analysis_get.get('findings')}")
            if analysis_options:
                print(f"  OPTIONS findings: {analysis_options.get('findings')}")

    print(CYAN + f"\nCritical: {critical_count}, High: {high_count}, Low: {low_count}\n" + RESET)


def save_json_report(report: list, outpath: str):
    try:
        with open(outpath, 'w', encoding='utf-8') as f:
            json.dump({'generated_at': datetime.utcnow().isoformat() + 'Z', 'results': report}, f, indent=2)
        logger.info(f"JSON report saved to: {outpath}")
    except Exception as e:
        logger.warning(f"Could not save JSON report: {e}")


def main():
    parser = argparse.ArgumentParser(description='CORS Hunter - Professional CORS misconfiguration scanner')
    parser.add_argument('target', help='Target URL to test (e.g. https://example.com/api)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent workers')
    parser.add_argument('-T', '--timeout', type=int, default=7, help='Request timeout in seconds')
    parser.add_argument('-r', '--retries', type=int, default=0, help='Number of retries on failure')
    parser.add_argument('-o', '--output', default=None, help='Path to JSON output report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--origins-file', default=None, help='Optional file with additional origins to test (one per line)')
    parser.add_argument('--log-file', default=None, help='Optional path to log file')
    parser.add_argument('--max-origins', type=int, default=40, help='Maximum number of origins to test (after dynamic generation)')

    args = parser.parse_args()

    
    if args.log_file:
        fh = logging.FileHandler(args.log_file)
        fh.setLevel(logging.DEBUG)
        fh_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(fh_formatter)
        logger.addHandler(fh)

    target = args.target
    logger.info(f"Target: {target}")

    origins = build_origin_list(target, extra_static=None, custom_file=args.origins_file)
    if args.max_origins and isinstance(args.max_origins, int):
        origins = origins[:args.max_origins]

    logger.info(f"Testing {len(origins)} origins (concurrency={args.threads})")

    report = []
    failures = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_origin = {executor.submit(scan_origin, target, o, args.timeout, args.retries): o for o in origins}
        try:
            for future in concurrent.futures.as_completed(future_to_origin):
                origin = future_to_origin[future]
                try:
                    res = future.result()
                    report.append(res)
                    
                    if args.verbose:
                        logger.info(f"Scanned: {origin} -> {res.get('get', {}).get('analysis') if res.get('get') else 'ERR'}")
                except Exception as e:
                    failures += 1
                    logger.warning(f"Scan error for {origin}: {e}")
        except KeyboardInterrupt:
            logger.warning("Keyboard interrupt received. Shutting down...")
            executor.shutdown(wait=False)

    
    summarize_and_print(report, verbose=args.verbose)

    
    if args.output:
        save_json_report(report, args.output)

    
    has_critical = any(
        any(part and part.get('analysis', {}).get('severity') == 'critical' for part in (entry.get('get'), entry.get('options'))) for entry in report
    )
    sys.exit(2 if has_critical else 0)

if __name__ == '__main__':
    main()
