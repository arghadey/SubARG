import subprocess
import os
import json
import time
import re  # Added for regex pattern matching
from typing import List, Dict, Callable, Optional
import tempfile
import requests

class SubARG:
    def __init__(self):
        self.target = None
        self.target_list = None
        self.output_format = 'txt'
        self.output_file = None
        self.results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'results')
        
        # Ensure results directory exists
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Tool paths (will be auto-detected)
        self.tool_paths = {}
        self.detect_tools()
    
    def detect_tools(self):
        """Detect available tools and their paths"""
        tools_to_check = [
            'subfinder', 'assetfinder', 'sublist3r', 'amass', 
            'dnsx', 'httpx', 'httprobe', 'ffuf', 'anew', 'dnsenum'
        ]
        
        # Check multiple possible paths
        possible_paths = [
            '',  # Default PATH
            '/usr/bin/',
            '/usr/local/bin/',
            '/go/bin/',
            '/root/go/bin/',
            '/host/usr/bin/',
            '/host/usr/local/bin/',
            '/host/go/bin/'
        ]
        
        for tool in tools_to_check:
            tool_found = False
            
            if tool == 'sublist3r':
                # Check for sublist3r Python module
                try:
                    import sublist3r
                    self.tool_paths[tool] = 'python'
                    tool_found = True
                except ImportError:
                    pass
            
            # Check all possible paths
            for path_prefix in possible_paths:
                tool_path = os.path.join(path_prefix, tool) if path_prefix else tool
                
                try:
                    if tool == 'sublist3r' and tool_found:
                        continue
                    
                    # Try which command
                    which_cmd = ['which', tool_path] if path_prefix else ['which', tool]
                    result = subprocess.run(which_cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        self.tool_paths[tool] = result.stdout.strip()
                        tool_found = True
                        break
                    
                    # Try direct execution
                    test_cmd = [tool_path] if path_prefix else [tool]
                    help_flag = ['-h'] if tool == 'ffuf' else ['--help', '--version', '-v']
                    
                    for flag in help_flag:
                        try:
                            test_result = subprocess.run([*test_cmd, flag], 
                                                        capture_output=True, 
                                                        timeout=2)
                            if test_result.returncode in [0, 1]:
                                self.tool_paths[tool] = tool_path if path_prefix else tool
                                tool_found = True
                                break
                        except:
                            continue
                    
                    if tool_found:
                        break
                        
                except Exception:
                    continue
            
            if not tool_found:
                self.tool_paths[tool] = None
        
        print(f"Detected tools: {self.tool_paths}")
    
    def filter_dns_records(self, results: List[str], target: str) -> List[str]:
        """Filter out DNS records and keep only subdomains"""
        filtered = []
        
        # DNS record patterns to exclude
        dns_patterns = [
            r'^ns-\d+\.',  # NS records like ns-1447.awsdns-52.org
            r'^mx\d*\.',   # MX records
            r'^mail\.',    # Mail servers
            r'^smtp\.',    # SMTP servers
            r'^pop\.',     # POP servers
            r'^imap\.',    # IMAP servers
            r'^relay\.',   # Relay servers
            r'^autodiscover\.',  # Exchange autodiscover
            r'\.awsdns-',  # AWS DNS servers
            r'\.cloudflare\.',  # Cloudflare nameservers
            r'\.googleusercontent\.',  # Google domains
            r'\.googlehosted\.',  # Google domains
            r'\.akamai\.',  # Akamai
            r'\.akamaiedge\.',  # Akamai
            r'\.edgekey\.',  # Akamai
            r'\.fastly\.',  # Fastly
            r'\.cloudfront\.',  # CloudFront
        ]
        
        for result in results:
            # Skip if result doesn't contain target domain
            if target not in result:
                continue
                
            # Skip if it's exactly the target domain
            if result == target:
                continue
                
            # Skip common DNS record patterns
            skip = False
            for pattern in dns_patterns:
                if re.search(pattern, result, re.IGNORECASE):
                    skip = True
                    break
            
            if skip:
                continue
            
            # Skip if looks like a nameserver record
            if re.match(r'^ns\d*\.', result.split('.')[0], re.IGNORECASE):
                continue
                
            # Skip if ends with common DNS provider domains
            dns_providers = [
                '.awsdns.org', '.awsdns.co.uk', '.awsdns.com', '.awsdns.net',
                '.cloudflare.com', '.akamai.net', '.akamaiedge.net',
                '.google.com', '.googlehosted.com'
            ]
            
            if any(result.endswith(provider) for provider in dns_providers):
                continue
            
            # Keep if it's a proper subdomain (ends with target domain)
            if result.endswith('.' + target):
                filtered.append(result)
        
        return filtered
    
    def set_target(self, target: str):
        self.target = target
    
    def set_target_list(self, target_list: str):
        self.target_list = target_list
    
    def set_output_format(self, format: str):
        self.output_format = format
    
    def set_output_file(self, filename: str):
        self.output_file = filename
    
    def check_installed_tools(self) -> Dict[str, bool]:
        """Check which tools are installed"""
        return {tool: path is not None for tool, path in self.tool_paths.items()}
    
    def run_httprobe(self, subdomains_list):
        """Run httprobe to find live subdomains"""
        results = []
        
        if not subdomains_list:
            return results
        
        try:
            # Write subdomains to temp file
            temp_input = tempfile.mktemp()
            with open(temp_input, 'w') as f:
                f.write('\n'.join(subdomains_list))
            
            # Run httprobe
            cmd = f"cat {temp_input} | httprobe -c 20 -t 3000"
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.stdout:
                results = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            
            # Cleanup
            os.remove(temp_input)
            
        except Exception as e:
            print(f"Error running httprobe: {e}")
        
        return results
    
    def run_tool(self, tool_name: str, target: str, progress_callback: Optional[Callable] = None, 
                result_callback: Optional[Callable] = None) -> List[str]:
        """Run a specific tool and return results"""
        results = []
        
        if progress_callback:
            progress_callback(f"Starting {tool_name}", 0)
        
        if tool_name == 'crt.sh':
            # Special handling for crt.sh - always available
            try:
                response = requests.get(f"https://crt.sh/?q=%25.{target}&output=json", timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        if 'name_value' in entry:
                            subdomains = entry['name_value'].split('\n')
                            for sub in subdomains:
                                sub = sub.replace('*.', '').strip()
                                if sub and target in sub:
                                    results.append(sub)
            except Exception as e:
                print(f"Error with crt.sh: {e}")
        
        elif tool_name in self.tool_paths and self.tool_paths[tool_name]:
            try:
                if tool_name == 'sublist3r':
                    # Run sublist3r via Python
                    import sublist3r
                    temp_file = tempfile.mktemp()
                    sublist3r.main(target, output_file=temp_file)
                    
                    if os.path.exists(temp_file):
                        with open(temp_file, 'r') as f:
                            results = [line.strip() for line in f if line.strip()]
                        os.remove(temp_file)
                
                elif tool_name == 'subfinder':
                    cmd = ['subfinder', '-d', target, '-silent']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    if result.stdout:
                        results = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                
                elif tool_name == 'assetfinder':
                    cmd = ['assetfinder', '--subs-only', target]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    if result.stdout:
                        results = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                
                elif tool_name == 'amass':
                    cmd = ['amass', 'enum', '-passive', '-d', target]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    if result.stdout:
                        results = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                
                elif tool_name == 'ffuf':
                    # Try different wordlist locations
                    wordlist_locations = [
                        '/usr/share/wordlists/subdomains.txt',
                        '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt',
                        '/root/tools/wordlists/subdomains.txt',
                        '/app/wordlists/subdomains.txt'
                    ]
                    
                    wordlist = None
                    for wl in wordlist_locations:
                        if os.path.exists(wl):
                            wordlist = wl
                            break
                    
                    if wordlist:
                        temp_file = tempfile.mktemp() + '.json'
                        cmd = ['ffuf', '-w', wordlist, '-u', f'http://FUZZ.{target}', 
                              '-H', 'User-Agent: Mozilla/5.0', '-mc', '200,301,302,403',
                              '-t', '10', '-o', temp_file, '-of', 'json', '-silent']
                        
                        subprocess.run(cmd, capture_output=True, timeout=300)
                        
                        if os.path.exists(temp_file):
                            with open(temp_file, 'r') as f:
                                try:
                                    data = json.load(f)
                                    for result_item in data.get('results', []):
                                        url = result_item.get('url', '')
                                        if url:
                                            domain = url.split('/')[2]
                                            results.append(domain)
                                except:
                                    pass
                            os.remove(temp_file)
                
                # Filter DNS records from results
                filtered_results = self.filter_dns_records(results, target)
                
                # Process filtered results
                for result in filtered_results:
                    if result_callback:
                        result_callback(result, tool_name)
                
                results = filtered_results  # Return filtered results
                
            except subprocess.TimeoutExpired:
                print(f"{tool_name} timed out")
            except Exception as e:
                print(f"Error running {tool_name}: {e}")
        else:
            print(f"Tool {tool_name} not available")
        
        if progress_callback:
            progress_callback(f"Completed {tool_name}", 100)
        
        return results
    
    def run(self, progress_callback: Optional[Callable] = None, 
           result_callback: Optional[Callable] = None) -> Dict:
        """Run complete subdomain enumeration"""
        all_subdomains = set()
        target = self.target
        
        if progress_callback:
            progress_callback("Initializing", 0)
        
        # Run available tools
        tools_to_run = []
        available_tools = self.check_installed_tools()
        
        # Only run tools that are available
        for tool, is_available in available_tools.items():
            if is_available and tool not in ['dnsx', 'httpx', 'httprobe', 'anew']:  # Skip resolvers and HTTP checkers for now
                tools_to_run.append(tool)
        
        # Always try crt.sh
        tools_to_run.append('crt.sh')
        
        print(f"Running tools: {tools_to_run}")
        
        for i, tool in enumerate(tools_to_run):
            if progress_callback:
                progress_callback(f"Running {tool}", int((i / len(tools_to_run)) * 70))
            
            try:
                results = self.run_tool(tool, target, progress_callback, result_callback)
                all_subdomains.update(results)
                
                if progress_callback:
                    progress_callback(f"Completed {tool}", int(((i + 1) / len(tools_to_run)) * 70))
                    
            except Exception as e:
                print(f"Error with {tool}: {e}")
        
        # Filter DNS records from all collected subdomains
        if progress_callback:
            progress_callback("Filtering DNS records", 75)
        
        filtered_subdomains = self.filter_dns_records(list(all_subdomains), target)
        all_subdomains = set(filtered_subdomains)
        
        # Run DNS resolution if dnsx is available
        resolved = []
        if 'dnsx' in self.tool_paths and self.tool_paths['dnsx'] and all_subdomains:
            if progress_callback:
                progress_callback("Resolving DNS", 80)
            
            temp_file = tempfile.mktemp()
            with open(temp_file, 'w') as f:
                f.write('\n'.join(all_subdomains))
            
            try:
                cmd = ['dnsx', '-l', temp_file, '-silent', '-a', '-resp']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    resolved = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            except:
                pass
            
            os.remove(temp_file)
        
        # Run HTTP check with httpx and httprobe fallback
        if progress_callback:
            progress_callback("Checking HTTP services", 85)
        
        live_subdomains = []
        httprobe_used = False
        
        # First try httpx if available
        if 'httpx' in self.tool_paths and self.tool_paths['httpx'] and resolved:
            temp_file = tempfile.mktemp()
            with open(temp_file, 'w') as f:
                f.write('\n'.join(resolved))
            
            try:
                cmd = ['httpx', '-l', temp_file, '-silent', '-title', 
                       '-status-code', '-tech-detect']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    live_subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            except:
                pass
            
            os.remove(temp_file)
        
        # If httpx failed or returned no results, try httprobe
        if (not live_subdomains or len(live_subdomains) == 0) and 'httprobe' in self.tool_paths and self.tool_paths['httprobe']:
            if progress_callback:
                progress_callback("Trying HTTPROBE as fallback", 88)
            
            httprobe_used = True
            
            # Use resolved subdomains if available, otherwise use all subdomains
            targets_to_probe = resolved if resolved else list(all_subdomains)
            
            if targets_to_probe:
                httprobe_results = self.run_httprobe(targets_to_probe)
                live_subdomains = httprobe_results
        
        # Save results
        if progress_callback:
            progress_callback("Saving results", 95)
        
        output_filename = self.output_file or f"subdomains_{target}_{int(time.time())}"
        
        if self.output_format == 'json':
            output_filename += '.json'
            output_path = os.path.join(self.results_dir, output_filename)
            with open(output_path, 'w') as f:
                json.dump({
                    'domain': target,
                    'timestamp': time.time(),
                    'total_subdomains': len(all_subdomains),
                    'resolved_subdomains': len(resolved),
                    'live_subdomains': len(live_subdomains),
                    'tools_used': {
                        'httpx_available': 'httpx' in self.tool_paths and self.tool_paths['httpx'] is not None,
                        'httprobe_available': 'httprobe' in self.tool_paths and self.tool_paths['httprobe'] is not None,
                        'httprobe_used_as_fallback': httprobe_used
                    },
                    'subdomains': list(all_subdomains),
                    'resolved': resolved,
                    'live': live_subdomains
                }, f, indent=2)
        
        elif self.output_format == 'csv':
            output_filename += '.csv'
            output_path = os.path.join(self.results_dir, output_filename)
            with open(output_path, 'w') as f:
                f.write("Subdomain,Status,Resolved,Live\n")
                for sub in all_subdomains:
                    resolved_status = "Yes" if sub in resolved else "No"
                    live_status = "Yes" if sub in live_subdomains else "No"
                    f.write(f"{sub},Active,{resolved_status},{live_status}\n")
        
        elif self.output_format == 'html':
            output_filename += '.html'
            output_path = os.path.join(self.results_dir, output_filename)
            
            with open(output_path, 'w') as f:
                f.write(f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>SubARG Results - {target}</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; }}
                        h1 {{ color: #333; }}
                        table {{ border-collapse: collapse; width: 100%; }}
                        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                        th {{ background-color: #f2f2f2; }}
                        tr:nth-child(even) {{ background-color: #f9f9f9; }}
                        .tool-info {{ background-color: #e8f4fd; padding: 10px; border-radius: 5px; margin: 10px 0; }}
                    </style>
                </head>
                <body>
                    <h1>Subdomain Enumeration Results</h1>
                    <p><strong>Target:</strong> {target}</p>
                    <p><strong>Total Subdomains Found:</strong> {len(all_subdomains)}</p>
                    <p><strong>Resolved:</strong> {len(resolved)}</p>
                    <p><strong>Live Services:</strong> {len(live_subdomains)}</p>
                """)
                
                if httprobe_used:
                    f.write(f"""
                    <div class="tool-info">
                        <strong>Note:</strong> HTTPROBE was used as a fallback tool for live subdomain detection.
                    </div>
                    """)
                
                f.write("""
                    <h2>Subdomains</h2>
                    <table>
                        <tr><th>Subdomain</th><th>Status</th><th>Resolved</th><th>Live</th></tr>
                """)
                
                for sub in sorted(all_subdomains):
                    resolved_status = "Yes" if sub in resolved else "No"
                    live_status = "Yes" if sub in live_subdomains else "No"
                    f.write(f'<tr><td>{sub}</td><td>Active</td><td>{resolved_status}</td><td>{live_status}</td></tr>\n')
                
                f.write("""
                    </table>
                </body>
                </html>
                """)
        
        else:  # txt format (default)
            output_filename += '.txt'
            output_path = os.path.join(self.results_dir, output_filename)
            with open(output_path, 'w') as f:
                f.write(f"# SubARG Results - {target}\n")
                f.write(f"# Generated: {time.ctime()}\n")
                f.write(f"# Total Subdomains: {len(all_subdomains)}\n")
                f.write(f"# Resolved: {len(resolved)}\n")
                f.write(f"# Live Services: {len(live_subdomains)}\n")
                if httprobe_used:
                    f.write(f"# Note: HTTPROBE used as fallback for live detection\n")
                f.write("\n")
                f.write("=" * 50 + "\n")
                f.write("SUB DOMAINS:\n")
                f.write("=" * 50 + "\n")
                for sub in sorted(all_subdomains):
                    f.write(f"{sub}\n")
        
        if progress_callback:
            progress_callback("Complete", 100)
        
        return {
            'output_file': output_filename,
            'subdomains': list(all_subdomains),
            'resolved': resolved,
            'live': live_subdomains,
            'httprobe_used': httprobe_used,
            'total': len(all_subdomains)
        }
