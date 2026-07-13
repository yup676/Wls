#!/usr/bin/env python3
"""
Automated Pentest Scanner - Auto-Install & Execute
Uso: python3 scanner.py alvo.com
"""

import socket
import sys
import re
import requests
import dns.resolver
import whois
import ssl
import json
import subprocess
import os
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import time
import shutil

class AutoPentestScanner:
    def __init__(self, target):
        self.target = target
        self.ip = None
        self.os_type = self.detect_os()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        self.results = {
            'target': target,
            'ip': None,
            'os': self.os_type,
            'ports': [],
            'services': {},
            'vulnerabilities': [],
            'exploits_executed': [],
            'tools_installed': [],
            'findings': []
        }
        self.tools = {
            'nmap': {'check': 'nmap --version', 'install': self.install_nmap, 'cmd': 'nmap -sV -p '},
            'sqlmap': {'check': 'sqlmap --version', 'install': self.install_sqlmap, 'cmd': 'sqlmap -u '},
            'nikto': {'check': 'nikto -Version', 'install': self.install_nikto, 'cmd': 'nikto -h '},
            'hydra': {'check': 'hydra -h', 'install': self.install_hydra, 'cmd': 'hydra -L users.txt -P pass.txt '},
            'wpscan': {'check': 'wpscan --version', 'install': self.install_wpscan, 'cmd': 'wpscan --url '},
            'sslscan': {'check': 'sslscan --version', 'install': self.install_sslscan, 'cmd': 'sslscan '},
            'dirb': {'check': 'dirb -h', 'install': self.install_dirb, 'cmd': 'dirb http://'},
            'whatweb': {'check': 'whatweb -v', 'install': self.install_whatweb, 'cmd': 'whatweb '},
            'gobuster': {'check': 'gobuster -h', 'install': self.install_gobuster, 'cmd': 'gobuster dir -u '}
        }

    def detect_os(self):
        """Detecta o sistema operacional"""
        try:
            if 'termux' in platform.platform().lower():
                return 'termux'
            elif 'kali' in platform.platform().lower() or 'Kali' in subprocess.getoutput('uname -a'):
                return 'kali'
            elif 'ubuntu' in platform.platform().lower() or 'debian' in platform.platform().lower():
                return 'debian'
            elif 'wsl' in platform.platform().lower():
                return 'wsl'
            else:
                return 'linux'
        except:
            return 'linux'

    def run_command(self, cmd, timeout=60):
        """Executa comando e retorna output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return "[TIMEOUT]"
        except Exception as e:
            return f"[ERROR] {e}"

    def install_package(self, package):
        """Instala pacote automaticamente"""
        if self.os_type == 'termux':
            cmd = f'pkg install {package} -y'
        elif self.os_type in ['kali', 'wsl', 'debian']:
            cmd = f'sudo apt install {package} -y'
        else:
            cmd = f'sudo apt install {package} -y'
        
        print(f"[INSTALL] Installing {package}...")
        output = self.run_command(cmd)
        if 'already' in output.lower() or 'installed' in output.lower():
            print(f"[OK] {package} already installed")
        else:
            print(f"[OK] {package} installed")
        return output

    def install_tool(self, tool_name):
        """Instala ferramenta específica"""
        if tool_name in self.tools:
            return self.tools[tool_name]['install']()
        return False

    def install_nmap(self):
        return self.install_package('nmap')
    
    def install_sqlmap(self):
        if self.os_type == 'termux':
            return self.run_command('pip install sqlmap')
        else:
            return self.install_package('sqlmap')
    
    def install_nikto(self):
        if self.os_type == 'termux':
            return self.run_command('pip install nikto')
        else:
            return self.install_package('nikto')
    
    def install_hydra(self):
        return self.install_package('hydra')
    
    def install_wpscan(self):
        if self.os_type == 'termux':
            return self.run_command('gem install wpscan')
        else:
            return self.install_package('wpscan')
    
    def install_sslscan(self):
        return self.install_package('sslscan')
    
    def install_dirb(self):
        return self.install_package('dirb')
    
    def install_whatweb(self):
        return self.install_package('whatweb')
    
    def install_gobuster(self):
        if self.os_type == 'termux':
            return self.run_command('pkg install gobuster -y')
        else:
            return self.install_package('gobuster')

    def check_tool(self, tool_name):
        """Verifica se ferramenta está instalada"""
        if tool_name not in self.tools:
            return False
        check_cmd = self.tools[tool_name]['check']
        try:
            result = subprocess.run(check_cmd, shell=True, capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def ensure_tool(self, tool_name):
        """Garante que a ferramenta está instalada"""
        if not self.check_tool(tool_name):
            print(f"[TOOL] Installing {tool_name}...")
            self.install_tool(tool_name)
            if tool_name not in self.results['tools_installed']:
                self.results['tools_installed'].append(tool_name)
            return self.check_tool(tool_name)
        return True

    def execute_tool(self, tool_name, target):
        """Executa ferramenta automaticamente"""
        if tool_name not in self.tools:
            return None
        
        if not self.ensure_tool(tool_name):
            return f"[ERROR] {tool_name} not available"
        
        cmd_template = self.tools[tool_name]['cmd']
        cmd = cmd_template + target
        print(f"\n[EXEC] {tool_name}: {cmd}")
        output = self.run_command(cmd, timeout=120)
        
        # Analisa output para vulnerabilidades
        self.analyze_output(tool_name, output)
        
        return output

    def analyze_output(self, tool_name, output):
        """Analisa output de ferramentas para encontrar vulnerabilidades"""
        vuln_patterns = {
            'sqlmap': {
                'patterns': ['vulnerable', 'injection', 'database', 'found', 'table'],
                'severity': 'High',
                'description': 'SQL Injection vulnerability detected'
            },
            'nikto': {
                'patterns': ['vulnerability', 'VULNERABLE', 'Outdated', 'XSS', 'SQL'],
                'severity': 'Medium',
                'description': 'Web vulnerability found'
            },
            'nmap': {
                'patterns': ['open', 'filtered', 'VULNERABLE', 'CVE'],
                'severity': 'Medium',
                'description': 'Service vulnerability detected'
            },
            'wpscan': {
                'patterns': ['vulnerability', 'VULNERABLE', 'CVE', 'exploit'],
                'severity': 'High',
                'description': 'WordPress vulnerability found'
            },
            'sslscan': {
                'patterns': ['vulnerable', 'weak', 'outdated', 'CVE'],
                'severity': 'Medium',
                'description': 'SSL/TLS vulnerability detected'
            },
            'gobuster': {
                'patterns': ['Status: 200', 'Status: 403', 'admin', 'login'],
                'severity': 'Low',
                'description': 'Sensitive directory found'
            }
        }
        
        if tool_name in vuln_patterns:
            for pattern in vuln_patterns[tool_name]['patterns']:
                if pattern.lower() in output.lower():
                    self.results['vulnerabilities'].append({
                        'tool': tool_name,
                        'description': vuln_patterns[tool_name]['description'],
                        'severity': vuln_patterns[tool_name]['severity'],
                        'details': output[:500]
                    })
                    print(f"[VULN] {vuln_patterns[tool_name]['severity']}: {vuln_patterns[tool_name]['description']}")
                    break

    def resolve_dns(self):
        """Resolução DNS"""
        try:
            self.ip = socket.gethostbyname(self.target)
            self.results['ip'] = self.ip
            print(f"[+] Target: {self.target} -> {self.ip}")
            
            try:
                w = whois.whois(self.target)
                if w.registrar:
                    print(f"[+] Registrar: {w.registrar}")
            except: pass
            
            return True
        except Exception as e:
            print(f"[-] DNS Error: {e}")
            return False

    def scan_ports(self):
        """Scan de portas"""
        print("\n[+] Scanning ports...")
        common_ports = [21,22,23,25,53,80,110,443,445,465,587,993,995,
                       1433,3306,3389,5432,5900,6379,8080,8443,9000]
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.ip, port))
                sock.close()
                if result == 0:
                    service = self.identify_service(port)
                    open_ports.append({'port': port, 'service': service})
            except: pass
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            executor.map(check_port, common_ports)
        
        self.results['ports'] = open_ports
        for p in open_ports:
            print(f"[+] Port {p['port']}: {p['service']}")
            self.results['services'][p['port']] = p['service']
        
        # Executa nmap se encontrar portas
        if open_ports and self.ensure_tool('nmap'):
            nmap_result = self.execute_tool('nmap', f"{self.ip} -p {','.join([str(p['port']) for p in open_ports[:10]])} -sV")
            self.results['findings'].append(nmap_result)

    def identify_service(self, port):
        services = {
            21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',
            110:'POP3',443:'HTTPS',445:'SMB',465:'SMTPS',587:'SMTP',
            993:'IMAPS',995:'POP3S',1433:'MSSQL',3306:'MySQL',
            3389:'RDP',5432:'PostgreSQL',5900:'VNC',6379:'Redis',
            8080:'HTTP',8443:'HTTPS'
        }
        return services.get(port, 'Unknown')

    def check_http_vulns(self):
        """Verifica vulnerabilidades HTTP automaticamente"""
        if any(p['port'] in [80, 8080, 8000] for p in self.results['ports']):
            print("\n[+] Checking HTTP vulnerabilities...")
            
            # Nikto
            if self.ensure_tool('nikto'):
                self.execute_tool('nikto', self.target)
            
            # Dirb/Gobuster
            if self.ensure_tool('gobuster'):
                self.execute_tool('gobuster', f"http://{self.target} -w /usr/share/wordlists/dirb/common.txt")
            
            # WhatWeb
            if self.ensure_tool('whatweb'):
                self.execute_tool('whatweb', self.target)
            
            # SQLMap (se encontrar parâmetros)
            try:
                resp = self.session.get(f"http://{self.target}", timeout=5)
                if '?' in resp.url or 'id=' in resp.text:
                    if self.ensure_tool('sqlmap'):
                        self.execute_tool('sqlmap', f"http://{self.target}/?id=1 --batch --dbs")
            except: pass

    def check_https_vulns(self):
        """Verifica vulnerabilidades HTTPS"""
        if any(p['port'] in [443, 8443] for p in self.results['ports']):
            print("\n[+] Checking HTTPS vulnerabilities...")
            
            # SSLScan
            if self.ensure_tool('sslscan'):
                self.execute_tool('sslscan', self.target)

    def check_service_vulns(self):
        """Verifica vulnerabilidades de serviços específicos"""
        for p in self.results['ports']:
            service = p['service']
            
            if service == 'SSH' and self.ensure_tool('hydra'):
                print(f"\n[+] Testing SSH on port {p['port']}")
                self.execute_tool('hydra', f"ssh://{self.ip} -l root -P /usr/share/wordlists/rockyou.txt")
            
            elif service == 'FTP' and self.ensure_tool('hydra'):
                print(f"\n[+] Testing FTP on port {p['port']}")
                self.execute_tool('hydra', f"ftp://{self.ip} -l admin -P /usr/share/wordlists/rockyou.txt")
            
            elif service == 'MySQL':
                print(f"\n[+] Testing MySQL on port {p['port']}")
                self.add_vuln('MySQL', 'Check default credentials', 'High')
                if self.ensure_tool('sqlmap'):
                    self.execute_tool('sqlmap', f"http://{self.ip}/ --dbms=mysql --dbs")
            
            elif service == 'Redis':
                self.add_vuln('Redis', 'No authentication possible', 'High')
                try:
                    import redis
                    r = redis.Redis(host=self.ip, port=6379, decode_responses=True)
                    info = r.info()
                    if info:
                        print(f"[+] Redis info: {list(info.keys())[:10]}")
                        self.results['findings'].append(f"Redis accessible: {info.get('redis_version')}")
                except: pass
            
            elif service == 'SMTP' and self.ensure_tool('nmap'):
                self.execute_tool('nmap', f"{self.ip} -p 25 --script smtp-*")

    def add_vuln(self, service, description, severity):
        vuln = {
            'service': service,
            'description': description,
            'severity': severity
        }
        if vuln not in self.results['vulnerabilities']:
            self.results['vulnerabilities'].append(vuln)
            print(f"  [!] {severity}: {description}")

    def generate_report(self):
        """Gera relatório completo"""
        print("\n" + "="*70)
        print(f"AUTO PENTEST REPORT - {self.target}")
        print("="*70)
        print(f"IP: {self.results['ip']}")
        print(f"OS: {self.results['os']}")
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"\n[+] Open Ports: {len(self.results['ports'])}")
        for p in self.results['ports']:
            print(f"    {p['port']}: {p['service']}")
        
        print(f"\n[+] Vulnerabilities Found: {len(self.results['vulnerabilities'])}")
        for v in self.results['vulnerabilities']:
            print(f"    [{v['severity']}] {v['service']}: {v['description']}")
        
        print(f"\n[+] Tools Installed: {len(self.results['tools_installed'])}")
        for t in self.results['tools_installed']:
            print(f"    {t}")
        
        print(f"\n[+] Exploits Executed: {len(self.results['exploits_executed'])}")
        for e in self.results['exploits_executed']:
            print(f"    {e}")
        
        print("\n" + "="*70)
        
        # Salvar relatório
        filename = f"autoscan_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n[+] Report saved: {filename}")

    def auto_install_all(self):
        """Instala todas as ferramentas automaticamente"""
        print("\n[+] Installing all tools...")
        for tool in self.tools:
            if not self.check_tool(tool):
                self.install_tool(tool)
                time.sleep(1)

    def run(self):
        """Executa scan completamente automático"""
        print(f"\n{'='*50}")
        print(f"AUTO PENTEST SCANNER")
        print(f"Target: {self.target}")
        print(f"OS: {self.os_type}")
        print(f"{'='*50}\n")
        
        # Instala dependências básicas
        if self.os_type == 'termux':
            self.run_command('pkg update -y')
        else:
            self.run_command('sudo apt update -y')
        
        # Resolve DNS
        if not self.resolve_dns():
            return
        
        # Scan de portas
        self.scan_ports()
        
        # Verifica HTTP/HTTPS
        self.check_http_vulns()
        self.check_https_vulns()
        
        # Verifica serviços
        self.check_service_vulns()
        
        # Gera relatório
        self.generate_report()

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 scanner.py <target>")
        print("Exemplo: python3 scanner.py exemplo.com")
        sys.exit(1)
    
    scanner = AutoPentestScanner(sys.argv[1])
    scanner.run()

if __name__ == "__main__":
    main()
