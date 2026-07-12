#!/usr/bin/env python3
"""
Fast Pentest Scanner - WSL
Uso: python3 scanner.py alvo.com
"""

import socket
import subprocess
import sys
import re
import requests
import dns.resolver
import whois
import ssl
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import base64
import hashlib

class FastScanner:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        self.results = {
            'target': target,
            'ip': None,
            'ports': [],
            'services': {},
            'vulnerabilities': [],
            'exploits': [],
            'tools': []
        }
        self.vuln_db = self.load_vuln_db()
        
    def load_vuln_db(self):
        """Base de dados de vulnerabilidades com exploração"""
        return {
            'FTP': {
                'vulns': ['Anonymous Login', 'FTP Bounce Attack', 'Plain Text Credentials'],
                'exploit': [
                    'ftp anonymous@{}',
                    'nmap --script ftp-bounce -p 21 {}',
                    'tcpdump -i any port 21'
                ],
                'tools': ['hydra -l admin -P wordlist.txt ftp://{}', 'nmap --script ftp-* -p 21 {}']
            },
            'SSH': {
                'vulns': ['Weak Ciphers', 'Password Brute Force', 'Version Disclosure'],
                'exploit': [
                    'ssh -oKexAlgorithms=diffie-hellman-group1-sha1 root@{}',
                    'hydra -L users.txt -P pass.txt ssh://{}',
                    'ssh-audit {}'
                ],
                'tools': ['hydra -L users.txt -P pass.txt ssh://{}', 'nmap --script ssh-* -p 22 {}']
            },
            'HTTP': {
                'vulns': ['XSS', 'SQL Injection', 'Directory Listing', 'Information Disclosure', 'CSRF'],
                'exploit': [
                    'sqlmap -u "http://{}/?id=1" --dbs',
                    'xsstrike -u "http://{}/" --crawl',
                    'dirb http://{}/',
                    'nikto -h http://{}',
                    'curl -I http://{}/'
                ],
                'tools': [
                    'sqlmap -u "http://{}/?id=1" --dbs --batch',
                    'nikto -h http://{}',
                    'dirb http://{}/',
                    'wpscan --url http://{}/'
                ]
            },
            'HTTPS': {
                'vulns': ['SSL/TLS Vulnerabilities', 'Self-Signed Certificate', 'Weak Ciphers'],
                'exploit': [
                    'sslscan {}:443',
                    'testssl.sh {}',
                    'openssl s_client -connect {}:443 -tls1'
                ],
                'tools': ['sslscan {}', 'testssl.sh {}']
            },
            'MySQL': {
                'vulns': ['Default Credentials', 'Remote Code Execution', 'SQL Injection'],
                'exploit': [
                    'mysql -h {} -u root -p',
                    'sqlmap -u "http://{}/" --dbms=mysql --dbs',
                    'hydra -L users.txt -P pass.txt mysql://{}'
                ],
                'tools': ['sqlmap -u "http://{}/" --dbms=mysql --dbs', 'hydra -l root -P wordlist.txt mysql://{}']
            },
            'PostgreSQL': {
                'vulns': ['Default Credentials', 'Remote Code Execution'],
                'exploit': [
                    'psql -h {} -U postgres',
                    'sqlmap -u "http://{}/" --dbms=postgresql --dbs'
                ],
                'tools': ['sqlmap -u "http://{}/" --dbms=postgresql --dbs']
            },
            'Redis': {
                'vulns': ['No Authentication', 'Remote Code Execution'],
                'exploit': [
                    'redis-cli -h {} info',
                    'redis-cli -h {} config get *'
                ],
                'tools': ['redis-cli -h {}']
            },
            'SMTP': {
                'vulns': ['Open Relay', 'User Enumeration', 'Email Spoofing'],
                'exploit': [
                    'nmap --script smtp-* -p 25 {}',
                    'smtp-user-enum -M VRFY -U users.txt -t {}'
                ],
                'tools': ['smtp-user-enum -M VRFY -U users.txt -t {}']
            }
        }

    def resolve_dns(self):
        """Resolução DNS rápida"""
        try:
            self.results['ip'] = socket.gethostbyname(self.target)
            print(f"[+] Target: {self.target} -> {self.results['ip']}")
            
            # DNS records
            for rtype in ['A', 'MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(self.target, rtype)
                    print(f"[+] {rtype}: {', '.join([str(r) for r in answers[:3]])}")
                except: pass
            
            # WHOIS
            try:
                w = whois.whois(self.target)
                print(f"[+] Registrar: {w.registrar}")
                print(f"[+] Created: {w.creation_date}")
            except: pass
        except Exception as e:
            print(f"[-] DNS Error: {e}")
            return False
        return True

    def scan_ports(self):
        """Scan de portas rápido"""
        print("\n[+] Scanning ports...")
        common_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,
                       1433,1521,3306,3389,5432,5900,6379,8080,8443,9000,9443,27017]
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.results['ip'], port))
                sock.close()
                if result == 0:
                    # Identificar serviço
                    service = self.identify_service(port)
                    open_ports.append({'port': port, 'service': service})
            except: pass
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(check_port, common_ports)
        
        self.results['ports'] = open_ports
        for p in open_ports:
            print(f"[+] Port {p['port']}: {p['service']}")
            self.results['services'][p['port']] = p['service']

    def identify_service(self, port):
        """Identifica serviço pela porta"""
        services = {
            21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',
            111:'RPC',135:'MSRPC',139:'NetBIOS',143:'IMAP',443:'HTTPS',445:'SMB',
            465:'SMTPS',587:'SMTP',993:'IMAPS',995:'POP3S',1433:'MSSQL',1521:'Oracle',
            3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',6379:'Redis',
            8080:'HTTP',8443:'HTTPS',27017:'MongoDB'
        }
        return services.get(port, 'Unknown')

    def check_http(self, port=80):
        """Verificação HTTP"""
        try:
            url = f"http://{self.target}:{port}"
            resp = self.session.get(url, timeout=5)
            print(f"\n[+] HTTP Headers:")
            for k,v in resp.headers.items():
                print(f"    {k}: {v}")
            
            # Security headers check
            missing = []
            for h in ['Strict-Transport-Security','Content-Security-Policy','X-Frame-Options',
                     'X-Content-Type-Options','X-XSS-Protection']:
                if h not in resp.headers:
                    missing.append(h)
            if missing:
                self.add_vuln('HTTP', f'Missing headers: {", ".join(missing)}', 'Medium',
                             f'Add headers: {", ".join(missing)}')
            
            # Check for XSS
            if '<script>' in resp.text or 'alert(' in resp.text:
                self.add_vuln('HTTP', 'Potential XSS detected', 'High',
                             'Test: <script>alert(1)</script>')
            
            # Check for SQL injection
            if 'sql' in resp.text.lower() or 'mysql' in resp.text.lower():
                self.add_vuln('HTTP', 'SQL error messages visible', 'High',
                             'sqlmap -u "http://{}/?id=1" --dbs')
            
            # Directory listing
            if 'Index of /' in resp.text:
                self.add_vuln('HTTP', 'Directory listing enabled', 'Medium',
                             'Access: http://{}/')
            
            # Technologies
            techs = []
            if 'php' in resp.text or 'PHP' in resp.headers.get('X-Powered-By', ''):
                techs.append('PHP')
            if 'wordpress' in resp.text.lower():
                techs.append('WordPress')
            if 'wp-content' in resp.text:
                techs.append('WordPress')
            if techs:
                print(f"[+] Technologies: {', '.join(techs)}")
                
        except Exception as e:
            print(f"[-] HTTP error: {e}")

    def check_https(self, port=443):
        """Verificação HTTPS/SSL"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    print(f"\n[+] SSL Certificate:")
                    print(f"    Subject: {cert.get('subject')}")
                    print(f"    Issuer: {cert.get('issuer')}")
                    print(f"    Expires: {cert.get('notAfter')}")
                    
                    # Check expiry
                    from datetime import datetime
                    expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days = (expiry - datetime.now()).days
                    if days < 30:
                        self.add_vuln('HTTPS', f'Certificate expires in {days} days', 'High',
                                     f'Renew certificate before {expiry}')
                    
                    # Self-signed check
                    subject = str(cert.get('subject', ''))
                    issuer = str(cert.get('issuer', ''))
                    if subject == issuer:
                        self.add_vuln('HTTPS', 'Self-signed certificate', 'Medium',
                                     'Replace with valid certificate')
                    
                    # TLS version
                    version = ssock.version()
                    if version in ['TLSv1', 'TLSv1.1']:
                        self.add_vuln('HTTPS', f'Outdated TLS: {version}', 'High',
                                     f'Upgrade to TLSv1.2+')
                        
        except Exception as e:
            print(f"[-] SSL error: {e}")

    def add_vuln(self, service, description, severity, exploit):
        """Adiciona vulnerabilidade"""
        vuln = {
            'service': service,
            'description': description,
            'severity': severity,
            'exploit': exploit.format(self.target)
        }
        self.results['vulnerabilities'].append(vuln)
        print(f"\n[!] {severity}: {description}")
        print(f"    -> {exploit.format(self.target)}")

    def check_service_vulns(self):
        """Verifica vulnerabilidades por serviço"""
        for port_info in self.results['ports']:
            service = port_info['service']
            port = port_info['port']
            
            if service in self.vuln_db:
                db = self.vuln_db[service]
                print(f"\n[+] Checking {service} on port {port}")
                
                # Add vulnerabilities
                for vuln in db['vulns']:
                    self.add_vuln(service, vuln, 'Medium', db['exploit'][0])
                
                # Add tools
                for tool in db['tools']:
                    self.results['tools'].append(tool.format(self.target))
                
                # Specific checks
                if service == 'FTP':
                    try:
                        import ftplib
                        ftp = ftplib.FTP(self.target, timeout=3)
                        ftp.login('anonymous', 'test@test.com')
                        self.add_vuln('FTP', 'Anonymous login allowed', 'High',
                                     'ftp anonymous@{}')
                        ftp.quit()
                    except: pass
                
                elif service == 'MySQL':
                    self.add_vuln('MySQL', 'Check for default credentials', 'High',
                                 'mysql -h {} -u root -p')
                
                elif service == 'Redis':
                    self.add_vuln('Redis', 'Check for no authentication', 'High',
                                 'redis-cli -h {} info')

    def recommend_tools(self):
        """Recomenda ferramentas"""
        tools_set = set(self.results['tools'])
        
        # Additional tools based on services
        services = [s['service'] for s in self.results['ports']]
        
        if 'HTTP' in services or 'HTTPS' in services:
            tools_set.add('sqlmap -u "http://{}/" --dbs --batch')
            tools_set.add('nikto -h http://{}')
            tools_set.add('dirb http://{}/')
            tools_set.add('wpscan --url http://{}/')
            tools_set.add('xsstrike -u "http://{}/" --crawl')
        
        if 'SSH' in services:
            tools_set.add('hydra -L users.txt -P pass.txt ssh://{}')
            tools_set.add('ssh-audit {}')
        
        if 'SMB' in services:
            tools_set.add('enum4linux -a {}')
            tools_set.add('crackmapexec smb {}')
        
        if 'DNS' in services:
            tools_set.add('dnsrecon -d {}')
            tools_set.add('fierce -dns {}')
        
        self.results['tools'] = list(tools_set)
        
        print("\n[+] Recommended Tools:")
        for tool in sorted(self.results['tools'])[:15]:
            print(f"    {tool}")

    def generate_report(self):
        """Gera relatório"""
        print("\n" + "="*70)
        print(f"SCAN REPORT - {self.target}")
        print("="*70)
        print(f"IP: {self.results['ip']}")
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Open Ports: {len(self.results['ports'])}")
        print("\nServices Found:")
        for p in self.results['ports']:
            print(f"  {p['port']}: {p['service']}")
        
        print(f"\nVulnerabilities Found: {len(self.results['vulnerabilities'])}")
        if self.results['vulnerabilities']:
            print("\n" + "-"*50)
            for i, vuln in enumerate(self.results['vulnerabilities'], 1):
                print(f"\n{i}. [{vuln['severity']}] {vuln['service']}: {vuln['description']}")
                print(f"   Exploit: {vuln['exploit']}")
        
        print(f"\nRecommended Tools ({len(self.results['tools'])}):")
        for tool in sorted(self.results['tools'])[:20]:
            print(f"  {tool}")
        
        print("\n" + "="*70)
        
        # Save report
        filename = f"scan_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(json.dumps(self.results, indent=2, default=str))
        print(f"\n[+] Report saved: {filename}")

    def run(self):
        """Executa scan completo"""
        print(f"\n{'='*50}")
        print(f"FAST PENTEST SCANNER")
        print(f"Target: {self.target}")
        print(f"{'='*50}\n")
        
        # DNS Resolution
        if not self.resolve_dns():
            return
        
        # Port Scan
        self.scan_ports()
        
        # HTTP/HTTPS checks
        if any(p['port'] in [80, 8080] for p in self.results['ports']):
            self.check_http(80)
        if any(p['port'] in [443, 8443] for p in self.results['ports']):
            self.check_https(443)
        
        # Service vulnerabilities
        self.check_service_vulns()
        
        # Tool recommendations
        self.recommend_tools()
        
        # Report
        self.generate_report()

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 scanner.py <target>")
        print("Exemplo: python3 scanner.py exemplo.com")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = FastScanner(target)
    scanner.run()

if __name__ == "__main__":
    main()
