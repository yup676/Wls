#!/usr/bin/env python3
"""
Professional Pentesting Scanner - WSL Edition
Author: Security Research Team
License: For authorized testing only
"""

import socket
import ssl
import subprocess
import sys
import re
import json
import time
import threading
import queue
from datetime import datetime
from urllib.parse import urlparse, urljoin
import http.client
import requests
import dns.resolver
import whois
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import concurrent.futures
import argparse
import logging
from typing import Dict, List, Tuple, Optional, Set
import ipaddress
import struct
import base64
import hashlib
import random
from email.parser import Parser
import ftplib
import telnetlib
import smtplib
import poplib
import imaplib
import ldap3
import pymysql
import psycopg2
import redis

class ProfessionalScanner:
    def __init__(self, target: str, threads: int = 50, timeout: int = 5):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.start_time = datetime.now()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.results = {
            'target': target,
            'timestamp': self.start_time.isoformat(),
            'ip_addresses': [],
            'dns_records': {},
            'open_ports': [],
            'services': {},
            'banners': {},
            'http_headers': {},
            'cookies': {},
            'technologies': [],
            'ssl_info': {},
            'subdomains': [],
            'directories': [],
            'parameters': [],
            'vulnerabilities': [],
            'tool_recommendations': [],
            'security_headers': {},
            'cves': [],
            'whois_info': {},
            'email_addresses': [],
            'links_found': [],
            'forms_found': [],
            'javascript_files': [],
            'hidden_endpoints': []
        }
        
    def resolve_target(self) -> bool:
        """Perform comprehensive DNS resolution"""
        try:
            ip_list = []
            for family in [socket.AF_INET, socket.AF_INET6]:
                try:
                    results = socket.getaddrinfo(self.target, None, family, socket.SOCK_STREAM)
                    for result in results:
                        ip = result[4][0]
                        if ip not in ip_list:
                            ip_list.append(ip)
                except:
                    pass
            
            self.results['ip_addresses'] = ip_list
            print(f"[DNS] Resolved {self.target} to {len(ip_list)} IP addresses")
            
            # Get DNS records
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV']
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(self.target, rtype)
                    self.results['dns_records'][rtype] = [str(r) for r in answers]
                except:
                    pass
            
            return True
        except Exception as e:
            print(f"[ERROR] DNS resolution failed: {e}")
            return False
    
    def get_whois(self) -> None:
        """Retrieve WHOIS information"""
        try:
            domain_info = whois.whois(self.target)
            if domain_info:
                self.results['whois_info'] = {
                    'registrar': domain_info.registrar,
                    'creation_date': str(domain_info.creation_date),
                    'expiration_date': str(domain_info.expiration_date),
                    'name_servers': domain_info.name_servers,
                    'emails': domain_info.emails,
                    'org': domain_info.org
                }
        except:
            pass
    
    def scan_ports(self, ports: List[int]) -> None:
        """Multi-threaded port scanning without nmap"""
        print(f"[SCAN] Starting port scan with {self.threads} threads")
        open_ports = []
        port_queue = queue.Queue()
        results_queue = queue.Queue()
        
        # Add ports to queue
        for port in ports:
            port_queue.put(port)
        
        def worker():
            while not port_queue.empty():
                try:
                    port = port_queue.get_nowait()
                except queue.Empty:
                    break
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((self.results['ip_addresses'][0], port))
                    sock.close()
                    
                    if result == 0:
                        # Get banner if possible
                        banner = self.get_service_banner(self.results['ip_addresses'][0], port)
                        service = self.identify_service(port, banner)
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'banner': banner[:200] if banner else None
                        })
                        results_queue.put((port, service, banner))
                except:
                    pass
        
        # Start threads
        threads_list = []
        for _ in range(min(self.threads, len(ports))):
            t = threading.Thread(target=worker)
            t.start()
            threads_list.append(t)
        
        # Wait for completion
        for t in threads_list:
            t.join()
        
        self.results['open_ports'] = [p['port'] for p in open_ports]
        for port_info in open_ports:
            self.results['services'][port_info['port']] = port_info['service']
            if port_info['banner']:
                self.results['banners'][port_info['port']] = port_info['banner']
        
        print(f"[SCAN] Found {len(open_ports)} open ports")
    
    def get_service_banner(self, ip: str, port: int) -> Optional[str]:
        """Get service banner by connecting to port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            # Send probe for different protocols
            if port in [21, 22, 25, 80, 110, 143, 443, 993, 995]:
                if port == 21:
                    sock.send(b'QUIT\r\n')
                elif port == 22:
                    sock.send(b'SSH-2.0-OpenSSH_8.9\r\n')
                elif port == 25 or port == 587:
                    sock.send(b'EHLO test\r\n')
                elif port in [80, 443, 8080, 8443]:
                    sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + self.target.encode() + b'\r\n\r\n')
                elif port == 110:
                    sock.send(b'QUIT\r\n')
                elif port == 143:
                    sock.send(b'a001 LOGOUT\r\n')
                elif port == 3306:
                    sock.send(b'\x00\x00\x00\x00')
                elif port == 6379:
                    sock.send(b'INFO\r\n')
            
            banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except:
            return None
    
    def identify_service(self, port: int, banner: Optional[str]) -> str:
        """Identify service based on port and banner"""
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC',
            135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS',
            995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        
        if port in common_ports:
            service = common_ports[port]
        else:
            service = 'Unknown'
        
        # Identify from banner if available
        if banner:
            banner_lower = banner.lower()
            if 'openssh' in banner_lower:
                service = 'SSH'
            elif 'apache' in banner_lower:
                service = 'HTTP-Apache'
            elif 'nginx' in banner_lower:
                service = 'HTTP-Nginx'
            elif 'iis' in banner_lower:
                service = 'HTTP-IIS'
            elif 'ftp' in banner_lower:
                service = 'FTP'
            elif 'mysql' in banner_lower:
                service = 'MySQL'
            elif 'postgresql' in banner_lower:
                service = 'PostgreSQL'
            elif 'redis' in banner_lower:
                service = 'Redis'
            elif 'mongo' in banner_lower:
                service = 'MongoDB'
            elif 'exim' in banner_lower:
                service = 'SMTP-Exim'
            elif 'sendmail' in banner_lower:
                service = 'SMTP-Sendmail'
        
        return service
    
    def check_http_services(self) -> None:
        """Comprehensive HTTP/HTTPS service enumeration"""
        http_ports = [80, 443, 8080, 8443, 8000, 8888, 9000, 9443]
        for port in http_ports:
            if port not in self.results['open_ports']:
                continue
            
            protocol = 'https' if port in [443, 8443, 9443] else 'http'
            url = f"{protocol}://{self.target}:{port}"
            
            try:
                response = self.session.get(url, timeout=10, verify=False)
                
                # Store headers
                self.results['http_headers'][port] = dict(response.headers)
                
                # Check security headers
                security_headers = {
                    'Strict-Transport-Security': 'HSTS',
                    'Content-Security-Policy': 'CSP',
                    'X-Frame-Options': 'Clickjacking Protection',
                    'X-Content-Type-Options': 'MIME Sniffing Protection',
                    'X-XSS-Protection': 'XSS Protection',
                    'Referrer-Policy': 'Referrer Policy',
                    'Permissions-Policy': 'Permissions Policy'
                }
                
                missing_headers = []
                for header, name in security_headers.items():
                    if header not in response.headers:
                        missing_headers.append(name)
                
                if missing_headers:
                    self.results['vulnerabilities'].append({
                        'category': 'Security Headers',
                        'description': f'Missing security headers: {", ".join(missing_headers)}',
                        'severity': 'Medium',
                        'port': port
                    })
                    self.results['security_headers'][port] = {
                        'present': [h for h in security_headers if h in response.headers],
                        'missing': missing_headers
                    }
                
                # Check cookies
                if 'Set-Cookie' in response.headers:
                    cookie_string = response.headers['Set-Cookie']
                    self.results['cookies'][port] = cookie_string
                    
                    # Check cookie security
                    if 'Secure' not in cookie_string:
                        self.results['vulnerabilities'].append({
                            'category': 'Cookie Security',
                            'description': 'Cookie missing Secure flag',
                            'severity': 'Medium',
                            'port': port
                        })
                    if 'HttpOnly' not in cookie_string:
                        self.results['vulnerabilities'].append({
                            'category': 'Cookie Security',
                            'description': 'Cookie missing HttpOnly flag',
                            'severity': 'Low',
                            'port': port
                        })
                
                # Check technologies
                tech_patterns = {
                    'php': r'php|\.php|X-Powered-By: PHP',
                    'asp.net': r'\.aspx|X-AspNet-Version|ASP\.NET',
                    'node.js': r'node|express|x-powered-by: express',
                    'django': r'django|csrftoken',
                    'rails': r'rails|ruby',
                    'wordpress': r'wordpress|wp-|wp-content',
                    'joomla': r'joomla|com_content',
                    'drupal': r'drupal|sites/all',
                    'angular': r'ng-|angular|ng-app',
                    'react': r'react|_react',
                    'vue': r'vue|v-'
                }
                
                for tech, pattern in tech_patterns.items():
                    if re.search(pattern, response.text, re.I):
                        self.results['technologies'].append(tech)
                
                # Extract links
                links = re.findall(r'<a\s+(?:[^>]*?\s+)?href="([^"]*)"', response.text)
                self.results['links_found'].extend(links[:50])
                
                # Extract forms
                forms = re.findall(r'<form[^>]*action="([^"]*)"[^>]*>', response.text)
                self.results['forms_found'].extend(forms[:20])
                
                # Extract emails
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text)
                if emails:
                    self.results['email_addresses'].extend(emails[:20])
                
                # Extract JS files
                js_files = re.findall(r'<script[^>]*src="([^"]*\.js)"', response.text)
                self.results['javascript_files'].extend(js_files[:20])
                
            except Exception as e:
                print(f"[ERROR] HTTP scan on port {port}: {e}")
    
    def check_ssl_tls(self) -> None:
        """Comprehensive SSL/TLS analysis"""
        ssl_ports = [443, 8443, 9443, 993, 995, 465]
        for port in ssl_ports:
            if port not in self.results['open_ports']:
                continue
            
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Certificate info
                        self.results['ssl_info'][port] = {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'serialNumber': cert.get('serialNumber'),
                            'notBefore': cert.get('notBefore'),
                            'notAfter': cert.get('notAfter'),
                            'subjectAltName': cert.get('subjectAltName', [])
                        }
                        
                        # Check SSL vulnerabilities
                        ciphers = ssock.cipher()
                        
                        # Weak protocol check
                        if ssock.version() in ['TLSv1', 'TLSv1.1']:
                            self.results['vulnerabilities'].append({
                                'category': 'SSL/TLS',
                                'description': f'Outdated TLS version: {ssock.version()}',
                                'severity': 'High',
                                'port': port
                            })
                        
                        # Check certificate validity
                        from datetime import datetime
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if (not_after - datetime.now()).days < 30:
                            self.results['vulnerabilities'].append({
                                'category': 'SSL/TLS',
                                'description': f'Certificate expires in {(not_after - datetime.now()).days} days',
                                'severity': 'Medium',
                                'port': port
                            })
                        
                        # Check for self-signed
                        issuer_cn = dict(x[0] for x in cert.get('issuer', [])).get('commonName', '')
                        subject_cn = dict(x[0] for x in cert.get('subject', [])).get('commonName', '')
                        if issuer_cn == subject_cn:
                            self.results['vulnerabilities'].append({
                                'category': 'SSL/TLS',
                                'description': 'Self-signed certificate detected',
                                'severity': 'Medium',
                                'port': port
                            })
                        
            except Exception as e:
                print(f"[ERROR] SSL scan on port {port}: {e}")
    
    def check_service_vulnerabilities(self) -> None:
        """Check for known service vulnerabilities"""
        for port, service in self.results['services'].items():
            vulnerabilities = []
            cves = []
            
            # FTP vulnerabilities
            if service == 'FTP':
                vulnerabilities.extend([
                    'Anonymous login check recommended',
                    'FTP bounce attack possible if port 20 open',
                    'Weak password policy potential',
                    'Clear text credentials transmission'
                ])
                cves.extend(['CVE-2011-2523', 'CVE-2015-3306', 'CVE-2017-9248'])
                
                # Test anonymous login
                try:
                    ftp = ftplib.FTP(self.target, timeout=5)
                    ftp.login('anonymous', 'test@test.com')
                    vulnerabilities.append('Anonymous FTP login allowed')
                    ftp.quit()
                except:
                    pass
            
            # SSH vulnerabilities
            elif service == 'SSH':
                vulnerabilities.extend([
                    'Weak ciphers check recommended',
                    'Password brute force risk',
                    'Version disclosure possible',
                    'Host key validation'
                ])
                cves.extend(['CVE-2016-6210', 'CVE-2018-15473', 'CVE-2020-14145'])
                
                # Check for old SSH versions
                if 'SSH-1.99' in self.results['banners'].get(port, ''):
                    vulnerabilities.append('SSHv1 protocol supported (insecure)')
            
            # HTTP vulnerabilities
            elif 'HTTP' in service:
                vulnerabilities.extend([
                    'Cross-Site Scripting (XSS) potential',
                    'SQL Injection vectors',
                    'Directory listing risk',
                    'Information disclosure',
                    'CSRF vulnerability potential',
                    'Insecure file uploads',
                    'XML External Entity (XXE)'
                ])
                cves.extend(['CVE-2021-41773', 'CVE-2021-42013', 'CVE-2020-16898'])
                
                # Check for directory listing
                try:
                    resp = self.session.get(f"http://{self.target}:{port}/", timeout=5)
                    if 'Index of /' in resp.text or 'Parent Directory' in resp.text:
                        vulnerabilities.append('Directory listing enabled on root')
                except:
                    pass
            
            # Database vulnerabilities
            elif service in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']:
                vulnerabilities.extend([
                    f'Default credentials for {service}',
                    'Remote code execution risk',
                    'SQL injection if web-facing',
                    'Weak authentication mechanisms'
                ])
                
                if service == 'MySQL':
                    cves.extend(['CVE-2018-3282', 'CVE-2019-2795', 'CVE-2020-14854'])
                elif service == 'PostgreSQL':
                    cves.extend(['CVE-2019-10164', 'CVE-2020-14349'])
                elif service == 'Redis':
                    cves.extend(['CVE-2019-8321', 'CVE-2019-8322'])
            
            # SMTP vulnerabilities
            elif service in ['SMTP', 'SMTPS']:
                vulnerabilities.extend([
                    'Open relay possible',
                    'Email spoofing risk',
                    'Weak authentication',
                    'Server information disclosure'
                ])
                cves.extend(['CVE-2021-28513', 'CVE-2020-28241', 'CVE-2019-13945'])
            
            # RDP vulnerabilities
            elif service == 'RDP':
                vulnerabilities.extend([
                    'BlueKeep vulnerability potential',
                    'Weak encryption possible',
                    'Man-in-the-middle risk'
                ])
                cves.extend(['CVE-2019-0708', 'CVE-2020-0609', 'CVE-2020-0610'])
            
            # Print findings
            if vulnerabilities:
                for vuln in vulnerabilities:
                    self.results['vulnerabilities'].append({
                        'category': f'{service} Security',
                        'description': vuln,
                        'severity': 'Medium',
                        'port': port
                    })
            
            if cves:
                self.results['cves'].extend(cves[:5])
    
    def recommend_tools(self) -> None:
        """Recommend tools based on discovered services"""
        tools = []
        
        # Web application tools
        if any('HTTP' in s for s in self.results['services'].values()):
            tools.append({
                'tool': 'Burp Suite Professional',
                'purpose': 'Web application security testing and interception',
                'category': 'Web'
            })
            tools.append({
                'tool': 'OWASP ZAP',
                'purpose': 'Automated web vulnerability scanner',
                'category': 'Web'
            })
            tools.append({
                'tool': 'SQLMap',
                'purpose': 'SQL injection detection and exploitation',
                'category': 'Web'
            })
            tools.append({
                'tool': 'Nikto',
                'purpose': 'Web server vulnerability scanner',
                'category': 'Web'
            })
            tools.append({
                'tool': 'Dirb/Dirbuster',
                'purpose': 'Directory and file brute forcing',
                'category': 'Web'
            })
            tools.append({
                'tool': 'WPScan',
                'purpose': 'WordPress vulnerability scanner',
                'category': 'Web'
            })
            tools.append({
                'tool': 'XSStrike',
                'purpose': 'XSS detection and exploitation',
                'category': 'Web'
            })
        
        # Network tools
        if self.results['open_ports']:
            tools.append({
                'tool': 'Nmap',
                'purpose': 'Network discovery and security scanning',
                'category': 'Network'
            })
            tools.append({
                'tool': 'Masscan',
                'purpose': 'Massive port scanning',
                'category': 'Network'
            })
            tools.append({
                'tool': 'Wireshark',
                'purpose': 'Network protocol analysis',
                'category': 'Network'
            })
        
        # SSH tools
        if 'SSH' in self.results['services'].values():
            tools.append({
                'tool': 'Hydra',
                'purpose': 'SSH password brute forcing',
                'category': 'Brute Force'
            })
            tools.append({
                'tool': 'Medusa',
                'purpose': 'Network service brute forcing',
                'category': 'Brute Force'
            })
            tools.append({
                'tool': 'SSH-Audit',
                'purpose': 'SSH server security auditing',
                'category': 'Audit'
            })
        
        # Database tools
        if any(s in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis'] for s in self.results['services'].values()):
            tools.append({
                'tool': 'SQLMap',
                'purpose': 'Database vulnerability exploitation',
                'category': 'Database'
            })
            tools.append({
                'tool': 'Metasploit',
                'purpose': 'Exploitation framework',
                'category': 'Exploitation'
            })
        
        # DNS tools
        if 'DNS' in self.results['services'].values():
            tools.append({
                'tool': 'Dnsrecon',
                'purpose': 'DNS enumeration and reconnaissance',
                'category': 'DNS'
            })
            tools.append({
                'tool': 'Fierce',
                'purpose': 'DNS subdomain brute forcing',
                'category': 'DNS'
            })
        
        # SMB tools
        if 'SMB' in self.results['services'].values():
            tools.append({
                'tool': 'Enum4Linux',
                'purpose': 'SMB enumeration',
                'category': 'Windows'
            })
            tools.append({
                'tool': 'CrackMapExec',
                'purpose': 'Windows/Linux post-exploitation',
                'category': 'Windows'
            })
        
        # SSL/TLS tools
        if any(p in [443, 8443, 9443, 993, 995] for p in self.results['open_ports']):
            tools.append({
                'tool': 'SSLScan',
                'purpose': 'SSL/TLS configuration scanning',
                'category': 'SSL'
            })
            tools.append({
                'tool': 'TestSSL',
                'purpose': 'SSL/TLS security testing',
                'category': 'SSL'
            })
        
        # General tools
        tools.append({
            'tool': 'Metasploit Framework',
            'purpose': 'Exploit development and execution',
            'category': 'Framework'
        })
        tools.append({
            'tool': 'Searchsploit',
            'purpose': 'Exploit database search',
            'category': 'Exploitation'
        })
        
        self.results['tool_recommendations'] = tools
    
    def discover_subdomains(self) -> None:
        """Discover subdomains using common wordlist"""
        subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
                      'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog',
                      'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new',
                      'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta',
                      'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email',
                      'images', 'img', 'download', 'dns', 'piwik', 'stats', 'dashboard', 'portal', 'manage']
        
        found_subdomains = []
        
        def check_subdomain(sub):
            try:
                host = f"{sub}.{self.target}"
                socket.gethostbyname(host)
                found_subdomains.append(host)
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_subdomain, subdomains)
        
        self.results['subdomains'] = found_subdomains
        print(f"[SUBDOMAINS] Found {len(found_subdomains)} subdomains")
    
    def discover_directories(self) -> None:
        """Discover common directories on web servers"""
        dirs = [
            'admin', 'login', 'wp-admin', 'administrator', 'phpmyadmin', 'mysql',
            'backup', 'backups', 'tmp', 'temp', 'test', 'dev', 'logs', 'log',
            'config', 'conf', 'etc', 'include', 'includes', 'lib', 'libs',
            'modules', 'plugins', 'themes', 'uploads', 'upload', 'download',
            'images', 'img', 'css', 'js', 'javascript', 'assets', 'resources',
            'data', 'db', 'database', 'sql', 'dump', 'export', 'import',
            'api', 'rest', 'service', 'ws', 'web', 'app', 'application',
            'src', 'source', 'git', 'svn', 'hg', 'cvs', 'hidden', 'secret'
        ]
        
        http_ports = [p for p in self.results['open_ports'] if p in [80, 443, 8080, 8443, 8000, 8888]]
        found_dirs = []
        
        for port in http_ports:
            protocol = 'https' if port in [443, 8443, 9443] else 'http'
            base_url = f"{protocol}://{self.target}:{port}"
            
            for directory in dirs:
                try:
                    url = f"{base_url}/{directory}"
                    resp = self.session.head(url, timeout=5, allow_redirects=False)
                    if resp.status_code in [200, 301, 302, 403]:
                        found_dirs.append({
                            'url': url,
                            'status': resp.status_code,
                            'port': port
                        })
                except:
                    pass
        
        self.results['directories'] = found_dirs
        print(f"[DIRECTORIES] Found {len(found_dirs)} directories")
    
    def get_parameters(self) -> None:
        """Extract parameters from found URLs"""
        params = set()
        
        for link in self.results['links_found']:
            if '?' in link:
                parts = link.split('?')
                if len(parts) > 1:
                    param_str = parts[1]
                    for p in param_str.split('&'):
                        if '=' in p:
                            param_name = p.split('=')[0]
                            params.add(param_name)
        
        self.results['parameters'] = list(params)
        print(f"[PARAMETERS] Found {len(params)} unique parameters")
    
    def check_common_cves(self) -> None:
        """Check for common CVEs based on services"""
        cve_database = {
            'Apache': [
                'CVE-2021-41773', 'CVE-2021-42013', 'CVE-2020-16898',
                'CVE-2020-11984', 'CVE-2019-10098', 'CVE-2019-0211'
            ],
            'Nginx': [
                'CVE-2021-23017', 'CVE-2020-36309', 'CVE-2019-20372',
                'CVE-2019-9511', 'CVE-2018-16843'
            ],
            'IIS': [
                'CVE-2021-31166', 'CVE-2020-17085', 'CVE-2019-0942',
                'CVE-2019-0630', 'CVE-2018-8420'
            ],
            'MySQL': [
                'CVE-2021-35604', 'CVE-2021-2030', 'CVE-2020-14854',
                'CVE-2019-2795', 'CVE-2018-3282'
            ],
            'PostgreSQL': [
                'CVE-2020-14349', 'CVE-2019-10164', 'CVE-2018-10915',
                'CVE-2017-7546', 'CVE-2016-5423'
            ],
            'OpenSSH': [
                'CVE-2020-14145', 'CVE-2018-15473', 'CVE-2016-6210',
                'CVE-2015-5600', 'CVE-2008-4109'
            ],
            'WordPress': [
                'CVE-2021-39327', 'CVE-2021-29447', 'CVE-2020-35489',
                'CVE-2020-28035', 'CVE-2019-8942'
            ],
            'Tomcat': [
                'CVE-2020-9484', 'CVE-2019-12408', 'CVE-2019-0232',
                'CVE-2018-11784', 'CVE-2017-12615'
            ],
            'Redis': [
                'CVE-2019-8321', 'CVE-2019-8322', 'CVE-2018-12326',
                'CVE-2017-15047', 'CVE-2016-8339'
            ],
            'PHP': [
                'CVE-2021-21708', 'CVE-2020-7066', 'CVE-2019-11043',
                'CVE-2018-17082', 'CVE-2016-5771'
            ]
        }
        
        for service in self.results['services'].values():
            for tech in cve_database:
                if tech.lower() in service.lower():
                    self.results['cves'].extend(cve_database[tech])
        
        # Remove duplicates
        self.results['cves'] = list(set(self.results['cves']))
    
    def generate_report(self) -> str:
        """Generate comprehensive JSON report"""
        report = {
            'scan_metadata': {
                'target': self.target,
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': (datetime.now() - self.start_time).total_seconds(),
                'scanner_version': '1.0.0'
            },
            'network_discovery': {
                'ip_addresses': self.results['ip_addresses'],
                'dns_records': self.results['dns_records'],
                'whois': self.results['whois_info'],
                'subdomains': self.results['subdomains']
            },
            'port_scanning': {
                'open_ports': self.results['open_ports'],
                'services': self.results['services'],
                'banners': self.results['banners']
            },
            'web_analysis': {
                'http_headers': self.results['http_headers'],
                'technologies': list(set(self.results['technologies'])),
                'security_headers': self.results['security_headers'],
                'cookies': self.results['cookies'],
                'directories': self.results['directories'],
                'parameters': self.results['parameters'],
                'links': self.results['links_found'],
                'forms': self.results['forms_found'],
                'javascript': self.results['javascript_files'],
                'emails': self.results['email_addresses']
            },
            'ssl_analysis': self.results['ssl_info'],
            'vulnerability_assessment': {
                'findings': self.results['vulnerabilities'],
                'cves': list(set(self.results['cves']))
            },
            'tool_recommendations': self.results['tool_recommendations']
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def print_summary(self) -> None:
        """Print concise summary to console"""
        print("\n" + "="*80)
        print(f"SCAN COMPLETE - {self.target}")
        print("="*80)
        print(f"Duration: {(datetime.now() - self.start_time).total_seconds():.2f}s")
        print(f"IP Addresses: {len(self.results['ip_addresses'])}")
        print(f"Open Ports: {len(self.results['open_ports'])}")
        print(f"Services: {len(self.results['services'])}")
        print(f"Subdomains: {len(self.results['subdomains'])}")
        print(f"Directories: {len(self.results['directories'])}")
        print(f"Parameters: {len(self.results['parameters'])}")
        print(f"Vulnerabilities: {len(self.results['vulnerabilities'])}")
        print(f"CVEs: {len(self.results['cves'])}")
        print("="*80)
        
        if self.results['open_ports']:
            print("\nOpen Ports:")
            for port in sorted(self.results['open_ports']):
                service = self.results['services'].get(port, 'Unknown')
                print(f"  {port}/{service}")
        
        if self.results['vulnerabilities']:
            print("\nVulnerability Summary:")
            for vuln in self.results['vulnerabilities'][:10]:
                print(f"  [{vuln['severity']}] {vuln['category']}: {vuln['description'][:100]}")
            if len(self.results['vulnerabilities']) > 10:
                print(f"  ... and {len(self.results['vulnerabilities'])-10} more")
        
        if self.results['tool_recommendations']:
            print("\nRecommended Tools:")
            for tool in self.results['tool_recommendations'][:10]:
                print(f"  {tool['tool']}: {tool['purpose']}")
            if len(self.results['tool_recommendations']) > 10:
                print(f"  ... and {len(self.results['tool_recommendations'])-10} more")
    
    def run_full_scan(self) -> None:
        """Execute complete scan workflow"""
        print(f"[INIT] Starting professional scan of {self.target}")
        print(f"[INIT] Threads: {self.threads}, Timeout: {self.timeout}s")
        
        # Phase 1: DNS Resolution
        print("\n[PHASE 1] DNS Resolution")
        if not self.resolve_target():
            return
        
        # Phase 2: WHOIS
        print("\n[PHASE 2] WHOIS Lookup")
        self.get_whois()
        
        # Phase 3: Port Scanning (all ports)
        print("\n[PHASE 3] Port Scanning")
        all_ports = list(range(1, 65535))
        self.scan_ports(all_ports[:1000])  # First 1000 ports
        if len(self.results['open_ports']) > 0:
            # Scan common ports
            common_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,
                          1433,1521,3306,3389,5432,5900,6379,8080,8443,9000,9443,27017]
            self.scan_ports(common_ports)
        
        # Phase 4: Service Enumeration
        print("\n[PHASE 4] Service Enumeration")
        self.check_http_services()
        self.check_ssl_tls()
        
        # Phase 5: Web Analysis
        if any(p in [80, 443, 8080, 8443] for p in self.results['open_ports']):
            print("\n[PHASE 5] Web Application Analysis")
            self.discover_subdomains()
            self.discover_directories()
            self.get_parameters()
        
        # Phase 6: Vulnerability Assessment
        print("\n[PHASE 6] Vulnerability Assessment")
        self.check_service_vulnerabilities()
        self.check_common_cves()
        
        # Phase 7: Tool Recommendations
        print("\n[PHASE 7] Tool Recommendations")
        self.recommend_tools()
        
        # Phase 8: Report Generation
        print("\n[PHASE 8] Report Generation")
        report_json = self.generate_report()
        
        # Save report
        filename = f"scan_report_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            f.write(report_json)
        print(f"[REPORT] Saved to {filename}")
        
        # Print summary
        self.print_summary()

def parse_arguments():
    parser = argparse.ArgumentParser(description='Professional Pentesting Scanner')
    parser.add_argument('target', help='Target IP address or domain')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('-to', '--timeout', type=int, default=5,
                       help='Connection timeout in seconds (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    # Setup logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Check dependencies
    required_packages = ['requests', 'dnspython', 'python-whois', 'pyOpenSSL', 'cryptography']
    missing = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"Missing dependencies: {', '.join(missing)}")
        print("Install with: pip install " + ' '.join(missing))
        sys.exit(1)
    
    # Create scanner instance
    scanner = ProfessionalScanner(
        target=args.target,
        threads=args.threads,
        timeout=args.timeout
    )
    
    try:
        scanner.run_full_scan()
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Scan stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
