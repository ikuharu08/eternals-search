import subprocess
import socket
from queue import Queue
import threading
from database import Database
import json
from datetime import datetime
import os
import logging
import ipaddress
import time

class EternalsSearchScanner:
    def __init__(self):
        self.db = Database()
        self._is_scanning = False
        self._is_paused = False
        self.progress = 0
        self.current_ip = None
        self.results = []
        self._status_file = 'scanner_status.json'
        self._load_status()
        self.current_scan = None
        self.is_active = False
        self.scan_start_time = None
        self.discovered_devices = 0

    def _save_status(self):
        """Save scanner status to JSON file"""
        status = {
            'is_scanning': self._is_scanning,
            'is_paused': self._is_paused,
            'progress': self.progress,
            'current_ip': self.current_ip,
            'results': self.results,
            'current_status': getattr(self, 'current_status', 'idle'),
            'discovered_devices': self.discovered_devices,
            'scan_start_time': self.scan_start_time.isoformat() if self.scan_start_time else None
        }
        try:
            with open(self._status_file, 'w') as f:
                json.dump(status, f)
        except Exception as e:
            logging.error(f"Error saving status: {e}")

    def _load_status(self):
        """Load scanner status from JSON file"""
        try:
            if os.path.exists(self._status_file):
                with open(self._status_file, 'r') as f:
                    status = json.load(f)
                    self._is_scanning = status.get('is_scanning', False)
                    self._is_paused = status.get('is_paused', False)
                    self.progress = status.get('progress', 0)
                    self.current_ip = status.get('current_ip')
                    self.results = status.get('results', [])
        except Exception as e:
            logging.error(f"Error loading status: {e}")

    def get_status(self):
        if not self.is_active:
            return {
                "status": "idle",
                "progress": 0,
                "message": "No active scan"
            }
        self._load_status()  # Reload status from disk
        return {
            "is_scanning": self._is_scanning,
            "status": self.current_status,
            "start_time": self.scan_start_time.isoformat() if self.scan_start_time else None,
            "discovered_devices": self.discovered_devices,
            "total_devices": self.db.get_total_devices()
        }

    def banner_grab(self, ip, port, queue):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            sock.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            queue.put((ip, port, banner))
        except:
            pass

    def scan_network(self, **kwargs):
        self.is_active = True
        queue = Queue()
        try:
            # Get parameters from kwargs
            ip_ranges = kwargs.get('ip_ranges', [])
            port_range = kwargs.get('port_range', '1-1000')
            speed = kwargs.get('speed', 'normal')
            
            print(f"Starting scan with: IP ranges={ip_ranges}, ports={port_range}, speed={speed}")
            
            if not ip_ranges:
                raise ValueError("No IP ranges provided")
            
            # Set status ke scanning
            self._is_scanning = True
            self.current_status = f"Starting scan of {len(ip_ranges)} ranges..."
            self.scan_start_time = datetime.now()
            self.discovered_devices = 0
            self._save_status()
            
            # Set RustScan speed parameters
            if speed == 'slow':
                batch_size = '500'
                timeout = '5000'
            elif speed == 'fast':
                batch_size = '2500'
                timeout = '2500'
            else:  # normal
                batch_size = '1000'
                timeout = '4000'
            
            # Scan each IP range
            for ip_range in ip_ranges:
                self.current_status = f"Scanning {ip_range}..."
                self._save_status()
                
                cmd = [
                    "rustscan",
                    "--addresses", ip_range,
                    "--batch-size", batch_size,
                    "--timeout", timeout,
                    "--range", port_range
                ]
                
                print(f"Running command: {' '.join(cmd)}")  # Debug log
                
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.stderr:
                        print(f"RustScan stderr: {result.stderr}")
                        
                    if not result.stdout:
                        print(f"No output from RustScan for {ip_range}")
                        continue
                        
                    scan_result = json.loads(result.stdout)
                    
                    # Process scan results
                    threads = []
                    total_hosts = len(scan_result.get('hosts', []))
                    processed_hosts = 0
                    
                    for host in scan_result.get('hosts', []):
                        ip = host.get('ip')
                        for port in host.get('ports', []):
                            port_number = port.get('port')
                            if port_number:
                                t = threading.Thread(target=self.banner_grab, args=(ip, port_number, queue))
                                threads.append(t)
                                t.start()
                        
                        processed_hosts += 1
                        self.progress = 50 + int((processed_hosts / total_hosts) * 40)
                        self._save_status()
                    
                    for t in threads:
                        t.join()
                        
                except json.JSONDecodeError as e:
                    print(f"Error parsing RustScan output for {ip_range}: {e}")
                    continue
                except Exception as e:
                    print(f"Error scanning {ip_range}: {e}")
                    continue
            
            # Save all results from queue
            self.current_status = "Saving results..."
            self.progress = 90
            self._save_status()
            
            while not queue.empty():
                ip, port, banner = queue.get()
                self.db.save_device(ip, port, banner)
                self.discovered_devices += 1
            
            self.current_status = "Scan completed"
            self.progress = 100
            self._save_status()
            return True
            
        except Exception as e:
            self.current_status = f"Error during scanning: {str(e)}"
            logging.error(f"Scan error: {e}")
            self._save_status()
            return False
            
        finally:
            self._is_scanning = False
            self._save_status()
            self.is_active = False

    @property
    def is_scanning(self):
        return self._is_scanning

    @is_scanning.setter 
    def is_scanning(self, value):
        self._is_scanning = value
        self._save_status()

    def start_scan(self, ip_ranges, ports, exclude_ranges=None):
        """Start scanning process"""
        if self.is_scanning:
            return False
        
        # Reset status
        self.progress = 0
        self.current_ip = None
        self.results = []
        
        # Set scanning flag
        self.is_scanning = True  # Pakai property setter
        self._save_status()
        
        # Start scan thread
        scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(ip_ranges, ports, exclude_ranges)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        return True

    def _scan_worker(self, ip_ranges, ports, exclude_ranges=None):
        """Worker thread for scanning"""
        try:
            # Convert IP ranges to list of IPs
            ip_list = []
            for ip_range in ip_ranges:
                network = ipaddress.ip_network(ip_range)
                ip_list.extend([str(ip) for ip in network])

            # Remove excluded IPs
            if exclude_ranges:
                exclude_ips = set()
                for exclude_range in exclude_ranges:
                    network = ipaddress.ip_network(exclude_range)
                    exclude_ips.update([str(ip) for ip in network])
                ip_list = [ip for ip in ip_list if ip not in exclude_ips]

            total_ips = len(ip_list)
            for i, ip in enumerate(ip_list):
                while self._is_paused:  # Tunggu ketika di-pause
                    time.sleep(1)
                    if not self.is_scanning:  # Check if stopped while paused
                        break
                
                if not self.is_scanning:  # Check if stopped
                    break
                    
                self.current_ip = ip
                self.progress = int((i + 1) / total_ips * 100)
                
                # Scan each port
                open_ports = []
                for port in ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)  # 1 second timeout
                        
                        result = sock.connect_ex((ip, port))
                        if result == 0:  # Port is open
                            service = self._get_service_banner(ip, port)
                            open_ports.append({
                                'port': port,
                                'service': service
                            })
                        sock.close()
                        
                    except (socket.timeout, ConnectionRefusedError):
                        continue
                    except Exception as e:
                        logging.error(f"Error scanning {ip}:{port} - {str(e)}")
                        
                # Save results if open ports found
                if open_ports:
                    self.results.append({
                        'ip': ip,
                        'ports': open_ports,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                self._save_status()
                
        except Exception as e:
            logging.error(f"Scan error: {e}")
        finally:
            self.is_scanning = False
            self._save_status()

    def _get_service_banner(self, ip, port):
        """Try to get service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            # Send HTTP GET request for web ports
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
            
        except:
            return "Unknown"

    def pause_scan(self):
        """Pause current scan"""
        if self.is_scanning:
            self._is_paused = True
            self.current_status = "Scan paused"
            self._save_status()
            return True
        return False

    def resume_scan(self):
        """Resume paused scan"""
        if self._is_paused:
            self._is_paused = False
            self.current_status = "Scan resumed"
            self._save_status()
            return True
        return False

    def stop_scan(self):
        """Stop current scan"""
        self.is_scanning = False
        self._is_paused = False
        self.current_status = "Scan stopped"
        self._save_status()