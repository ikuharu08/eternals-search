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
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Iterator
import sqlite3
from pathlib import Path
import requests

# Buat folder logs jika belum ada
LOG_DIR = "logs"
Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

class EternalsSearchScanner:
    def __init__(self):
        # Inisialisasi logger terlebih dahulu
        self.logger = logging.getLogger("scanner")
        self.logger.setLevel(logging.INFO)
        self.log_file_handler = None
        
        self._is_scanning = False
        self._is_paused = False
        self.current_ip = None
        self.progress = 0
        self.results = []
        self.discovered_devices = []
        self.scan_start_time = None
        self.executor = ThreadPoolExecutor(max_workers=500)
        self.db = Database()
        self.thread_limit = threading.Semaphore(500)  # Batasi jumlah thread aktif
        self._status_file = 'scanner_status.json'  # Atau path ke file status yang sesuai
        # Tambahkan rate limit dan batch size
        self.rate_limit = 1000
        self.batch_size = 500
        # Update proxy configuration untuk ScraperAPI
        self.scraper_api_key = "59f79d65e9107daec3b98b8b348a00b2"
        self.proxy_config = {
            "https": f"scraperapi:{self.scraper_api_key}@proxy-server.scraperapi.com:8001"
        }
        self.max_retries = 3

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
                    self.discovered_devices = status.get('discovered_devices', [])
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

    def scan_network(self, ip_ranges: List[str], exclude_ranges: Optional[List[str]] = None):
        self.logger.info("Scan network started")
        try:
            # Buat executor baru setiap kali scan dimulai
            self.executor = ThreadPoolExecutor(max_workers=500)
            
            self._is_scanning = True
            self._is_paused = False
            self.scan_start_time = datetime.now()
            self.results = []
            self.discovered_devices = []
            self.progress = 0
            self.current_ip = None
            self.completed_ips = 0
            self.total_ips = self._estimate_total_ips(ip_ranges, exclude_ranges)
            
            # Start logging
            self._start_logging(ip_ranges)
            
            # Gunakan generator untuk IP list
            ip_generator = self._generate_ip_generator(ip_ranges, exclude_ranges)
            
            futures = []
            for ip in ip_generator:
                if not self._is_scanning:
                    break
                        
                while self._is_paused:
                    time.sleep(1)  # Tunggu saat pause
                    if not self._is_scanning:  # Check jika stop ditekan saat pause
                        break
                        
                self.current_ip = ip
                self.completed_ips += 1
                if self.total_ips:
                    self.progress = int((self.completed_ips) / self.total_ips * 100)
                
                # Submit scan task ke thread pool
                if self._is_scanning and not self._is_paused:
                    future = self.executor.submit(self._scan_single_ip, ip)
                    futures.append(future)
            
            # Process results
            for future in as_completed(futures):
                if not self._is_scanning:
                    break
                        
                while self._is_paused:
                    time.sleep(1)
                    if not self._is_scanning:
                        break
                        
                if self._is_scanning and not self._is_paused:
                    self._process_future(future)
            
        except Exception as e:
            self.logger.error(f"Scan error: {str(e)}")
        finally:
            self._is_scanning = False
            self._stop_logging()

    def _parse_port_range(self, port_range: str) -> List[int]:
        ports = []
        ranges = port_range.split(',')
        for part in ranges:
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return ports

    def _generate_ip_generator(self, ip_ranges: List[str], exclude_ranges: Optional[List[str]] = None) -> Iterator[str]:
        """Generate IP addresses using a generator to handle large IP ranges."""
        exclude_ips = set()
        if exclude_ranges:
            for exclude_range in exclude_ranges:
                try:
                    network = ipaddress.ip_network(exclude_range)
                    exclude_ips.update(str(ip) for ip in network)
                except ValueError:
                    self.logger.warning(f"Invalid exclude IP range: {exclude_range}")

        for ip_range in ip_ranges:
            try:
                network = ipaddress.ip_network(ip_range)
                for ip in network:
                    ip_str = str(ip)
                    if ip_str not in exclude_ips:
                        yield ip_str
            except ValueError:
                self.logger.warning(f"Invalid IP range: {ip_range}")
        
    def _scan_single_ip(self, ip: str) -> tuple:
        """Scan IP menggunakan Shodan InternetDB dengan ScraperAPI proxy"""
        with self.thread_limit:
            if not self._is_scanning:
                return ip, []
            
            retries = 0
            while retries < self.max_retries:
                try:
                    # Gunakan ScraperAPI proxy
                    url = f"https://internetdb.shodan.io/{ip}"
                    response = requests.get(
                        url, 
                        proxies=self.proxy_config,
                        timeout=10,
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        open_ports_info = []
                        
                        # Process ports dan services dari Shodan
                        for port in data.get('ports', []):
                            service_info = {
                                'timestamp': datetime.now().isoformat(),
                                'ip': ip,
                                'port': port,
                                'hostnames': data.get('hostnames', []),
                                'cpes': data.get('cpes', []),
                                'vulns': data.get('vulns', []),
                                'tags': data.get('tags', [])
                            }
                            
                            open_ports_info.append({
                                'port': port,
                                'service': json.dumps(service_info)
                            })
                        
                        return ip, open_ports_info
                        
                    elif response.status_code == 404:
                        return ip, []
                    
                except requests.exceptions.RequestException as e:
                    self.logger.warning(f"Proxy error untuk {ip}: {str(e)}")
                    retries += 1
                    time.sleep(1)
                    continue
                
                except Exception as e:
                    self.logger.error(f"Error scanning {ip}: {str(e)}")
                    return ip, []
                
            self.logger.error(f"Gagal scan {ip} setelah {self.max_retries} percobaan")
            return ip, []

    def _process_scan_result(self, ip: str, open_ports: List[Dict]):
        try:
            with sqlite3.connect(self.db.db_name) as conn:
                c = conn.cursor()
                
                for port_info in open_ports:
                    if port_info['service'] is not None:
                        # Simpan langsung sebagai JSON string
                        c.execute('''
                            INSERT INTO devices (ip, port, banner, timestamp)
                            VALUES (?, ?, ?, datetime('now'))
                            ON CONFLICT(ip, port) DO UPDATE SET
                                banner = excluded.banner,
                                timestamp = datetime('now')
                        ''', (
                            ip,
                            port_info['port'],
                            port_info['service']  # Service sudah dalam format JSON string
                        ))
                
                conn.commit()
                
            # Log hasil scan
            self._log_scan_result(ip, open_ports)
            
        except Exception as e:
            self.logger.error(f"Error saving scan result to database: {str(e)}")
        
    def _get_service_banner(self, ip: str, port: int) -> str:
        try:
            # Skip HTTPX untuk port-port umum non-HTTP
            non_http_ports = {53, 22, 25, 110, 143, 465, 587, 993, 995}
            if port in non_http_ports:
                # Gunakan simple banner grab untuk non-HTTP ports
                banner_info = {
                    "timestamp": datetime.now().isoformat(),
                    "ip": ip,
                    "port": port,
                    "protocol": self._get_common_protocol(port),
                    "type": "non-http",
                    "raw_banner": self._simple_banner_grab(ip, port)
                }
                return json.dumps(banner_info)

            # Untuk port yang mungkin HTTP/HTTPS
            command = [
                "httpx",
                "-u", f"{ip}:{port}",
                "-title",
                "-tech-detect",
                "-status-code",
                "-location",
                "-server",
                "-content-length",
                "-content-type",
                "-method",
                "-follow-redirects",
                "-silent",
                "-json",
                "-header", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "-response-time",
                "-timeout", "5"  # Kurangi timeout jadi 5 detik
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=7  # Timeout subprocess sedikit lebih lama
            )
            
            if result.stdout:
                try:
                    banner_json = json.loads(result.stdout.strip())
                    banner_json["type"] = "http"
                    return json.dumps(banner_json)
                except json.JSONDecodeError:
                    return None
                
        except subprocess.TimeoutExpired:
            self.logger.info(f"Timeout scanning {ip}:{port} - possibly non-HTTP service")
            return None
        except Exception as e:
            self.logger.error(f"Error getting banner for {ip}:{port}: {str(e)}")
            return None

    def _simple_banner_grab(self, ip: str, port: int) -> str:
        """Simple banner grab for non-HTTP ports"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            # Send appropriate probe based on port
            if port == 53:  # DNS
                # Simple DNS query
                sock.send(b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            else:
                # Generic probe
                sock.send(b'\r\n\r\n')
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner
        except Exception:
            return None

    def _get_common_protocol(self, port: int) -> str:
        """Return common protocol name for well-known ports"""
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTPS",
            587: "SMTP",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            5432: "PostgreSQL",
            27017: "MongoDB"
        }
        return common_ports.get(port, "Unknown")

    def pause_scan(self) -> bool:
        """Pause scanning process"""
        try:
            if self._is_scanning and not self._is_paused:
                self._is_paused = True
                self.current_status = "paused"
                
                # Force pause executor
                if hasattr(self, 'executor'):
                    try:
                        # Pause semua threads yang sedang berjalan
                        self.executor._work_queue.queue.clear()
                    except Exception as e:
                        self.logger.error(f"Error pausing executor: {str(e)}")
                
                self._save_status()
                return True
        except Exception as e:
            self.logger.error(f"Error pausing scan: {str(e)}")
        return False
        
    def resume_scan(self) -> bool:
        """Resume scanning process"""
        try:
            if self._is_scanning and self._is_paused:
                self._is_paused = False
                self.current_status = "scanning"
                self._save_status()
                return True
        except Exception as e:
            self.logger.error(f"Error resuming scan: {str(e)}")
        return False
        
    def stop_scan(self):
        """Stop scanning process and cleanup resources"""
        try:
            # Set flag stop
            self._is_scanning = False
            self._is_paused = False
            
            # Force shutdown executor
            if hasattr(self, 'executor'):
                try:
                    # Cancel semua pending tasks
                    self.executor._threads.clear()
                    # Shutdown executor tanpa menunggu
                    self.executor.shutdown(wait=False, cancel_futures=True)
                    # Buat executor baru
                    self.executor = ThreadPoolExecutor(max_workers=500)
                except Exception as e:
                    self.logger.error(f"Error shutting down executor: {str(e)}")
            
            # Reset status
            self.current_ip = None
            self.progress = 0
            self.current_status = "Scan stopped"
            
            # Save final status
            self._save_status()
            
            # Stop logging
            self._stop_logging()
            
        except Exception as e:
            self.logger.error(f"Error stopping scan: {str(e)}")

    @property
    def is_scanning(self):
        return self._is_scanning

    @is_scanning.setter 
    def is_scanning(self, value):
        self._is_scanning = value
        self._save_status()

    def start_scan(self, ip_ranges, exclude_ranges=None):
        """Start scanning process"""
        if self.is_scanning:
            self.logger.info("Scan is already running")
            return False
        
        self.logger.info("Starting scan...")
        # Reset status
        self.progress = 0
        self.current_ip = None
        self.results = []
        
        # Set scanning flag
        self.is_scanning = True  # Pakai property setter
        self._save_status()
        
        # Start scan thread
        scan_thread = threading.Thread(
            target=self.scan_network,
            args=(ip_ranges, exclude_ranges)
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
                    self.semaphore.acquire()
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

    @property
    def status(self) -> str:
        if not self._is_scanning:
            return "idle"
        elif self._is_paused:
            return "paused"
        else:
            return "scanning"

    def _start_logging(self, ip_ranges: List[str]):
        try:
            # Pastikan folder logs ada
            if not os.path.exists(LOG_DIR):
                os.makedirs(LOG_DIR)
            
            # Buat nama file log di folder logs
            log_filename = f"{LOG_DIR}/scan_log_{self.scan_start_time.strftime('%Y%m%d_%H%M%S')}.txt"
            log_filepath = os.path.abspath(log_filename)

            # Setup logging handler untuk file
            self.log_file_handler = logging.FileHandler(log_filepath, mode='w', encoding='utf-8')
            self.log_file_handler.setLevel(logging.INFO)

            # Buat formatter tanpa cache agar log ditulis secara realtime
            log_formatter = logging.Formatter('%(message)s')
            self.log_file_handler.setFormatter(log_formatter)

            # Tambahkan handler ke logger
            self.logger.addHandler(self.log_file_handler)

            # Tulis header log
            self.logger.info(f"Scan started at: {self.scan_start_time}")
            self.logger.info(f"IP Ranges: {', '.join(ip_ranges)}")
            self.logger.info("="*50)

        except Exception as e:
            self.logger.error(f"Error creating log file: {str(e)}")

    def _log_scan_result(self, ip: str, open_ports: List[Dict]):
        if open_ports:
            log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {ip}:"
            for port_info in open_ports:
                log_entry += f"\n  - Port {port_info['port']}: {port_info['service']}"

            # Tulis log ke file dan console
            self.logger.info(log_entry)

    def _stop_logging(self):
        if self.logger and self.log_file_handler:
            self.logger.info(f"\nScan completed at: {datetime.now()}")
            self.logger.info(f"Total devices found: {len(self.discovered_devices)}")
            # Hapus handler setelah selesai
            self.logger.removeHandler(self.log_file_handler)
            self.log_file_handler.close()

    def _naabu_scan(self, ip: str) -> List[int]:
        try:
            # Kurangi concurrent threads untuk menghindari too many files
            command = [
                "naabu",
                "-host", ip,
                "-c", "100",  # Kurangi dari 500 ke 100
                "-json",
                "-silent",
                "-rate", "100"  # Tambahkan rate limiting
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True
            )

            # Parse output JSON
            open_ports = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        scan_result = json.loads(line)
                        if 'port' in scan_result:
                            open_ports.append(scan_result['port'])
                    except json.JSONDecodeError:
                        continue

            return open_ports

        except Exception as e:
            self.logger.error(f"Naabu exception: {str(e)}")
            return []

    def get_scan_history(self, limit: int = 100) -> List[Dict]:
        try:
            with sqlite3.connect(self.db.db_name) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                
                results = c.execute('''
                    SELECT ip, port, banner, timestamp
                    FROM devices
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (limit,)).fetchall()
                
                return [dict(row) for row in results]
                
        except Exception as e:
            self.logger.error(f"Error getting scan history: {str(e)}")
            return []

    @property
    def is_active(self) -> bool:
        return self._is_scanning

    def scan_single_device(self, ip: str, port: int) -> dict:
        """Scan single device menggunakan Shodan InternetDB"""
        try:
            # Setup logging untuk single device scan
            log_filename = f"{LOG_DIR}/single_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            if not os.path.exists(LOG_DIR):
                os.makedirs(LOG_DIR)
            
            file_handler = logging.FileHandler(log_filename, mode='w', encoding='utf-8')
            file_handler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(message)s')
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
            
            self.logger.info(f"Starting single device scan for {ip}")
            
            retries = 0
            while retries < self.max_retries:
                try:
                    proxy = self._get_next_proxy()
                    proxies = {'http': proxy, 'https': proxy} if proxy else None
                    
                    url = f"https://internetdb.shodan.io/{ip}"
                    response = requests.get(url, proxies=proxies, timeout=15, verify=False)
                    
                    if response.status_code == 200:
                        data = response.json()
                        ports = data.get('ports', [])
                        
                        if port in ports:
                            service_info = {
                                'timestamp': datetime.now().isoformat(),
                                'ip': ip,
                                'port': port,
                                'hostnames': data.get('hostnames', []),
                                'cpes': data.get('cpes', []),
                                'vulns': data.get('vulns', []),
                                'tags': data.get('tags', [])
                            }
                            
                            # Save to database
                            with sqlite3.connect(self.db.db_name) as conn:
                                c = conn.cursor()
                                c.execute('''
                                    INSERT INTO devices (ip, port, banner, timestamp)
                                    VALUES (?, ?, ?, datetime('now'))
                                    ON CONFLICT(ip, port) DO UPDATE SET
                                        banner = excluded.banner,
                                        timestamp = datetime('now')
                                ''', (ip, port, json.dumps(service_info)))
                                conn.commit()
                                
                            self.logger.info(f"Port {port} is open on {ip}")
                            return service_info
                        else:
                            self.logger.info(f"Port {port} is not open on {ip}")
                            return None
                            
                    elif response.status_code == 404:
                        self.logger.info(f"No information found for {ip}")
                        return None
                        
                except requests.exceptions.RequestException as e:
                    self.logger.warning(f"Proxy error: {str(e)}")
                    retries += 1
                    time.sleep(1)
                    continue
                    
                except Exception as e:
                    self.logger.error(f"Error scanning {ip}: {str(e)}")
                    return None
                    
            self.logger.error(f"Failed to scan {ip} after {self.max_retries} retries")
            return None
            
        except Exception as e:
            self.logger.error(f"Error in scan_single_device: {str(e)}")
            if 'file_handler' in locals():
                self.logger.removeHandler(file_handler)
                file_handler.close()
            raise
        finally:
            if 'file_handler' in locals():
                self.logger.removeHandler(file_handler)
                file_handler.close()

    def _estimate_total_ips(self, ip_ranges: List[str], exclude_ranges: Optional[List[str]] = None) -> int:
        total_ips = 0
        for ip_range in ip_ranges:
            network = ipaddress.ip_network(ip_range)
            total_ips += network.num_addresses  # Menggunakan num_addresses
        return total_ips

    def _process_future(self, future):
        try:
            ip, open_ports = future.result(timeout=5)
            if open_ports:
                self._process_scan_result(ip, open_ports)
        except Exception as e:
            self.logger.error(f"Error processing result: {str(e)}")

    def _increase_file_limit(self):
        """Increase system file limit"""
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_NOFILE, (65535, 65535))
        except Exception as e:
            self.logger.warning(f"Failed to increase file limit: {e}")

    def _scan_ip_batch(self, ip_batch: List[str]) -> None:
        """Scan a batch of IPs"""
        try:
            with self.thread_limit:
                # Convert IPs to string format naabu expects
                ip_list = ','.join(ip_batch)
                
                # Run naabu with rate limit
                cmd = f"naabu -l {ip_list} -p {self.ports} -rate {self.rate_limit}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    # Process results
                    self._process_scan_results(result.stdout)
                else:
                    self.logger.error(f"Scan failed for batch: {result.stderr}")
                    
        except Exception as e:
            self.logger.error(f"Error scanning batch: {e}")

    def start_scan(self, target_ips: List[str]) -> None:
        """Start scanning with batching"""
        try:
            self._increase_file_limit()
            self._is_scanning = True
            self.scan_start_time = datetime.now()
            
            # Split IPs into batches
            ip_batches = [target_ips[i:i + self.batch_size] 
                         for i in range(0, len(target_ips), self.batch_size)]
            
            total_batches = len(ip_batches)
            
            for i, batch in enumerate(ip_batches, 1):
                if self._is_paused:
                    self.logger.info("Scan paused")
                    break
                    
                self._scan_ip_batch(batch)
                self.progress = (i / total_batches) * 100
                self._save_status()
                
            self._is_scanning = False
            self._save_status()
            
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            self._is_scanning = False
            self._save_status()

    def _get_proxies(self):
        """Membaca daftar proxy dari file 'proxies.txt'"""
        try:
            with open('proxies.txt', 'r') as f:
                self.proxies = [line.strip() for line in f if line.strip()]
            self.logger.info(f"✨ Berhasil memuat {len(self.proxies)} proxy dari 'proxies.txt'!")
        except Exception as e:
            self.logger.error(f"❌ Error saat membaca 'proxies.txt': {str(e)}")
            self.proxies = []

    def _get_next_proxy(self):
        """Dapatkan proxy berikutnya dengan rotasi"""
        if not self.proxies:
            self._get_proxies()
        
        if self.proxies:
            proxy = self.proxies[self.current_proxy_index]
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
            return proxy
        return None