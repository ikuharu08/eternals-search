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
from typing import List, Dict, Optional
import sqlite3
from pathlib import Path

# Buat folder logs jika belum ada
LOG_DIR = "logs"
Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

class EternalsSearchScanner:
    def __init__(self):
        self._is_scanning = False
        self._is_paused = False
        self.current_ip = None
        self.progress = 0
        self.results = []
        self.discovered_devices = []
        self.scan_start_time = None
        self.executor = ThreadPoolExecutor(max_workers=500)
        self.logger = logging.getLogger("scanner")
        self.logger.setLevel(logging.INFO)
        self.log_file_handler = None
        self.db = Database()

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
            self.total_ips = 0
            self.completed_ips = 0
            
            # Start logging
            self._start_logging(ip_ranges)
            
            # Generate IP list
            ip_list = self._generate_ip_list(ip_ranges, exclude_ranges)
            self.total_ips = len(ip_list)
            
            # Start scanning
            futures = []
            for i, ip in enumerate(ip_list):
                if not self._is_scanning:
                    break
                    
                while self._is_paused:
                    time.sleep(1)  # Tunggu saat pause
                    if not self._is_scanning:  # Check jika stop ditekan saat pause
                        break
                    
                self.current_ip = ip
                self.progress = int((i + 1) / self.total_ips * 100)
                
                # Submit scan task ke thread pool
                if self._is_scanning and not self._is_paused:  # Double check sebelum submit
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
                    
                if self._is_scanning and not self._is_paused:  # Double check sebelum process
                    try:
                        ip, open_ports = future.result(timeout=5)  # Tambah timeout
                        if open_ports:
                            self._process_scan_result(ip, open_ports)
                    except Exception as e:
                        self.logger.error(f"Error processing result: {str(e)}")
                
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

    def _generate_ip_list(self, ip_ranges: List[str], exclude_ranges: Optional[List[str]]) -> List[str]:
        ip_list = []
        for ip_range in ip_ranges:
            try:
                network = ipaddress.ip_network(ip_range)
                ip_list.extend([str(ip) for ip in network])
            except ValueError:
                self.logger.warning(f"Invalid IP range: {ip_range}")
                
        if exclude_ranges:
            exclude_ips = set()
            for exclude_range in exclude_ranges:
                try:
                    network = ipaddress.ip_network(exclude_range)
                    exclude_ips.update([str(ip) for ip in network])
                except ValueError:
                    self.logger.warning(f"Invalid exclude IP range: {exclude_range}")
                    
            ip_list = [ip for ip in ip_list if ip not in exclude_ips]
            
        return ip_list
        
    def _scan_single_ip(self, ip: str) -> tuple:
        if not self._is_scanning:
            return ip, []
        try:
            # Panggil Naabu untuk scan IP
            open_ports = self._naabu_scan(ip)

            # Dapatkan service banner untuk port yang terbuka
            open_ports_info = []
            for port in open_ports:
                service = self._get_service_banner(ip, port)
                open_ports_info.append({
                    'port': port,
                    'service': service
                })
            return ip, open_ports_info

        except Exception as e:
            self.logger.error(f"Error scanning {ip}: {str(e)}")
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
            # Run Naabu dengan 500 concurrent threads
            command = [
                "naabu",
                "-host", ip,
                "-c", "500",  # Set ke 500 threads
                "-json",
                "-silent"
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
            
            self.logger.info(f"Starting single device scan for {ip}:{port}")
            
            # Gunakan naabu untuk scan port
            command = [
                "naabu",
                "-host", ip,
                "-p", str(port),  # Scan port spesifik
                "-c", "500",
                "-json",
                "-silent"
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True
            )

            # Parse output naabu
            port_open = False
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        scan_result = json.loads(line)
                        if 'port' in scan_result and scan_result['port'] == port:
                            port_open = True
                            break
                    except json.JSONDecodeError:
                        continue

            if port_open:
                self.logger.info(f"Port {port} is open on {ip}")
                # Gunakan httpx untuk grab banner
                service = self._get_service_banner(ip, port)
                result = {
                    'ip': ip,
                    'port': port,
                    'banner': service,
                    'timestamp': datetime.now().isoformat()
                }

                # Simpan ke database jika ada banner
                if service:
                    with sqlite3.connect(self.db.db_name) as conn:
                        c = conn.cursor()
                        c.execute('''
                            INSERT INTO devices (ip, port, banner, timestamp)
                            VALUES (?, ?, ?, datetime('now'))
                            ON CONFLICT(ip, port) DO UPDATE SET
                                banner = excluded.banner,
                                timestamp = datetime('now')
                        ''', (ip, port, service))
                        conn.commit()
                    self.logger.info(f"Saved to database: {ip}:{port} - {service}")
            else:
                self.logger.info(f"Port {port} is closed on {ip}")
                result = {
                    'ip': ip,
                    'port': port,
                    'banner': None,
                    'timestamp': datetime.now().isoformat()
                }

            self.logger.info(f"Scan completed for {ip}:{port}")
            
            # Cleanup logging
            self.logger.removeHandler(file_handler)
            file_handler.close()
            
            return result

        except Exception as e:
            self.logger.error(f"Error scanning {ip}:{port}: {str(e)}")
            if 'file_handler' in locals():
                self.logger.removeHandler(file_handler)
                file_handler.close()
            raise