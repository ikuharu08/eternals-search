import sqlite3
from datetime import datetime
from auth import get_password_hash
import json
import logging

class Database:
    def __init__(self, db_name='eternals_search.db'):
        self.db_name = db_name

    def init_db(self):
        with sqlite3.connect(self.db_name) as conn:
            c = conn.cursor()
            
            # Create devices table if not exists
            c.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT,
                    port INTEGER,
                    banner JSON,  -- Ubah ke JSON type untuk menyimpan semua info
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (ip, port)
                )
            ''')
            
            # Create users table
            c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    full_name TEXT,
                    profile_pic TEXT,
                    password_hash TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()

    def save_device(self, ip, port, banner):
        with sqlite3.connect(self.db_name) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO devices VALUES (?,?,?,?)", 
                     (ip, port, banner, datetime.now().isoformat()))
            conn.commit()

    def get_all_devices(self):
        """Get all devices with JSON banner"""
        with sqlite3.connect(self.db_name) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            devices = c.execute('SELECT * FROM devices').fetchall()
            return [{
                'ip': d['ip'],
                'port': d['port'],
                'banner': json.loads(d['banner']) if d['banner'] else None,
                'timestamp': d['timestamp']
            } for d in devices]

    def get_total_devices(self):
        """Get total number of devices in database"""
        with sqlite3.connect(self.db_name) as conn:
            c = conn.cursor()
            return c.execute('SELECT COUNT(DISTINCT ip) FROM devices').fetchone()[0]

    def get_latest_devices(self, limit=100):
        """Get latest devices with pagination"""
        with sqlite3.connect(self.db_name) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            devices = c.execute('''
                SELECT * FROM devices 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,)).fetchall()
            return [{
                'ip': d['ip'],
                'port': d['port'],
                'banner': json.loads(d['banner']) if d['banner'] else None,
                'timestamp': d['timestamp']
            } for d in devices]

    def get_devices_by_ip(self, ip):
        """Get devices filtered by IP"""
        with sqlite3.connect(self.db_name) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            devices = c.execute('SELECT * FROM devices WHERE ip = ?', (ip,)).fetchall()
            return [{
                'ip': d['ip'],
                'port': d['port'],
                'banner': json.loads(d['banner']) if d['banner'] else None,
                'timestamp': d['timestamp']
            } for d in devices]

    def get_scan_history(self):
        """Get scan history with aggregated device counts"""
        with sqlite3.connect(self.db_name) as conn:
            c = conn.cursor()
            history = c.execute('''
                SELECT 
                    date(timestamp) as scan_date,
                    count(distinct ip) as devices_found,
                    min(timestamp) as timestamp
                FROM devices 
                GROUP BY date(timestamp)
                ORDER BY scan_date DESC
                LIMIT 30
            ''').fetchall()
            
            return [{
                'date': h[0],
                'devices_found': h[1],
                'timestamp': h[2]
            } for h in history]

    def create_default_user(self):
        try:
            with sqlite3.connect(self.db_name) as conn:
                c = conn.cursor()
                
                # Check if default user exists
                user = c.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
                if user:
                    return
                
                # Create default user with hashed password
                password_hash = get_password_hash('admin123')
                c.execute('''
                    INSERT INTO users (username, full_name, password_hash)
                    VALUES (?, ?, ?)
                ''', ('admin', 'Administrator', password_hash))
                conn.commit()
                print("Default user created successfully!")
        except Exception as e:
            print(f"Error creating default user: {str(e)}")

    def search_devices(self, query=None, port=None, banner=None, page=1, per_page=100):
        """Search devices with pagination"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                
                # Build query
                query_parts = ["SELECT * FROM devices WHERE 1=1"]
                count_parts = ["SELECT COUNT(*) FROM devices WHERE 1=1"]
                params = []
                
                if query:
                    condition = "AND (ip LIKE ? OR banner LIKE ?)"
                    query_parts.append(condition)
                    count_parts.append(condition)
                    params.extend([f"%{query}%", f"%{query}%"])
                
                if port:
                    condition = "AND port = ?"
                    query_parts.append(condition)
                    count_parts.append(condition)
                    params.append(port)
                    
                if banner:
                    condition = "AND banner LIKE ?"
                    query_parts.append(condition)
                    count_parts.append(condition)
                    params.append(f"%{banner}%")
                
                # Get total count
                total = c.execute(" ".join(count_parts), params).fetchone()[0]
                
                # Add pagination
                query_parts.append("ORDER BY timestamp DESC LIMIT ? OFFSET ?")
                params.extend([per_page, (page - 1) * per_page])
                
                # Execute final query
                devices = c.execute(" ".join(query_parts), params).fetchall()
                
                return {
                    'items': [{
                        'ip': d['ip'],
                        'port': d['port'],
                        'banner': json.loads(d['banner']) if d['banner'] else None,
                        'timestamp': d['timestamp']
                    } for d in devices],
                    'pagination': {
                        'total': total,
                        'page': page,
                        'per_page': per_page,
                        'pages': (total + per_page - 1) // per_page
                    }
                }
                
        except Exception as e:
            logging.error(f"Error searching devices: {str(e)}")
            return {'items': [], 'pagination': {'total': 0, 'page': 1, 'per_page': per_page, 'pages': 0}} 