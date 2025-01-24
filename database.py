import sqlite3
from datetime import datetime

class Database:
    def __init__(self, db_name='the_list.db'):
        self.db_name = db_name

    def init_db(self):
        with sqlite3.connect(self.db_name) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS devices
                     (ip text, port integer, banner text, timestamp text)''')
            conn.commit()

    def save_device(self, ip, port, banner):
        with sqlite3.connect(self.db_name) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO devices VALUES (?,?,?,?)", 
                     (ip, port, banner, datetime.now().isoformat()))
            conn.commit()

    def get_all_devices(self):
        with sqlite3.connect(self.db_name) as conn:
            c = conn.cursor()
            devices = c.execute('SELECT * FROM devices').fetchall()
            return [{'ip': d[0], 'port': d[1], 'banner': d[2], 'timestamp': d[3]} 
                   for d in devices]

    def get_total_devices(self):
        """Get total number of devices in database"""
        with sqlite3.connect(self.db_name) as conn:
            c = conn.cursor()
            return c.execute('SELECT COUNT(DISTINCT ip) FROM devices').fetchone()[0]

    def get_latest_devices(self, limit=100):
        """Get latest devices with pagination"""
        with sqlite3.connect(self.db_name) as conn:
            c = conn.cursor()
            devices = c.execute('''
                SELECT * FROM devices 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,)).fetchall()
            return [{'ip': d[0], 'port': d[1], 'banner': d[2], 'timestamp': d[3]} 
                   for d in devices]

    def get_devices_by_ip(self, ip):
        """Get devices filtered by IP"""
        with sqlite3.connect(self.db_name) as conn:
            c = conn.cursor()
            devices = c.execute('SELECT * FROM devices WHERE ip = ?', (ip,)).fetchall()
            return [{'ip': d[0], 'port': d[1], 'banner': d[2], 'timestamp': d[3]} 
                   for d in devices]

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