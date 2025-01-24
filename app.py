from flask import Flask, jsonify, render_template, request, Response
from scanner import EternalsSearchScanner
from database import Database
from ip_utils import RIPEManager
import threading
import csv
from io import StringIO

app = Flask(__name__)
db = Database()
scanner = EternalsSearchScanner()
ripe = RIPEManager()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/devices')
def get_devices():
    ip_filter = request.args.get('ip')
    limit = request.args.get('limit', 100, type=int)
    
    if ip_filter:
        return jsonify(db.get_devices_by_ip(ip_filter))
    return jsonify(db.get_latest_devices(limit))

@app.route('/api/scan', methods=['POST'])
def start_scan():
    try:
        data = request.json
        print(f"Received scan request: {data}")  # Debug log
        
        # Validate input
        if data['scan_type'] == 'country':
            country_codes = data.get('country_codes', [])
            if not country_codes:
                return jsonify({
                    'success': False,
                    'message': 'Country codes required'
                })
                
            print(f"Getting IP ranges for countries: {country_codes}")  # Debug log
            # Get IP ranges for selected countries
            ip_ranges = []
            for code in country_codes:
                ranges = ripe.get_country_ip_ranges(code)
                if ranges:
                    ip_ranges.extend(ranges)
                    
            print(f"Found IP ranges: {ip_ranges}")  # Debug log
                    
        else:
            # Custom IP range
            ip_ranges = data.get('ip_range', '').split('\n')
            
        if not ip_ranges:
            return jsonify({
                'success': False,
                'message': 'No valid IP ranges found for selected countries'
            })

        # Start scan in background thread
        scan_thread = threading.Thread(
            target=scanner.scan_network,
            kwargs={
                'ip_ranges': ip_ranges,
                'port_range': data.get('port_range', '1-1000'),
                'speed': data.get('speed', 'normal')
            }
        )
        scan_thread.daemon = True
        scan_thread.start()

        return jsonify({
            'success': True,
            'message': f'Scan started for {len(ip_ranges)} IP ranges',
            'ip_ranges': ip_ranges[:5],  # Show first 5 ranges as preview
            'total_ranges': len(ip_ranges)
        })
        
    except Exception as e:
        print(f"Error starting scan: {str(e)}")  # Debug log
        return jsonify({
            'success': False,
            'message': f'Error starting scan: {str(e)}'
        })

@app.route('/api/status')
def get_status():
    return jsonify({
        'status': scanner.current_status if scanner.is_active else 'idle',
        'is_scanning': scanner._is_scanning,
        'progress': scanner.progress,
        'current_ip': scanner.current_ip,
        'results': scanner.results,
        'start_time': scanner.scan_start_time.isoformat() if scanner.scan_start_time else None,
        'discovered_devices': scanner.discovered_devices
    })

@app.route('/api/export', methods=['GET'])
def export_devices():
    format_type = request.args.get('format', 'csv')
    devices = db.get_latest_devices()
    
    if format_type == 'csv':
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['IP', 'Port', 'Banner', 'Timestamp'])
        for device in devices:
            writer.writerow([
                device['ip'],
                device['port'],
                device['banner'],
                device['timestamp']
            ])
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={"Content-disposition": "attachment; filename=devices.csv"}
        )
    
    return jsonify({"error": "Unsupported format"}), 400

@app.route('/api/countries')
def get_countries():
    """Get list of all countries with their IP range counts"""
    countries = ripe.get_country_list()
    return jsonify(countries)

@app.route('/api/country/<country_code>/ranges')
def get_country_ranges(country_code):
    """Get IP ranges for specific country"""
    ranges = ripe.get_country_ip_ranges(country_code.upper())
    return jsonify(ranges)

@app.route('/api/preview', methods=['POST'])
def preview_scan():
    data = request.json
    ranges = data.get('ranges', [])
    exclude_ranges = data.get('exclude_ranges', [])
    
    # Validate and get preview
    valid_ranges = ripe.validate_ip_ranges(ranges, exclude_ranges)
    preview = ripe.preview_ranges(valid_ranges)
    
    return jsonify(preview)

@app.route('/api/scan/pause', methods=['POST'])
def pause_scan():
    success = scanner.pause_scan()
    return jsonify({
        'success': success,
        'message': 'Scan paused' if success else 'No active scan to pause'
    })

@app.route('/api/scan/resume', methods=['POST'])
def resume_scan():
    success = scanner.resume_scan()
    return jsonify({
        'success': success,
        'message': 'Scan resumed' if success else 'No paused scan to resume'
    })

@app.route('/api/scan/stop', methods=['POST'])
def stop_scan():
    scanner.stop_scan()
    return jsonify({
        'success': True,
        'message': 'Scan stopped'
    })

@app.route('/api/scan/history')
def get_scan_history():
    """Get scan history with device counts"""
    try:
        # Ambil history dari database
        history = db.get_scan_history()
        return jsonify(history)
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

if __name__ == '__main__':
    db.init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)