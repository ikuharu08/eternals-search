from fastapi import FastAPI, HTTPException, Request, Response, UploadFile, File, Form, Cookie, Query
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from scanner import EternalsSearchScanner
from database import Database
from ip_utils import RIPEManager
import threading
import csv
from io import StringIO
from pydantic import BaseModel
from models import UserCreate, UserResponse, UserLogin
import sqlite3
from datetime import datetime
import shutil
import os
from auth import get_password_hash, verify_password
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends, status
import logging
from pathlib import Path
from typing import List

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# Definisikan direktori upload
UPLOAD_DIR = "uploads"
Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)

# Tambahkan route untuk melayani file upload
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

db = Database()
scanner = EternalsSearchScanner()
scanner.db = db
ripe = RIPEManager()

class ScanConfig(BaseModel):
    scan_type: str
    port_range: str = "1-1000"
    speed: str = "normal"
    country_codes: list[str] = None
    ip_range: str = None

class DeviceHistory(BaseModel):
    ip: str
    port: int
    banner: str
    timestamp: datetime

# Buat model untuk request
class DeviceScanRequest(BaseModel):
    ip: str
    port: int

security = HTTPBearer(auto_error=False)

# Definisikan logger kustom
logger = logging.getLogger("myapp_logger")
logger.setLevel(logging.INFO)

# Tambahkan handler jika belum ada
if not logger.hasHandlers():
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

async def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = None
        if credentials:
            token = credentials.credentials
            logging.debug(f"Token from credentials: {token}")

        if not token:
            token = request.cookies.get("token")
            logging.debug(f"Token from cookies: {token}")
            if not token:
                logging.debug("No token found in credentials or cookies")
                raise HTTPException(status_code=401, detail="Not authenticated")
        
        logging.debug(f"Using token: {token}")
        
        with sqlite3.connect(db.db_name) as conn:
            c = conn.cursor()
            user = c.execute('SELECT * FROM users WHERE id = ?', (token,)).fetchone()
            if not user:
                logging.debug("User not found for given token")
                raise HTTPException(status_code=401, detail="Invalid authentication credentials")
            logging.debug(f"Authenticated user: {user[1]}")
            return user
    except Exception as e:
        logging.exception("Error in get_current_user")
        raise HTTPException(status_code=401, detail="Could not validate credentials")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    token = request.cookies.get("token")
    if not token:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    # Verifikasi token
    try:
        with sqlite3.connect(db.db_name) as conn:
            c = conn.cursor()
            user = c.execute('SELECT * FROM users WHERE id = ?', (token,)).fetchone()
            if not user:
                response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
                response.delete_cookie("token", path="/")
                logger.info("Cookie 'token' has been deleted.")
                return response
    except:
        response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        response.delete_cookie("token", path="/")
        logger.info("Cookie 'token' has been deleted.")
        return response
    
    with open("templates/index.html") as f:
        return HTMLResponse(content=f.read())

@app.get("/api/devices")
async def get_devices(ip: str = None, limit: int = 100):
    if ip:
        return db.get_devices_by_ip(ip)
    return db.get_latest_devices(limit)

@app.post("/api/scan")
async def start_scan(config: ScanConfig):
    try:
        if config.scan_type == 'country':
            if not config.country_codes:
                raise HTTPException(status_code=400, detail="Country codes required")
            
            ip_ranges = []
            for code in config.country_codes:
                ranges = ripe.get_country_ip_ranges(code)
                if ranges:
                    ip_ranges.extend(ranges)
        else:
            ip_ranges = config.ip_range.split('\n') if config.ip_range else []
            
        if not ip_ranges:
            raise HTTPException(status_code=400, detail="No valid IP ranges found")
            
        scan_thread = threading.Thread(
            target=scanner.scan_network,
            kwargs={
                'ip_ranges': ip_ranges,
            }
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        return {
            "success": True,
            "message": f"Scan started for {len(ip_ranges)} IP ranges",
            "ip_ranges": ip_ranges[:5],
            "total_ranges": len(ip_ranges)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/status")
async def get_status(current_user: dict = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    status = "idle"
    if scanner.is_active:
        status = "Scanning" if not scanner._is_paused else "paused"
    
    return {
        "status": status,
        "is_scanning": scanner._is_scanning,
        "progress": scanner.progress,
        "current_ip": scanner.current_ip,
        "results": scanner.results,
        "start_time": scanner.scan_start_time.isoformat() if scanner.scan_start_time else None,
        "discovered_devices": scanner.discovered_devices
    }

@app.get("/api/export")
async def export_devices(format: str = "csv"):
    devices = db.get_latest_devices()
    
    if format == "csv":
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
        
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=devices.csv"}
        )
    
    raise HTTPException(status_code=400, detail="Unsupported format")

@app.get("/api/countries")
async def get_countries():
    return ripe.get_country_list()

@app.get("/api/country/{country_code}/ranges")
async def get_country_ranges(country_code: str):
    ranges = ripe.get_country_ip_ranges(country_code.upper())
    return ranges

@app.post("/api/preview")
async def preview_scan(request: Request):
    data = await request.json()
    ranges = data.get('ranges', [])
    exclude_ranges = data.get('exclude_ranges', [])
    
    # Validate and get preview
    valid_ranges = ripe.validate_ip_ranges(ranges, exclude_ranges)
    preview = ripe.preview_ranges(valid_ranges)
    
    return preview

@app.post("/api/scan/pause")
async def pause_scan():
    success = scanner.pause_scan()
    return {
        'success': success,
        'message': 'Scan paused' if success else 'No active scan to pause'
    }

@app.post("/api/scan/resume")
async def resume_scan():
    success = scanner.resume_scan()
    return {
        'success': success,
        'message': 'Scan resumed' if success else 'No paused scan to resume'
    }

@app.post("/api/scan/stop")
async def stop_scan():
    scanner.stop_scan()
    return {
        'success': True,
        'message': 'Scan stopped'
    }

@app.get("/api/scan/history")
async def get_scan_history():
    """Get scan history with device counts"""
    try:
        # Ambil history dari database
        history = db.get_scan_history()
        return history
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/devices/history", response_model=List[DeviceHistory])
async def get_devices_history(limit: int = Query(100, gt=0, le=1000)):
    try:
        # Panggil fungsi dari scanner
        history = scanner.get_scan_history(limit)
        
        # Format response
        return [{
            "ip": item["ip"],
            "port": item["port"],
            "banner": item["banner"],
            "timestamp": item["timestamp"]
        } for item in history]
        
    except Exception as e:
        logger.error(f"Error getting devices history: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/users", response_model=UserResponse)
async def create_user(user: UserCreate):
    try:
        with sqlite3.connect(db.db_name) as conn:
            c = conn.cursor()
            password_hash = get_password_hash(user.password)
            c.execute('''
                INSERT INTO users (username, full_name, profile_pic, password_hash)
                VALUES (?, ?, ?, ?)
            ''', (user.username, user.full_name, user.profile_pic, password_hash))
            conn.commit()
            
            # Get the created user
            user_id = c.lastrowid
            created_user = c.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            
            return {
                "id": created_user[0],
                "username": created_user[1],
                "full_name": created_user[2],
                "profile_pic": created_user[3],
                "created_at": created_user[5]
            }
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/login")
async def login(user: UserLogin, response: Response):
    try:
        with sqlite3.connect(db.db_name) as conn:
            c = conn.cursor()
            user_data = c.execute('SELECT * FROM users WHERE username = ?', (user.username,)).fetchone()
            
            if not user_data or not verify_password(user.password, user_data[4]):
                raise HTTPException(status_code=401, detail="Invalid username or password")
            
            # Set cookie
            response.set_cookie(
                key="token",
                value=str(user_data[0]),
                httponly=True,
                path="/"
            )
            
            return {
                "id": user_data[0],
                "username": user_data[1],
                "full_name": user_data[2],
                "profile_pic": user_data[3],
                "created_at": user_data[5]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/users/current")
async def get_current_user_api(current_user: dict = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {
        "id": current_user[0],
        "username": current_user[1],
        "full_name": current_user[2],
        "profile_pic": current_user[3],
        "created_at": current_user[4],
    }

@app.get("/api/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: int):
    try:
        with sqlite3.connect(db.db_name) as conn:
            c = conn.cursor()
            user = c.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
            return {
                "id": user[0],
                "username": user[1],
                "full_name": user[2],
                "profile_pic": user[3],
                "created_at": user[4]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/users/{user_id}", response_model=UserResponse)
async def update_user(user_id: int, user: UserCreate):
    try:
        with sqlite3.connect(db.db_name) as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE users
                SET username = ?, full_name = ?, profile_pic = ?
                WHERE id = ?
            ''', (user.username, user.full_name, user.profile_pic, user_id))
            conn.commit()
            
            updated_user = c.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            return {
                "id": updated_user[0],
                "username": updated_user[1],
                "full_name": updated_user[2],
                "profile_pic": updated_user[3],
                "created_at": updated_user[4]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/users/{user_id}/upload-profile-pic")
async def upload_profile_pic(user_id: int, file: UploadFile = File(...)):
    try:
        # Create upload directory if not exists
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        
        # Save file
        file_location = f"{UPLOAD_DIR}/{user_id}_{file.filename}"
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Update user profile pic in database
        with sqlite3.connect(db.db_name) as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE users
                SET profile_pic = ?
                WHERE id = ?
            ''', (file_location, user_id))
            conn.commit()
        
        return {"success": True, "file_path": file_location}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/users/current")
async def update_current_user(
    username: str = Form(...),
    full_name: str = Form(...),
    password: str = Form(None),
    file: UploadFile = File(None),
    token: str = Cookie(None)
):
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        with sqlite3.connect(db.db_name) as conn:
            c = conn.cursor()
            user = c.execute('SELECT * FROM users WHERE id = ?', (token,)).fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
            profile_pic = user[3]
            if file:
                # Pastikan direktori upload ada
                if not os.path.exists(UPLOAD_DIR):
                    os.makedirs(UPLOAD_DIR)
                
                # Buat nama file unik
                file_location = f"{UPLOAD_DIR}/{user[0]}_{file.filename}"
                
                # Simpan file
                with open(file_location, "wb") as buffer:
                    shutil.copyfileobj(file.file, buffer)
                profile_pic = file_location

            password_hash = user[4]
            if password:
                password_hash = get_password_hash(password)

            c.execute('''
                UPDATE users
                SET username = ?, full_name = ?, profile_pic = ?, password_hash = ?
                WHERE id = ?
            ''', (username, full_name, profile_pic, password_hash, user[0]))
            conn.commit()

            return {"message": "Profile updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/logout")
async def logout(response: Response):
    response.delete_cookie("token", path="/")
    return {"message": "Logged out successfully"}

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )
    else:
        if exc.status_code == 401:
            response = RedirectResponse(url="/login", status_code=302)
            response.delete_cookie("token", path="/")
            return response
        else:
            return HTMLResponse(
                content=f"<h1>{exc.status_code} - {exc.detail}</h1>",
                status_code=exc.status_code,
            )

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get("token")
    if token:
        # Verifikasi token
        try:
            with sqlite3.connect(db.db_name) as conn:
                c = conn.cursor()
                user = c.execute('SELECT * FROM users WHERE id = ?', (token,)).fetchone()
                if user:
                    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
                else:
                    # Token invalid, hapus cookie dan redirect ke /login
                    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
                    response.delete_cookie("token", path="/")
                    logger.info("Cookie 'token' has been deleted.")
                    return response
        except:
            response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
            response.delete_cookie("token", path="/")
            logger.info("Cookie 'token' has been deleted.")
            return response
    else:
        with open("templates/login.html") as f:
            return HTMLResponse(content=f.read())

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Incoming request: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"Response status: {response.status_code}")
    return response

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    token = request.cookies.get("token")
    if not token:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    try:
        with sqlite3.connect(db.db_name) as conn:
            c = conn.cursor()
            user = c.execute('SELECT * FROM users WHERE id = ?', (token,)).fetchone()
            if not user:
                response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
                response.delete_cookie("token", path="/")
                logger.info("Cookie 'token' has been deleted.")
                return response
            
            # Baca template dan inject data user
            with open("templates/profile.html") as f:
                template = f.read()
                
                # Replace placeholder dengan data user
                template = template.replace('{{ username }}', user[1] or '')
                template = template.replace('{{ full_name }}', user[2] or '')
                template = template.replace('{{ profile_pic }}', user[3] or '/static/img/default-avatar.png')
                
                return HTMLResponse(content=template)
                
    except Exception as e:
        logger.error(f"Error loading profile: {str(e)}")
        response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        response.delete_cookie("token", path="/")
        logger.info("Cookie 'token' has been deleted.")
        return response

@app.get("/api/history")
async def get_history(
    page: int = Query(1, ge=1),  # minimal halaman 1
    per_page: int = Query(100, le=100)  # maksimal 100 item per page
):
    try:
        with sqlite3.connect(scanner.db.db_name) as conn:
            c = conn.cursor()
            
            # Hitung total records
            total_count = c.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
            
            # Hitung offset untuk pagination
            offset = (page - 1) * per_page
            
            # Query dengan pagination
            c.execute('''
                SELECT ip, port, banner, timestamp 
                FROM devices 
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            ''', (per_page, offset))
            
            rows = c.fetchall()
            history = []
            
            for row in rows:
                history.append({
                    "ip": row[0],
                    "port": row[1],
                    "banner": row[2],
                    "timestamp": row[3]
                })
            
            # Hitung total pages
            total_pages = (total_count + per_page - 1) // per_page
                
            return {
                "items": history,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total_items": total_count,
                    "total_pages": total_pages
                }
            }
            
    except Exception as e:
        logger.error(f"Error getting history: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/search")
async def search_devices(
    query: str = Query(None),
    port: int = Query(None),
    banner: str = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(100, le=100)
):
    try:
        with sqlite3.connect(db.db_name) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Buat query dasar untuk total count
            count_parts = ["SELECT COUNT(*) FROM devices WHERE 1=1"]
            query_parts = ["SELECT * FROM devices WHERE 1=1"]
            params = []
            
            # Tambah filter berdasarkan parameter
            if query:
                # Mencari di IP dan banner
                condition = "AND (ip LIKE ? OR banner LIKE ?)"
                count_parts.append(condition)
                query_parts.append(condition)
                params.extend([f"%{query}%", f"%{query}%"])
            
            if port:
                condition = "AND port = ?"
                count_parts.append(condition)
                query_parts.append(condition)
                params.append(port)
                
            if banner:
                condition = "AND banner LIKE ?"
                count_parts.append(condition)
                query_parts.append(condition)
                params.append(f"%{banner}%")
            
            # Hitung total records
            total_count = c.execute(" ".join(count_parts), params).fetchone()[0]
            
            # Tambah pagination
            offset = (page - 1) * per_page
            query_parts.append("ORDER BY timestamp DESC LIMIT ? OFFSET ?")
            params.extend([per_page, offset])
            
            # Execute query
            results = c.execute(" ".join(query_parts), params).fetchall()
            
            # Hitung total pages
            total_pages = (total_count + per_page - 1) // per_page
            
            return {
                "items": [dict(row) for row in results],
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total_items": total_count,
                    "total_pages": total_pages
                }
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/device")
async def scan_single_device(request: DeviceScanRequest):
    try:
        result = scanner.scan_single_device(request.ip, request.port)
        return {
            "success": True,
            "message": "Device scan completed",
            "result": result
        }
    except Exception as e:
        logger.error(f"Error scanning device {request.ip}:{request.port} - {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    db.init_db()
    db.create_default_user()
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)