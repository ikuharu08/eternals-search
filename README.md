# Eternals Search

Eternals Search adalah aplikasi web untuk melakukan network scanning dan monitoring device yang terhubung ke jaringan. Aplikasi ini dibuat menggunakan FastAPI untuk backend dan Bootstrap untuk frontend.

## 🚀 Fitur Utama

- Network scanning dengan multiple threads
- Port scanning menggunakan Naabu
- Banner grabbing untuk service detection  
- Filter pencarian berdasarkan IP, port dan banner
- Export hasil scan ke CSV
- Dark/Light mode theme
- User authentication dan management
- Profile customization
- Realtime scan progress monitoring
- Scan history dan device tracking

## 📋 Prasyarat

- Python 3.8+
- Naabu (untuk port scanning)
- HTTPX (untuk banner grabbing)
- SQLite3

## 🛠️ Instalasi

1. Clone repository
```bash
git clone https://github.com/yourusername/eternals-search.git
cd eternals-search
```

2. Install dependencies
```bash 
pip install -r requirements.txt
```

3. Install Naabu dan HTTPX
```bash
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

4. Setup database
```bash
python -c "from database import Database; db = Database(); db.init_db()"
```

5. Jalankan aplikasi
```bash
uvicorn app:app --reload
```

## 🔧 Konfigurasi

Beberapa konfigurasi yang bisa disesuaikan:

- `UPLOAD_DIR`: Directory untuk menyimpan file upload (default: "uploads")
- `LOG_DIR`: Directory untuk log files (default: "logs") 
- `PER_PAGE`: Jumlah item per halaman untuk pagination (default: 100)

## 📝 Penggunaan

1. Login ke aplikasi menggunakan username dan password
2. Pilih mode scanning:
   - Scan by Country: Scan range IP berdasarkan negara
   - Custom IP Range: Scan range IP custom
3. Konfigurasi scan:
   - Exclude IP ranges (opsional)
   - Port range
   - Scan speed
4. Monitor progress scanning secara realtime
5. Lihat hasil scan di tab "Live Results"
6. Filter dan export hasil sesuai kebutuhan

## 🔒 Keamanan

- Password di-hash menggunakan algoritma bcrypt
- Token based authentication
- Input validation dan sanitization
- Rate limiting untuk API endpoints
- Secure file upload handling

## 📊 Database Schema

### Devices Table
- ip (TEXT)
- port (INTEGER) 
- banner (JSON)
- timestamp (DATETIME)
- Primary Key: (ip, port)

### Users Table
- id (INTEGER PRIMARY KEY)
- username (TEXT UNIQUE)
- full_name (TEXT)
- profile_pic (TEXT)
- password_hash (TEXT)
- created_at (DATETIME)

## 👥 Kontribusi

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 Lisensi

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/)
- [Bootstrap](https://getbootstrap.com/)
- [Naabu](https://github.com/projectdiscovery/naabu)
- [HTTPX](https://github.com/projectdiscovery/httpx)
