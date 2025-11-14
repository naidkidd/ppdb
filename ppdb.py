BACKGROUND_IMAGE_URL = "/static/images/latar_belakang.jpg"

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from models import db, User, BuktiPendaftaran, DokumenTambahan, Pengumuman, DaftarKelulusanSementara, encrypt_data, decrypt_data
import os
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import re
import time
import html
import hashlib

app = Flask(__name__)

@app.context_processor
def inject_background_image():
    return dict(background_image_url=BACKGROUND_IMAGE_URL)

app.config['SECRET_KEY'] = 'rahasia_sekali_ppdb_317'

# === KONFIGURASI DATABASE ===
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://ppdb_admin:Ppdb317#Admin@192.168.182.18:3306/ppdb_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True
}

app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

# Konfigurasi keamanan
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax'
)

db.init_app(app)

# Setup logging
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Security logging
security_handler = RotatingFileHandler('security.log', maxBytes=10000, backupCount=3)
security_handler.setLevel(logging.WARNING)
security_logger = logging.getLogger('security')
security_logger.addHandler(security_handler)

ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

# ===== SECURITY CLASSES & FUNCTIONS =====
class RateLimiter:
    def __init__(self):
        self.attempts = {}
        self.lockout_time = 900
        self.max_attempts = 5
        self.window_time = 3600

    def is_rate_limited(self, ip_address):
        current_time = time.time()
        if ip_address not in self.attempts:
            self.attempts[ip_address] = []
        
        self.attempts[ip_address] = [
            attempt_time for attempt_time in self.attempts[ip_address]
            if current_time - attempt_time < self.window_time
        ]

        return len(self.attempts[ip_address]) >= self.max_attempts

    def add_attempt(self, ip_address):
        current_time = time.time()
        if ip_address not in self.attempts:
            self.attempts[ip_address] = []
        self.attempts[ip_address].append(current_time)

    def reset_attempts(self, ip_address):
        if ip_address in self.attempts:
            del self.attempts[ip_address]

rate_limiter = RateLimiter()

def validate_input(input_string, max_length=100):
    if input_string is None:
        return False
    if len(input_string.strip()) == 0:
        return False
    if len(input_string) > max_length:
        return False
    if not re.match(r'^[a-zA-Z0-9_@.\-\s\p{L}]*$', input_string):
        return False
    return True

def sanitize_input(input_string):
    if input_string:
        return html.escape(input_string.strip())
    return ""

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_security_event(event_type, ip_address, username, details=""):
    security_logger.warning(f"{event_type} - IP: {ip_address}, User: {username}, Details: {details}")

# ===== MIDDLEWARE & DECORATORS =====
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Akses ditolak. Hanya admin yang dapat mengakses halaman ini.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Silakan login terlebih dahulu.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def siswa_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'siswa':
            flash('Akses ditolak. Hanya siswa yang dapat mengakses halaman ini.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ===== PUBLIC ROUTES =====
@app.route('/')
def home():
    pengumuman_terbaru = Pengumuman.query.order_by(Pengumuman.tanggal.desc()).first()
    siswa_lulus = User.query.filter_by(role='siswa', status='lulus').count()
    total_siswa = User.query.filter_by(role='siswa').count()
    return render_template('home.html',
                         pengumuman=pengumuman_terbaru,
                         siswa_lulus=siswa_lulus,
                         total_siswa=total_siswa)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form['username'])
        password = request.form['password']
        role = request.form['role']
        nama = sanitize_input(request.form['nama'])
        ip_address = request.remote_addr

        if not username or not nama:
            flash('Username dan nama harus diisi!', 'error')
            return redirect(url_for('register'))

        if len(username) > 50 or len(nama) > 100:
            flash('Username atau nama terlalu panjang!', 'error')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password harus minimal 6 karakter!', 'error')
            return redirect(url_for('register'))

        if role != 'siswa':
            flash('Registrasi admin tidak tersedia melalui halaman publik.', 'error')
            return redirect(url_for('home'))

        if User.query.filter_by(username=username).first():
            flash('Username sudah terdaftar!', 'error')
            return redirect(url_for('register'))

        status_awal = 'belum_lengkap'
        new_user = User(username=username, role=role, status=status_awal)
        new_user.set_password(password)
        new_user.set_encrypted_data(nama=nama)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registrasi berhasil! Silakan login.', 'success')
            log_security_event("REGISTRATION_SUCCESS", ip_address, username, "New user registered")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Registration error: {e}')
            log_security_event("REGISTRATION_ERROR", ip_address, username, f"{e.__class__.__name__}: {str(e)}")
            flash('Terjadi kesalahan saat registrasi. Silakan coba lagi.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        ip_address = request.remote_addr

        if rate_limiter.is_rate_limited(ip_address):
            remaining_time = rate_limiter.get_remaining_time(ip_address)
            flash(f'Terlalu banyak percobaan login. Silakan coba lagi dalam {int(remaining_time/60)} menit.', 'error')
            log_security_event("RATE_LIMITED", ip_address, username, f"Too many login attempts")
            return redirect(url_for('login'))

        if not username or not password:
            flash('Username dan password harus diisi!', 'error')
            rate_limiter.add_attempt(ip_address)
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        # DEBUG LOGIN
        app.logger.info(f"Login attempt - User: {username}, Role: {role}")
        if user:
            app.logger.info(f"DB hash: {user.password_hash}")
            app.logger.info(f"Input hash: {hashlib.sha256(password.encode()).hexdigest()}")
            app.logger.info(f"Password match: {user.check_password(password)}")

        if user and user.check_password(password) and user.role == role:
            rate_limiter.reset_attempts(ip_address)
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['nama'] = user.nama_decrypted

            log_security_event("LOGIN_SUCCESS", ip_address, username, f"Role: {role}")
            app.logger.info(f'Login successful - User: {username}')

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard_siswa'))
        else:
            rate_limiter.add_attempt(ip_address)
            log_security_event("LOGIN_FAILED", ip_address, username, f"Role attempted: {role}")
            flash('Username, password, atau role salah!', 'error')

    role = request.args.get('role', 'siswa')
    return render_template('login.html', role=role)

@app.route('/ppdb-admin317/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr

        if rate_limiter.is_rate_limited(ip_address):
            flash('Terlalu banyak percobaan login. Silakan coba lagi nanti.', 'error')
            return redirect(url_for('admin_login'))

        if not username or not password:
            flash('Username dan password harus diisi!', 'error')
            rate_limiter.add_attempt(ip_address)
            return redirect(url_for('admin_login'))

        user = User.query.filter_by(username=username, role='admin').first()

        app.logger.info(f"Admin login: {username}, Password check: {user.check_password(password) if user else 'No user'}")

        if user and user.check_password(password):
            rate_limiter.reset_attempts(ip_address)
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['nama'] = user.nama_decrypted

            log_security_event("ADMIN_LOGIN_SUCCESS", ip_address, username, "Admin login successful")
            return redirect(url_for('admin_dashboard'))
        else:
            rate_limiter.add_attempt(ip_address)
            log_security_event("ADMIN_LOGIN_FAILED", ip_address, username, "Admin login failed")
            flash('Username atau password admin salah!', 'error')

    return render_template('admin_login.html')

# ===== ROUTE SISWA =====
@app.route('/dashboard_siswa')
@login_required
@siswa_required
def dashboard_siswa():
    user = User.query.get(session['user_id'])
    bukti = BuktiPendaftaran.query.filter_by(user_id=session['user_id']).first()
    pengumuman = Pengumuman.query.order_by(Pengumuman.tanggal.desc()).first()
    return render_template('dashboard_siswa.html', user=user, bukti=bukti, pengumuman=pengumuman)

@app.route('/lengkapi_data_siswa', methods=['GET', 'POST'])
@login_required
@siswa_required
def lengkapi_data_siswa():
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        user.set_encrypted_data(
            tempat_lahir=request.form['tempat_lahir'],
            jenis_kelamin=request.form['jenis_kelamin'],
            agama=request.form['agama'],
            alamat=request.form['alamat'],
            no_hp=request.form['no_hp'],
            asal_sekolah=request.form['asal_sekolah'],
            nama_ayah=request.form['nama_ayah'],
            pekerjaan_ayah=request.form['pekerjaan_ayah'],
            nama_ibu=request.form['nama_ibu'],
            pekerjaan_ibu=request.form['pekerjaan_ibu']
        )

        try:
            user.tanggal_lahir = datetime.strptime(request.form['tanggal_lahir'], '%Y-%m-%d')
        except ValueError:
            flash('Format tanggal tidak valid!', 'error')
            return redirect(url_for('lengkapi_data_siswa'))

        if not all([request.form['tempat_lahir'], request.form['jenis_kelamin'], request.form['agama'], 
                   request.form['alamat'], request.form['no_hp'], request.form['asal_sekolah']]):
            flash('Semua field wajib diisi!', 'error')
            return redirect(url_for('lengkapi_data_siswa'))

        if user.status == 'belum_lengkap':
            user.status = 'menunggu'

        try:
            db.session.commit()
            flash('Data berhasil disimpan!', 'success')
            return redirect(url_for('dashboard_siswa'))
        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat menyimpan data.', 'error')
            app.logger.error(f"Data completion error: {str(e)}")

    return render_template('lengkapi_data_siswa.html', user=user)

@app.route('/upload_bukti', methods=['GET', 'POST'])
@login_required
@siswa_required
def upload_bukti():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Tidak ada file yang dipilih', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('Tidak ada file yang dipilih', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            existing_bukti = BuktiPendaftaran.query.filter_by(user_id=session['user_id']).first()
            if existing_bukti:
                existing_bukti.filename = filename
                existing_bukti.filepath = filepath
                existing_bukti.tanggal_upload = datetime.utcnow()
                existing_bukti.status = 'menunggu'
            else:
                new_bukti = BuktiPendaftaran(
                    user_id=session['user_id'],
                    filename=filename,
                    filepath=filepath,
                    status='menunggu'
                )
                db.session.add(new_bukti)

            try:
                db.session.commit()
                flash('Bukti pendaftaran berhasil diupload!', 'success')
                return redirect(url_for('dashboard_siswa'))
            except Exception as e:
                db.session.rollback()
                flash('Terjadi kesalahan saat upload file.', 'error')
                app.logger.error(f"File upload error: {str(e)}")
        else:
            flash('Format file tidak didukung!', 'error')

    return render_template('upload_bukti.html')

@app.route('/upload_dokumen', methods=['GET', 'POST'])
@login_required
@siswa_required
def upload_dokumen():
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Tidak ada file yang dipilih', 'error')
            return redirect(request.url)

        file = request.files['file']
        jenis_dokumen = request.form['jenis_dokumen']

        if file.filename == '':
            flash('Tidak ada file yang dipilih', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            existing_doc = DokumenTambahan.query.filter_by(
                user_id=session['user_id'],
                jenis_dokumen=jenis_dokumen
            ).first()

            if existing_doc:
                existing_doc.filename = filename
                existing_doc.filepath = filepath
                existing_doc.tanggal_upload = datetime.utcnow()
                existing_doc.status = 'menunggu'
            else:
                new_doc = DokumenTambahan(
                    user_id=session['user_id'],
                    jenis_dokumen=jenis_dokumen,
                    filename=filename,
                    filepath=filepath,
                    status='menunggu'
                )
                db.session.add(new_doc)

            try:
                db.session.commit()
                flash(f'Dokumen {jenis_dokumen} berhasil diupload!', 'success')
                return redirect(url_for('upload_dokumen'))
            except Exception as e:
                db.session.rollback()
                flash('Terjadi kesalahan saat upload dokumen.', 'error')
                app.logger.error(f"Dokumen upload error: {str(e)}")
        else:
            flash('Format file tidak didukung!', 'error')

    dokumen = DokumenTambahan.query.filter_by(user_id=session['user_id']).all()
    dokumen_dict = {}
    for doc in dokumen:
        dokumen_dict[doc.jenis_dokumen] = doc

    return render_template('upload_dokumen.html', user=user, dokumen=dokumen_dict)

@app.route('/pengumuman_public')
def pengumuman_public():
    pengumuman = Pengumuman.query.order_by(Pengumuman.tanggal.desc()).all()
    current_year = 2024
    next_year = 2025

    total_siswa = User.query.filter_by(role='siswa').count()
    siswa_lulus = User.query.filter_by(role='siswa', status='lulus').count()
    siswa_daftar = User.query.filter_by(role='siswa', status='menunggu').count()

    return render_template('pengumuman_public.html',
                         pengumuman=pengumuman,
                         current_year=current_year,
                         next_year=next_year,
                         total_siswa=total_siswa,
                         siswa_lulus=siswa_lulus,
                         siswa_daftar=siswa_daftar)

# ===== ADMIN ROUTES =====
@app.route('/ppdb-admin317')
@admin_required
def admin_dashboard():
    semua_siswa = User.query.filter_by(role='siswa').all()
    siswa_data = []

    for siswa in semua_siswa:
        bukti = BuktiPendaftaran.query.filter_by(user_id=siswa.id).first()
        dokumen = DokumenTambahan.query.filter_by(user_id=siswa.id).all()
        dokumen_dict = {}
        for doc in dokumen:
            dokumen_dict[doc.jenis_dokumen] = doc

        siswa_data.append({
            'user': siswa,
            'bukti': bukti,
            'dokumen': dokumen_dict
        })

    total_siswa = len(semua_siswa)
    siswa_lulus = User.query.filter_by(role='siswa', status='lulus').count()
    siswa_menunggu = User.query.filter_by(role='siswa', status='menunggu').count()
    siswa_belum_lengkap = User.query.filter_by(role='siswa', status='belum_lengkap').count()
    total_lulus = DaftarKelulusanSementara.query.count()

    return render_template('dashboard_admin.html',
                         siswa_data=siswa_data,
                         total_siswa=total_siswa,
                         siswa_lulus=siswa_lulus,
                         siswa_menunggu=siswa_menunggu,
                         siswa_belum_lengkap=siswa_belum_lengkap,
                         total_lulus=total_lulus)

@app.route('/ppdb-admin317/detail_siswa/<int:user_id>')
@admin_required
def detail_siswa(user_id):
    siswa = User.query.get(user_id)
    if not siswa or siswa.role != 'siswa':
        flash('Data siswa tidak ditemukan', 'error')
        return redirect(url_for('admin_dashboard'))

    bukti = BuktiPendaftaran.query.filter_by(user_id=user_id).first()
    dokumen = DokumenTambahan.query.filter_by(user_id=user_id).all()
    dokumen_dict = {}
    for doc in dokumen:
        dokumen_dict[doc.jenis_dokumen] = doc

    return render_template('detail_siswa.html',
                         siswa=siswa,
                         bukti=bukti,
                         dokumen=dokumen_dict)

@app.route('/ppdb-admin317/update_status/<int:user_id>', methods=['POST'])
@admin_required
def update_status(user_id):
    status = request.form['status']
    user = User.query.get(user_id)

    if user and user.role == 'siswa':
        status_sebelumnya = user.status
        user.status = status

        try:
            db.session.commit()

            if status == 'lulus' and status_sebelumnya != 'lulus':
                existing = DaftarKelulusanSementara.query.filter_by(user_id=user_id).first()
                if not existing:
                    kelulusan_baru = DaftarKelulusanSementara(
                        user_id=user_id,
                        status_pengumuman='belum_diumumkan'
                    )
                    db.session.add(kelulusan_baru)
                    db.session.commit()
                    flash(f'{user.nama_decrypted} berhasil diupdate ke LULUS dan ditambahkan ke daftar pengumuman!', 'success')
                else:
                    flash(f'{user.nama_decrypted} berhasil diupdate ke LULUS!', 'success')

            elif status_sebelumnya == 'lulus' and status != 'lulus':
                kelulusan = DaftarKelulusanSementara.query.filter_by(user_id=user_id).first()
                if kelulusan:
                    db.session.delete(kelulusan)
                    db.session.commit()
                    flash(f'{user.nama_decrypted} dihapus dari daftar pengumuman kelulusan.', 'info')
            else:
                flash(f'Status {user.nama_decrypted} berhasil diupdate!', 'success')

        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat update status.', 'error')
            app.logger.error(f"Status update error: {str(e)}")

    return redirect(url_for('detail_siswa', user_id=user_id))

@app.route('/ppdb-admin317/update_dokumen_status/<int:dokumen_id>', methods=['POST'])
@admin_required
def update_dokumen_status(dokumen_id):
    status = request.form['status']
    dokumen = DokumenTambahan.query.get(dokumen_id)

    if dokumen:
        user_id = dokumen.user_id
        dokumen.status = status
        try:
            db.session.commit()
            flash('Status dokumen berhasil diupdate!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat update status dokumen.', 'error')
            app.logger.error(f"Dokumen status update error: {str(e)}")
        return redirect(url_for('detail_siswa', user_id=user_id))

    flash('Dokumen tidak ditemukan!', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/ppdb-admin317/download_file/<int:file_id>/<string:file_type>')
@admin_required
def download_file(file_id, file_type):
    if file_type == 'bukti':
        file_data = BuktiPendaftaran.query.get(file_id)
    elif file_type == 'dokumen':
        file_data = DokumenTambahan.query.get(file_id)
    else:
        flash('Tipe file tidak valid!', 'error')
        return redirect(url_for('admin_dashboard'))

    if file_data and os.path.exists(file_data.filepath):
        return send_file(file_data.filepath, as_attachment=True)
    else:
        flash('File tidak ditemukan!', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/ppdb-admin317/buat_pengumuman', methods=['POST'])
@admin_required
def buat_pengumuman():
    judul = sanitize_input(request.form['judul'])
    isi = sanitize_input(request.form['isi'])

    if not judul or not isi:
        flash('Judul dan isi pengumuman tidak boleh kosong!', 'error')
        return redirect(url_for('admin_dashboard'))

    new_pengumuman = Pengumuman(judul=judul, isi=isi)
    db.session.add(new_pengumuman)

    try:
        db.session.commit()
        flash('Pengumuman berhasil dibuat!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Terjadi kesalahan saat membuat pengumuman.', 'error')
        app.logger.error(f"Pengumuman creation error: {str(e)}")

    return redirect(url_for('admin_dashboard'))

# ===== PENGUMUMAN KELULUSAN =====
@app.route('/ppdb-admin317/daftar_kelulusan_sementara')
@admin_required
def daftar_kelulusan_sementara():
    daftar_kelulusan = DaftarKelulusanSementara.query.all()
    total_lulus = len(daftar_kelulusan)
    total_siswa = User.query.filter_by(role='siswa').count()

    return render_template('daftar_kelulusan_sementara.html',
                         daftar_kelulusan=daftar_kelulusan,
                         total_lulus=total_lulus,
                         total_siswa=total_siswa)

@app.route('/ppdb-admin317/daftar_kelulusan')
@admin_required
def daftar_kelulusan():
    return redirect(url_for('daftar_kelulusan_sementara'))

@app.route('/ppdb-admin317/publish_pengumuman_kelulusan', methods=['POST'])
@admin_required
def publish_pengumuman_kelulusan():
    judul = sanitize_input(request.form.get('judul', 'Pengumuman Kelulusan PPDB SMA Negeri 317'))
    tambahan_teks = sanitize_input(request.form.get('tambahan_teks', ''))

    daftar_kelulusan = DaftarKelulusanSementara.query.all()

    if not daftar_kelulusan:
        flash('Tidak ada siswa dalam daftar kelulusan!', 'error')
        return redirect(url_for('daftar_kelulusan_sementara'))

    isi_pengumuman = f"{tambahan_teks}\n\n" if tambahan_teks else ""
    isi_pengumuman += "DAFTAR SISWA YANG LULUS SELEKSI PPDB SMA NEGERI 317:\n\n"

    daftar_terurut = sorted(daftar_kelulusan, key=lambda x: x.user.nama_decrypted)

    for i, kelulusan in enumerate(daftar_terurut, 1):
        isi_pengumuman += f"{i}. {kelulusan.user.nama_decrypted} - NIS: {kelulusan.user.username}\n"

    isi_pengumuman += f"\nTotal: {len(daftar_kelulusan)} siswa\n"
    isi_pengumuman += "\nSelamat kepada seluruh siswa yang lulus!"
    isi_pengumuman += "\n\nBagi siswa yang lulus, silakan melakukan daftar ulang sesuai jadwal yang akan ditentukan."

    new_pengumuman = Pengumuman(judul=judul, isi=isi_pengumuman)

    try:
        db.session.add(new_pengumuman)
        db.session.commit()
        flash(f'Pengumuman kelulusan berhasil dipublish! {len(daftar_kelulusan)} siswa diumumkan.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Terjadi kesalahan saat mempublish pengumuman.', 'error')
        app.logger.error(f"Publish pengumuman error: {str(e)}")

    return redirect(url_for('daftar_kelulusan_sementara'))

@app.route('/ppdb-admin317/hapus_dari_daftar_kelulusan/<int:kelulusan_id>')
@admin_required
def hapus_dari_daftar_kelulusan(kelulusan_id):
    kelulusan = DaftarKelulusanSementara.query.get(kelulusan_id)

    if kelulusan:
        nama_siswa = kelulusan.user.nama_decrypted
        db.session.delete(kelulusan)

        try:
            db.session.commit()
            flash(f'{nama_siswa} berhasil dihapus dari daftar pengumuman kelulusan!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat menghapus dari daftar kelulusan.', 'error')

    return redirect(url_for('daftar_kelulusan_sementara'))

# ===== COMMON ROUTES =====
@app.route('/logout')
def logout():
    user_info = f"{session.get('username', 'Unknown')} ({session.get('role', 'Unknown')})"
    ip_address = request.remote_addr
    log_security_event("LOGOUT", ip_address, user_info, "User logged out")
    session.clear()
    return redirect(url_for('home'))

@app.route('/test')
def test_route():
    return "Flask server is working! Timestamp: " + str(datetime.utcnow())

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        try:
            db.create_all()
            
            admin_username = 'ADMIN317'
            admin_user = User.query.filter_by(username=admin_username, role='admin').first()
            
            if not admin_user:
                print("Creating admin user...")
                admin_user = User(
                    username=admin_username,
                    role='admin',
                    status='aktif'
                )
                admin_user.set_password('bismillah317')
                admin_user.set_encrypted_data(nama='Administrator Utama')
                db.session.add(admin_user)
                db.session.commit()
                print("Admin user created successfully!")
            else:
                print("Admin user already exists")
                
                # Reset password untuk memastikan
                admin_user.set_password('bismillah317')
                db.session.commit()
                print("Admin password reset")

            db.session.commit()
            print("Database initialized successfully!")

        except Exception as e:
            db.session.rollback()
            print(f"Error initializing database: {e}")

    print("Starting Flask server...")
    print("Access URLs:")
    print("   http://localhost:5001")
    print("   http://192.168.182.17:5001")
    print("   http://0.0.0.0:5001")

    app.run(debug=True, host='0.0.0.0', port=5001)