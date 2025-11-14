from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib
import base64
from cryptography.fernet import Fernet
import os

db = SQLAlchemy()

# Generate encryption key
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'ppdb-317-encryption-key-32-chars-long')
cipher_suite = Fernet(base64.urlsafe_b64encode(hashlib.sha256(ENCRYPTION_KEY.encode()).digest()))

def encrypt_data(data):
    """Encrypt data menggunakan symmetric encryption"""
    if data is None or data == '':
        return data
    try:
        return cipher_suite.encrypt(data.encode()).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return data

def decrypt_data(encrypted_data):
    """Decrypt data menggunakan symmetric encryption"""
    if encrypted_data is None or encrypted_data == '':
        return encrypted_data
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return encrypted_data

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    nama = db.Column(db.Text, nullable=False)
    tanggal_daftar = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='belum_lengkap')

    # Additional fields for students - semua akan dienkripsi
    tempat_lahir = db.Column(db.Text, default='')
    tanggal_lahir = db.Column(db.Date, nullable=True)
    jenis_kelamin = db.Column(db.Text, default='')
    agama = db.Column(db.Text, default='')
    alamat = db.Column(db.Text, default='')
    no_hp = db.Column(db.Text, default='')
    asal_sekolah = db.Column(db.Text, default='')
    nama_ayah = db.Column(db.Text, default='')
    pekerjaan_ayah = db.Column(db.Text, default='')
    nama_ibu = db.Column(db.Text, default='')
    pekerjaan_ibu = db.Column(db.Text, default='')

    def set_password(self, password):
        """Hash password dengan SHA256"""
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        """Verifikasi password dengan SHA256"""
        try:
            return self.password_hash == hashlib.sha256(password.encode()).hexdigest()
        except Exception as e:
            print(f"Error checking password: {e}")
            return False

    # Property untuk mengakses data terdekripsi
    @property
    def nama_decrypted(self):
        return decrypt_data(self.nama)
    
    @property
    def tempat_lahir_decrypted(self):
        return decrypt_data(self.tempat_lahir)
    
    @property
    def jenis_kelamin_decrypted(self):
        return decrypt_data(self.jenis_kelamin)
    
    @property
    def agama_decrypted(self):
        return decrypt_data(self.agama)
    
    @property
    def alamat_decrypted(self):
        return decrypt_data(self.alamat)
    
    @property
    def no_hp_decrypted(self):
        return decrypt_data(self.no_hp)
    
    @property
    def asal_sekolah_decrypted(self):
        return decrypt_data(self.asal_sekolah)
    
    @property
    def nama_ayah_decrypted(self):
        return decrypt_data(self.nama_ayah)
    
    @property
    def pekerjaan_ayah_decrypted(self):
        return decrypt_data(self.pekerjaan_ayah)
    
    @property
    def nama_ibu_decrypted(self):
        return decrypt_data(self.nama_ibu)
    
    @property
    def pekerjaan_ibu_decrypted(self):
        return decrypt_data(self.pekerjaan_ibu)

    def set_encrypted_data(self, **kwargs):
        """Set data dengan enkripsi otomatis"""
        for key, value in kwargs.items():
            if hasattr(self, key) and value is not None:
                encrypted_value = encrypt_data(str(value))
                setattr(self, key, encrypted_value)

class BuktiPendaftaran(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    tanggal_upload = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='menunggu')

class DokumenTambahan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    jenis_dokumen = db.Column(db.String(50), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    tanggal_upload = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='menunggu')

class Pengumuman(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    judul = db.Column(db.String(200), nullable=False)
    isi = db.Column(db.Text, nullable=False)
    tanggal = db.Column(db.DateTime, default=datetime.utcnow)

class DaftarKelulusanSementara(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tanggal_diluluskan = db.Column(db.DateTime, default=datetime.utcnow)
    status_pengumuman = db.Column(db.String(20), default='belum_diumumkan')
    
    user = db.relationship('User', backref=db.backref('daftar_kelulusan', lazy=True))
