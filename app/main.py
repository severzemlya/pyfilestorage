"""
PyFileStorage - Web File Storage Server
A lightweight, secure file storage solution with user management, sharing, and media playback.
"""

import base64
import hashlib
import io
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from authlib.integrations.flask_client import OAuth
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dotenv import load_dotenv
from stream_zip import ZIP_64, stream_zip
from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, send_file, session, url_for)
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Load environment variables
load_dotenv()

# Configuration
BASE_DIR = Path(__file__).parent.absolute()
SETTINGS_FILE = BASE_DIR / 'settings.json'


def load_settings():
    """Load settings from settings.json file."""
    default_settings = {
        'app_name': 'PyFileStorage',
        'site_url': 'http://localhost:5000',
        'site_description': 'A lightweight, secure web file storage server',
        'og_image': '/static/og-image.png',
        'upload_folder': 'uploads',
        'database_path': 'storage.db',
        'max_file_size': 100 * 1024 * 1024,  # 100MB default
        'default_quota': 1024 * 1024 * 1024,  # 1GB per user default
        'system_quota': 10 * 1024 * 1024 * 1024,  # 10GB system default
        'blocked_extensions': [
            '.exe', '.php', '.phtml', '.php3', '.php4', '.php5',
            '.phps', '.cgi', '.pl', '.py', '.pyc', '.pyo', '.jsp',
            '.jspx', '.asp', '.aspx', '.sh', '.bash', '.bat', '.cmd',
            '.com', '.vbs', '.vbe', '.js', '.jse', '.ws', '.wsf',
            '.msc', '.msi', '.msp', '.scr', '.hta', '.cpl', '.jar',
            '.dll', '.sys', '.drv'
        ]
    }
    try:
        if SETTINGS_FILE.exists():
            with open(SETTINGS_FILE, 'r') as f:
                settings = json.load(f)
                # Merge with defaults (keeping user settings)
                for key, value in default_settings.items():
                    if key not in settings:
                        settings[key] = value
                return settings
    except (json.JSONDecodeError, IOError) as e:
        print(f'Warning: Could not load settings.json: {e}')
    return default_settings


# Load settings from JSON file
APP_SETTINGS = load_settings()

# Path settings (derived from settings or environment variables)
# UPLOAD_FOLDER can be set via environment variable for absolute paths (e.g., different drives)
_upload_folder_env = os.environ.get('UPLOAD_FOLDER', '').strip()
if _upload_folder_env:
    # Use absolute path from environment variable
    UPLOAD_FOLDER = Path(_upload_folder_env)
else:
    # Fall back to settings.json or default (relative to app directory)
    UPLOAD_FOLDER = BASE_DIR / APP_SETTINGS.get('upload_folder', 'uploads')

DATABASE = BASE_DIR / APP_SETTINGS.get('database_path', 'storage.db')

# Site settings
APP_NAME = APP_SETTINGS.get('app_name', 'PyFileStorage')
SITE_URL = APP_SETTINGS.get('site_url', 'http://localhost:5000')
SITE_DESCRIPTION = APP_SETTINGS.get('site_description', 'A lightweight, secure web file storage server')
OG_IMAGE = APP_SETTINGS.get('og_image', '/static/og-image.png')

# Domain separation settings for XSS/session hijacking prevention
# APP_DOMAIN: Main application domain for authenticated operations
# CONTENT_DOMAIN: Separate domain for serving uploaded files
APP_DOMAIN = os.environ.get('APP_DOMAIN', '').strip() or None
CONTENT_DOMAIN = os.environ.get('CONTENT_DOMAIN', '').strip() or None

# Quota settings
MAX_FILE_SIZE = APP_SETTINGS.get('max_file_size', 100 * 1024 * 1024)
DEFAULT_QUOTA = APP_SETTINGS.get('default_quota', 1024 * 1024 * 1024)
SYSTEM_QUOTA = APP_SETTINGS.get('system_quota', 10 * 1024 * 1024 * 1024)

# Blocked file extensions for security (loaded from settings)
BLOCKED_EXTENSIONS = set(APP_SETTINGS.get('blocked_extensions', [
    '.exe', '.php', '.phtml', '.php3', '.php4', '.php5',
    '.phps', '.cgi', '.pl', '.py', '.pyc', '.pyo', '.jsp',
    '.jspx', '.asp', '.aspx', '.sh', '.bash', '.bat', '.cmd',
    '.com', '.vbs', '.vbe', '.js', '.jse', '.ws', '.wsf',
    '.msc', '.msi', '.msp', '.scr', '.hta', '.cpl', '.jar',
    '.dll', '.sys', '.drv'
]))

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))


def get_env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on'}


# Set MAX_CONTENT_LENGTH to None if max_file_size is 0 or null (unlimited)
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE if MAX_FILE_SIZE else None
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Session cookie security settings - don't set domain to ensure cookie is app-domain only
debug_mode = get_env_bool('FLASK_DEBUG', False)
app.config['SESSION_COOKIE_SECURE'] = get_env_bool('SESSION_COOKIE_SECURE', not debug_mode)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Trust proxy headers (e.g., X-Forwarded-Proto) for correct scheme detection
if get_env_bool('TRUST_X_FORWARDED_PROTO', False):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

# Initialize CSRF protection
csrf = CSRFProtect(app)

GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
FILE_ENCRYPTION_SECRET = (
    os.environ.get('FILE_ENCRYPTION_SECRET')
    or os.environ.get('SECRET_KEY')
    or app.secret_key
)

if not os.environ.get('FILE_ENCRYPTION_SECRET') and not os.environ.get('SECRET_KEY'):
    print('WARNING: FILE_ENCRYPTION_SECRET or SECRET_KEY is not set. '
          'Encrypted files may become unrecoverable after restart.')

oauth = OAuth(app)
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )

# Ensure upload folder exists
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)


# ==================== Security Middleware ====================

# Routes that are allowed on CONTENT_DOMAIN (file serving only)
CONTENT_DOMAIN_ALLOWED_ROUTES = frozenset([
    'view_file', 'download_file', 'get_thumbnail', 'static',
    'access_share_link', 'shared_folder_download'
])


@app.before_request
def check_domain_routing():
    """
    Security middleware to enforce domain separation.
    If CONTENT_DOMAIN is configured:
    - APP_DOMAIN: Full application access
    - CONTENT_DOMAIN: Only file viewing/download routes
    This prevents XSS attacks via uploaded files from stealing session cookies.
    """
    if not CONTENT_DOMAIN or not APP_DOMAIN:
        return  # Domain separation not configured

    host = request.host.split(':')[0]  # Remove port if present
    endpoint = request.endpoint

    # Allow static files on any domain
    if endpoint == 'static':
        return

    # If request is to CONTENT_DOMAIN, only allow content-serving routes
    if host == CONTENT_DOMAIN:
        if endpoint and endpoint not in CONTENT_DOMAIN_ALLOWED_ROUTES:
            abort(404)  # Reject non-content routes on content domain

    # If request is to APP_DOMAIN with CONTENT_DOMAIN configured,
    # the app works normally (all routes available)


@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    # Content-Security-Policy to prevent XSS from uploaded files
    # Allow inline styles and scripts for the app, but restrict other content
    csp_directives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
        "font-src 'self' https://cdnjs.cloudflare.com",
        "img-src 'self' data: blob:",
        "media-src 'self' blob:",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ]
    response.headers['Content-Security-Policy'] = '; '.join(csp_directives)

    # Additional security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    return response


# ==================== Database Functions ====================
def get_db():
    """Get database connection."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    """Close database connection."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database with tables."""
    db = get_db()
    db.executescript('''
        -- Users table
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT DEFAULT 'user' CHECK (role IN ('admin', 'user')),
            quota INTEGER DEFAULT 1073741824,
            used_space INTEGER DEFAULT 0,
            is_approved INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );

        -- Folders table
        CREATE TABLE IF NOT EXISTS folders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            parent_id INTEGER,
            owner_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Files table
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_name TEXT NOT NULL,
            stored_name TEXT UNIQUE NOT NULL,
            mime_type TEXT,
            size INTEGER NOT NULL,
            folder_id INTEGER,
            owner_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Invitation links table
        CREATE TABLE IF NOT EXISTS invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            created_by INTEGER NOT NULL,
            max_uses INTEGER DEFAULT 1,
            current_uses INTEGER DEFAULT 0,
            auto_approve INTEGER DEFAULT 0,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Share links (external)
        CREATE TABLE IF NOT EXISTS share_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            file_id INTEGER,
            folder_id INTEGER,
            created_by INTEGER NOT NULL,
            password_hash TEXT,
            expires_at TIMESTAMP,
            download_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
        );

        -- User-to-user sharing
        CREATE TABLE IF NOT EXISTS user_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            folder_id INTEGER,
            owner_id INTEGER NOT NULL,
            shared_with_id INTEGER NOT NULL,
            permission TEXT DEFAULT 'read' CHECK (permission IN ('read', 'write')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (shared_with_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- System settings
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        -- API tokens
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    ''')

    ensure_schema()

    # Insert default system settings
    db.execute('''INSERT OR IGNORE INTO settings (key, value) VALUES ('system_quota', ?)''',
               (str(SYSTEM_QUOTA),))
    db.execute('''INSERT OR IGNORE INTO settings (key, value) VALUES ('default_user_quota', ?)''',
               (str(DEFAULT_QUOTA),))
    db.execute('''INSERT OR IGNORE INTO settings (key, value) VALUES ('require_approval', '1')''')

    db.commit()


def ensure_schema():
    """Apply lightweight schema migrations."""
    db = get_db()

    user_columns = {row['name'] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    if 'oauth_provider' not in user_columns:
        db.execute('ALTER TABLE users ADD COLUMN oauth_provider TEXT')
    if 'oauth_subject' not in user_columns:
        db.execute('ALTER TABLE users ADD COLUMN oauth_subject TEXT')

    file_columns = {row['name'] for row in db.execute("PRAGMA table_info(files)").fetchall()}
    if 'is_encrypted' not in file_columns:
        db.execute('ALTER TABLE files ADD COLUMN is_encrypted INTEGER DEFAULT 0')
    if 'stored_size' not in file_columns:
        db.execute('ALTER TABLE files ADD COLUMN stored_size INTEGER DEFAULT 0')

    db.execute('UPDATE files SET stored_size = size WHERE stored_size IS NULL OR stored_size = 0')
    db.commit()


def create_admin_user():
    """Create default admin user if none exists."""
    db = get_db()
    admin = db.execute('SELECT * FROM users WHERE role = ?', ('admin',)).fetchone()
    if not admin:
        password = os.environ.get('ADMIN_PASSWORD', 'admin123')
        email = os.environ.get('ADMIN_EMAIL', 'admin@local.host')
        db.execute('''INSERT INTO users (email, password_hash, name, role, is_approved)
                      VALUES (?, ?, ?, ?, ?)''',
                   (email, generate_password_hash(password), 'Administrator', 'admin', 1))
        db.commit()
        print(f"Admin user created: {email}")


# ==================== Authentication Helpers ====================
def login_required(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


def api_auth_required(f):
    """Decorator to require API token authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('X-API-Token')
        if not token:
            return jsonify({'error': 'API token required'}), 401

        # Hash the provided token and look up by hash
        token_hash = hash_api_token(token)
        db = get_db()
        api_token = db.execute(
            'SELECT at.*, u.* FROM api_tokens at JOIN users u ON at.user_id = u.id WHERE at.token = ?',
            (token_hash,)
        ).fetchone()

        if not api_token:
            return jsonify({'error': 'Invalid API token'}), 401

        # Update last used
        db.execute('UPDATE api_tokens SET last_used = ? WHERE token = ?',
                   (datetime.now(), token_hash))
        db.commit()

        g.api_user = dict(api_token)
        return f(*args, **kwargs)
    return decorated_function


def hash_api_token(token):
    """Hash an API token for secure storage."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def get_current_user():
    """Get current logged in user."""
    if 'user_id' not in session:
        return None
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()


# ==================== File Helpers ====================
def is_safe_filename(filename):
    """Check if filename has a safe extension."""
    ext = Path(filename).suffix.lower()
    return ext not in BLOCKED_EXTENSIONS


def generate_stored_name(original_name):
    """Generate a random stored filename while preserving extension."""
    ext = Path(original_name).suffix.lower()
    return f"{uuid.uuid4().hex}{ext}"


def get_file_type(mime_type):
    """Categorize file by mime type."""
    if not mime_type:
        return 'other'
    if mime_type.startswith('image/'):
        return 'image'
    if mime_type.startswith('video/'):
        return 'video'
    if mime_type.startswith('audio/'):
        return 'audio'
    if mime_type in ['application/pdf']:
        return 'pdf'
    if mime_type.startswith('text/') or mime_type in ['application/json', 'application/xml']:
        return 'text'
    return 'other'


def format_size(size):
    """Format file size for display."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def get_system_used_space():
    """Calculate total used space in the system."""
    db = get_db()
    result = db.execute('SELECT COALESCE(SUM(used_space), 0) as total FROM users').fetchone()
    return result['total']


def check_quota(user_id, file_size):
    """Check if user has enough quota for file."""
    db = get_db()
    user = db.execute('SELECT quota, used_space FROM users WHERE id = ?', (user_id,)).fetchone()

    if user['used_space'] + file_size > user['quota']:
        return False, "User quota exceeded"

    # Check system quota
    system_quota = int(db.execute("SELECT value FROM settings WHERE key = 'system_quota'").fetchone()['value'])
    system_used = get_system_used_space()

    if system_used + file_size > system_quota:
        return False, "System storage quota exceeded"

    return True, None


def update_user_space(user_id, size_change):
    """Update user's used space."""
    db = get_db()
    db.execute('UPDATE users SET used_space = used_space + ? WHERE id = ?', (size_change, user_id))
    db.commit()


def get_user_identity(user_id):
    """Fetch minimal user identity for encryption."""
    db = get_db()
    return db.execute('SELECT id, email FROM users WHERE id = ?', (user_id,)).fetchone()


def derive_user_encryption_key(user_id, email):
    """Derive a per-user AES-256 key for streaming encryption."""
    if not email:
        raise ValueError('Email is required for encryption')

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requires 32 bytes
        salt=b'pyfilestorage_v2',  # New salt for v2 encryption
        info=f'user:{user_id}:{email}'.encode('utf-8')
    )
    return hkdf.derive(FILE_ENCRYPTION_SECRET.encode('utf-8'))


# Encryption chunk size for streaming (64KB)
ENCRYPTION_CHUNK_SIZE = 64 * 1024


def encrypt_file_streaming(input_file, output_path, user_id, email):
    """
    Encrypt file using AES-GCM with streaming support.
    Format: [12-byte nonce][encrypted chunks...][16-byte auth tag]
    Each chunk is encrypted independently with a derived nonce.
    Chunk format: [4-byte chunk size][chunk ciphertext]
    """
    key = derive_user_encryption_key(user_id, email)
    base_nonce = secrets.token_bytes(12)

    total_stored_size = 12  # base nonce

    with open(output_path, 'wb') as out:
        out.write(base_nonce)

        chunk_index = 0
        while True:
            chunk = input_file.read(ENCRYPTION_CHUNK_SIZE)
            if not chunk:
                break

            # Derive chunk-specific nonce from base nonce and chunk index
            chunk_nonce = derive_chunk_nonce(base_nonce, chunk_index)
            cipher = Cipher(algorithms.AES(key), modes.GCM(chunk_nonce))
            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(chunk) + encryptor.finalize()
            # Append auth tag to ciphertext
            encrypted_chunk = ciphertext + encryptor.tag

            # Write chunk size (4 bytes, big endian) + encrypted data
            chunk_size = len(encrypted_chunk)
            out.write(chunk_size.to_bytes(4, 'big'))
            out.write(encrypted_chunk)

            total_stored_size += 4 + chunk_size
            chunk_index += 1

    return total_stored_size


def derive_chunk_nonce(base_nonce, chunk_index):
    """Derive a unique nonce for each chunk using XOR with chunk index."""
    # Convert chunk_index to 12 bytes (padded)
    index_bytes = chunk_index.to_bytes(12, 'big')
    # XOR base_nonce with index_bytes
    return bytes(a ^ b for a, b in zip(base_nonce, index_bytes))


def decrypt_file_streaming(file_path, user_id, email, chunk_size=ENCRYPTION_CHUNK_SIZE):
    """
    Generator that decrypts and yields file data in chunks.
    Uses streaming decryption to avoid loading entire file into memory.
    """
    key = derive_user_encryption_key(user_id, email)

    with open(file_path, 'rb') as f:
        base_nonce = f.read(12)
        if len(base_nonce) != 12:
            raise ValueError('Invalid encrypted file format: missing nonce')

        chunk_index = 0
        while True:
            # Read chunk size
            size_bytes = f.read(4)
            if not size_bytes:
                break
            if len(size_bytes) != 4:
                raise ValueError('Invalid encrypted file format: truncated chunk size')

            encrypted_chunk_size = int.from_bytes(size_bytes, 'big')

            # Read encrypted chunk (ciphertext + tag)
            encrypted_chunk = f.read(encrypted_chunk_size)
            if len(encrypted_chunk) != encrypted_chunk_size:
                raise ValueError('Invalid encrypted file format: truncated chunk data')

            # Last 16 bytes are the auth tag
            ciphertext = encrypted_chunk[:-16]
            tag = encrypted_chunk[-16:]

            # Derive chunk-specific nonce
            chunk_nonce = derive_chunk_nonce(base_nonce, chunk_index)

            cipher = Cipher(algorithms.AES(key), modes.GCM(chunk_nonce, tag))
            decryptor = cipher.decryptor()

            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            yield plaintext

            chunk_index += 1


def decrypt_file_to_bytes(file_path, user_id, email):
    """Decrypt entire file and return as bytes (for small files or when full content needed)."""
    return b''.join(decrypt_file_streaming(file_path, user_id, email))


def get_effective_stored_size(file_row):
    """Get stored size for quota accounting."""
    stored_size = file_row['stored_size'] if 'stored_size' in file_row.keys() else None
    if stored_size:
        return stored_size
    return file_row['size']


def load_file_bytes(file_row):
    """Load and decrypt file bytes if needed."""
    file_path = UPLOAD_FOLDER / file_row['stored_name']
    if 'is_encrypted' in file_row.keys() and file_row['is_encrypted']:
        owner = get_user_identity(file_row['owner_id'])
        if not owner:
            raise ValueError('Owner not found for encrypted file')
        return decrypt_file_to_bytes(file_path, owner['id'], owner['email'])
    return file_path.read_bytes()


def stream_file_data(file_row):
    """Generator that yields decrypted file data chunks for streaming responses."""
    file_path = UPLOAD_FOLDER / file_row['stored_name']
    is_encrypted = 'is_encrypted' in file_row.keys() and file_row['is_encrypted']

    if is_encrypted:
        owner = get_user_identity(file_row['owner_id'])
        if not owner:
            raise ValueError('Owner not found for encrypted file')
        yield from decrypt_file_streaming(file_path, owner['id'], owner['email'])
    else:
        # Stream unencrypted file in chunks
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(ENCRYPTION_CHUNK_SIZE)
                if not chunk:
                    break
                yield chunk


def stream_file_response(file_row, as_attachment=False, download_name=None):
    """
    Create a streaming file response.
    Uses generator-based streaming for both encrypted and unencrypted files.
    """
    mime_type = file_row['mime_type'] if file_row['mime_type'] else 'application/octet-stream'
    original_name = download_name or file_row['original_name'] or 'file'
    original_size = file_row['size']

    def generate():
        yield from stream_file_data(file_row)

    response = Response(generate(), mimetype=mime_type)

    if as_attachment:
        # Use RFC 5987 encoding for non-ASCII filenames
        try:
            original_name.encode('ascii')
            response.headers['Content-Disposition'] = f'attachment; filename="{original_name}"'
        except UnicodeEncodeError:
            encoded_name = original_name.encode('utf-8').decode('unicode_escape', errors='ignore')
            response.headers['Content-Disposition'] = (
                f"attachment; filename*=UTF-8''{original_name}"
            )

    # Set Content-Length from original (unencrypted) size
    response.headers['Content-Length'] = original_size

    return response


# ==================== Routes: Authentication ====================
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    google_login_enabled = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            if not user['is_approved']:
                flash('Your account is pending approval.', 'warning')
                return redirect(url_for('login'))

            session['user_id'] = user['id']
            session['email'] = user['email']
            session['name'] = user['name']
            session['role'] = user['role']

            db.execute('UPDATE users SET last_login = ? WHERE id = ?',
                       (datetime.now(), user['id']))
            db.commit()

            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html', google_login_enabled=google_login_enabled)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    invite_token = request.args.get('invite')
    auto_approve = False

    if invite_token:
        db = get_db()
        invitation = db.execute('''
            SELECT * FROM invitations WHERE token = ?
            AND (expires_at IS NULL OR expires_at > ?)
            AND (max_uses = 0 OR current_uses < max_uses)
        ''', (invite_token, datetime.now())).fetchone()

        if invitation:
            auto_approve = bool(invitation['auto_approve'])
        else:
            flash('Invalid or expired invitation link.', 'error')
            return redirect(url_for('login'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        name = request.form.get('name', '').strip()

        if not email or not password or not name:
            flash('All fields are required.', 'error')
            return render_template('register.html', invite_token=invite_token)

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('register.html', invite_token=invite_token)

        db = get_db()

        # Check if email exists
        existing = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        if existing:
            flash('Email already registered.', 'error')
            return render_template('register.html', invite_token=invite_token)

        # Get default quota
        default_quota = int(db.execute(
            "SELECT value FROM settings WHERE key = 'default_user_quota'"
        ).fetchone()['value'])

        # Check if registration requires approval
        require_approval = db.execute(
            "SELECT value FROM settings WHERE key = 'require_approval'"
        ).fetchone()['value'] == '1'

        is_approved = auto_approve or not require_approval

        # Create user
        db.execute('''INSERT INTO users (email, password_hash, name, quota, is_approved)
                      VALUES (?, ?, ?, ?, ?)''',
                   (email, generate_password_hash(password), name, default_quota, int(is_approved)))

        # Update invitation usage
        if invite_token:
            db.execute('UPDATE invitations SET current_uses = current_uses + 1 WHERE token = ?',
                       (invite_token,))

        db.commit()

        if is_approved:
            flash('Registration successful! You can now log in.', 'success')
        else:
            flash('Registration successful! Please wait for admin approval.', 'info')

        return redirect(url_for('login'))

    return render_template('register.html', invite_token=invite_token)


@app.route('/logout')
def logout():
    """User logout."""
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


@app.route('/login/google')
def login_google():
    """Start Google OAuth login."""
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        flash('Google login is not configured.', 'error')
        return redirect(url_for('login'))

    redirect_uri = url_for('login_google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/login/google/callback')
def login_google_callback():
    """Handle Google OAuth callback."""
    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET):
        flash('Google login is not configured.', 'error')
        return redirect(url_for('login'))

    token = oauth.google.authorize_access_token()
    userinfo = oauth.google.userinfo()

    email = (userinfo or {}).get('email', '').strip().lower()
    email_verified = bool((userinfo or {}).get('email_verified'))
    name = (userinfo or {}).get('name') or (userinfo or {}).get('given_name') or 'Google User'
    subject = (userinfo or {}).get('sub')

    if not email or not email_verified:
        flash('Google account email is not verified.', 'error')
        return redirect(url_for('login'))

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

    if user and user['oauth_provider'] == 'google' and user['oauth_subject'] and user['oauth_subject'] != subject:
        flash('Google account does not match this user.', 'error')
        return redirect(url_for('login'))

    if not user:
        default_quota = int(db.execute(
            "SELECT value FROM settings WHERE key = 'default_user_quota'"
        ).fetchone()['value'])

        require_approval = db.execute(
            "SELECT value FROM settings WHERE key = 'require_approval'"
        ).fetchone()['value'] == '1'

        is_approved = not require_approval

        db.execute('''INSERT INTO users (email, password_hash, name, quota, is_approved, oauth_provider, oauth_subject)
                      VALUES (?, ?, ?, ?, ?, ?, ?)''',
                   (email, generate_password_hash(secrets.token_urlsafe(32)), name,
                    default_quota, int(is_approved), 'google', subject))
        db.commit()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

    if not user['is_approved']:
        flash('Your account is pending approval.', 'warning')
        return redirect(url_for('login'))

    if user['oauth_provider'] != 'google' or user['oauth_subject'] != subject:
        db.execute('UPDATE users SET oauth_provider = ?, oauth_subject = ? WHERE id = ?',
                   ('google', subject, user['id']))

    session['user_id'] = user['id']
    session['email'] = user['email']
    session['name'] = user['name']
    session['role'] = user['role']

    db.execute('UPDATE users SET last_login = ? WHERE id = ?',
               (datetime.now(), user['id']))
    db.commit()

    flash('Logged in with Google.', 'success')
    return redirect(url_for('index'))


# ==================== Routes: Main Dashboard ====================
@app.route('/')
@login_required
def index():
    """Main dashboard showing files and folders."""
    folder_id = request.args.get('folder', type=int)
    search = request.args.get('search', '').strip()

    db = get_db()
    user_id = session['user_id']

    # Get current folder info
    current_folder = None
    breadcrumbs = []
    if folder_id:
        current_folder = db.execute(
            'SELECT * FROM folders WHERE id = ? AND owner_id = ?',
            (folder_id, user_id)
        ).fetchone()
        if not current_folder:
            flash('Folder not found.', 'error')
            return redirect(url_for('index'))

        # Build breadcrumbs
        folder = current_folder
        while folder:
            breadcrumbs.insert(0, dict(folder))
            if folder['parent_id']:
                folder = db.execute('SELECT * FROM folders WHERE id = ?',
                                    (folder['parent_id'],)).fetchone()
            else:
                folder = None

    if search:
        # Search mode
        folders = db.execute('''
            SELECT * FROM folders WHERE owner_id = ? AND name LIKE ?
            ORDER BY name
        ''', (user_id, f'%{search}%')).fetchall()

        files = db.execute('''
            SELECT * FROM files WHERE owner_id = ? AND original_name LIKE ?
            ORDER BY original_name
        ''', (user_id, f'%{search}%')).fetchall()
    else:
        # Normal mode - list contents of current folder
        folders = db.execute('''
            SELECT * FROM folders WHERE owner_id = ? AND parent_id IS ?
            ORDER BY name
        ''', (user_id, folder_id)).fetchall()

        files = db.execute('''
            SELECT * FROM files WHERE owner_id = ? AND folder_id IS ?
            ORDER BY original_name
        ''', (user_id, folder_id)).fetchall()

    # Get shared items
    shared_files = db.execute('''
        SELECT f.*, us.permission, u.name as owner_name
        FROM user_shares us
        JOIN files f ON us.file_id = f.id
        JOIN users u ON f.owner_id = u.id
        WHERE us.shared_with_id = ?
    ''', (user_id,)).fetchall()

    shared_folders = db.execute('''
        SELECT fo.*, us.permission, u.name as owner_name
        FROM user_shares us
        JOIN folders fo ON us.folder_id = fo.id
        JOIN users u ON fo.owner_id = u.id
        WHERE us.shared_with_id = ?
    ''', (user_id,)).fetchall()

    # Get user info
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    return render_template('index.html',
                           folders=folders,
                           files=files,
                           shared_files=shared_files,
                           shared_folders=shared_folders,
                           current_folder=current_folder,
                           breadcrumbs=breadcrumbs,
                           search=search,
                           user=user,
                           format_size=format_size,
                           get_file_type=get_file_type)


# ==================== Routes: Folder Management ====================
@app.route('/folder/create', methods=['POST'])
@login_required
def create_folder():
    """Create a new folder."""
    name = request.form.get('name', '').strip()
    parent_id = request.form.get('parent_id', type=int)

    if not name:
        flash('Folder name is required.', 'error')
        return redirect(url_for('index', folder=parent_id))

    # Sanitize folder name
    name = re.sub(r'[<>:"/\\|?*]', '', name)[:255]

    db = get_db()
    user_id = session['user_id']

    # Check for duplicate name in same location
    existing = db.execute('''
        SELECT id FROM folders WHERE name = ? AND owner_id = ? AND parent_id IS ?
    ''', (name, user_id, parent_id)).fetchone()

    if existing:
        flash('A folder with this name already exists.', 'error')
        return redirect(url_for('index', folder=parent_id))

    db.execute('INSERT INTO folders (name, parent_id, owner_id) VALUES (?, ?, ?)',
               (name, parent_id, user_id))
    db.commit()

    flash('Folder created successfully.', 'success')
    return redirect(url_for('index', folder=parent_id))


@app.route('/folder/<int:folder_id>/rename', methods=['POST'])
@login_required
def rename_folder(folder_id):
    """Rename a folder."""
    db = get_db()
    folder = db.execute(
        'SELECT * FROM folders WHERE id = ? AND owner_id = ?',
        (folder_id, session['user_id'])
    ).fetchone()

    if not folder:
        flash('Folder not found.', 'error')
        return redirect(url_for('index'))

    name = request.form.get('name', '').strip()
    if not name:
        flash('Folder name is required.', 'error')
        return redirect(url_for('index', folder=folder['parent_id']))

    name = re.sub(r'[<>:"/\\|?*]', '', name)[:255]

    db.execute('UPDATE folders SET name = ? WHERE id = ?', (name, folder_id))
    db.commit()

    flash('Folder renamed successfully.', 'success')
    return redirect(url_for('index', folder=folder['parent_id']))


@app.route('/folder/<int:folder_id>/delete', methods=['POST'])
@login_required
def delete_folder(folder_id):
    """Delete a folder and its contents."""
    db = get_db()
    folder = db.execute(
        'SELECT * FROM folders WHERE id = ? AND owner_id = ?',
        (folder_id, session['user_id'])
    ).fetchone()

    if not folder:
        flash('Folder not found.', 'error')
        return redirect(url_for('index'))

    # Get all files in folder and subfolders to delete from storage
    def delete_folder_contents(fid):
        files = db.execute('SELECT * FROM files WHERE folder_id = ?', (fid,)).fetchall()
        total_size = 0
        for file in files:
            file_path = UPLOAD_FOLDER / file['stored_name']
            if file_path.exists():
                file_path.unlink()
            total_size += get_effective_stored_size(file)

        # Recursively delete subfolders
        subfolders = db.execute('SELECT id FROM folders WHERE parent_id = ?', (fid,)).fetchall()
        for subfolder in subfolders:
            total_size += delete_folder_contents(subfolder['id'])

        return total_size

    total_size = delete_folder_contents(folder_id)

    # Delete folder (cascades to files and subfolders)
    db.execute('DELETE FROM folders WHERE id = ?', (folder_id,))

    # Update user space
    update_user_space(session['user_id'], -total_size)
    db.commit()

    flash('Folder deleted successfully.', 'success')
    return redirect(url_for('index', folder=folder['parent_id']))


# ==================== Routes: File Management ====================
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Upload files."""
    folder_id = request.form.get('folder_id', type=int)

    if 'files' not in request.files:
        flash('No files selected.', 'error')
        return redirect(url_for('index', folder=folder_id))

    files = request.files.getlist('files')
    db = get_db()
    user_id = session['user_id']

    uploaded = 0
    for file in files:
        if file.filename:
            original_name = secure_filename(file.filename)

            # Check file extension
            if not is_safe_filename(original_name):
                flash(f'File type not allowed: {original_name}', 'error')
                continue

            # Get file size by seeking to end
            file.seek(0, 2)  # Seek to end
            file_size = file.tell()
            file.seek(0)  # Reset to beginning

            # Generate random stored name
            stored_name = generate_stored_name(original_name)
            file_path = UPLOAD_FOLDER / stored_name

            try:
                # Use streaming encryption
                stored_size = encrypt_file_streaming(file, file_path, user_id, session.get('email'))
            except Exception as exc:
                flash(f'Encryption failed for {original_name}: {exc}', 'error')
                # Clean up partial file if exists
                if file_path.exists():
                    file_path.unlink()
                continue

            # Check quota (use stored size)
            can_upload, error = check_quota(user_id, stored_size)
            if not can_upload:
                flash(f'{error}: {original_name}', 'error')
                # Remove the encrypted file since quota exceeded
                if file_path.exists():
                    file_path.unlink()
                continue

            mime_type = mimetypes.guess_type(original_name)[0]

            # Save to database
            db.execute('''
                INSERT INTO files (original_name, stored_name, mime_type, size, stored_size, folder_id, owner_id, is_encrypted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (original_name, stored_name, mime_type, file_size, stored_size, folder_id, user_id, 1))

            # Update user space
            update_user_space(user_id, stored_size)
            uploaded += 1

    db.commit()

    if uploaded > 0:
        flash(f'{uploaded} file(s) uploaded successfully.', 'success')

    return redirect(url_for('index', folder=folder_id))


@app.route('/upload/ajax', methods=['POST'])
@login_required
def upload_file_ajax():
    """Upload files with AJAX support and folder structure preservation."""
    folder_id = request.form.get('folder_id', type=int)
    relative_paths = request.form.getlist('relative_paths')

    if 'files' not in request.files:
        return jsonify({'success': False, 'error': 'No files selected'}), 400

    files = request.files.getlist('files')
    db = get_db()
    user_id = session['user_id']

    uploaded = 0
    errors = []

    # Create folder mapping for nested folder uploads
    folder_cache = {None: folder_id}  # Map relative folder path to folder ID

    def get_or_create_folder(relative_path):
        """Get or create nested folders based on relative path."""
        if not relative_path or '/' not in relative_path:
            return folder_id

        folder_path = '/'.join(relative_path.split('/')[:-1])
        if folder_path in folder_cache:
            return folder_cache[folder_path]

        # Create nested folders
        parts = folder_path.split('/')
        current_parent = folder_id

        for i, part in enumerate(parts):
            # Sanitize folder name to prevent traversal
            part = re.sub(r'[<>:"/\\|?*\.]', '', part)[:255]
            if not part:
                continue

            partial_path = '/'.join(parts[:i + 1])
            if partial_path in folder_cache:
                current_parent = folder_cache[partial_path]
                continue

            # Check if folder exists - use proper NULL handling
            if current_parent is None:
                existing = db.execute('''
                    SELECT id FROM folders WHERE name = ? AND owner_id = ? AND parent_id IS NULL
                ''', (part, user_id)).fetchone()
            else:
                existing = db.execute('''
                    SELECT id FROM folders WHERE name = ? AND owner_id = ? AND parent_id = ?
                ''', (part, user_id, current_parent)).fetchone()

            if existing:
                current_parent = existing['id']
            else:
                # Create folder
                db.execute('INSERT INTO folders (name, parent_id, owner_id) VALUES (?, ?, ?)',
                           (part, current_parent, user_id))
                db.commit()
                current_parent = db.execute('SELECT last_insert_rowid()').fetchone()[0]

            folder_cache[partial_path] = current_parent

        return current_parent

    for i, file in enumerate(files):
        if file.filename:
            relative_path = relative_paths[i] if i < len(relative_paths) else file.filename

            # Validate relative path - prevent directory traversal
            if '..' in relative_path or relative_path.startswith('/'):
                errors.append(f'Invalid path: {relative_path}')
                continue

            original_name = secure_filename(Path(relative_path).name)

            # Determine target folder
            target_folder_id = get_or_create_folder(relative_path)

            # Check file extension
            if not is_safe_filename(original_name):
                errors.append(f'File type not allowed: {original_name}')
                continue

            # Get file size by seeking to end
            file.seek(0, 2)  # Seek to end
            file_size = file.tell()
            file.seek(0)  # Reset to beginning

            # Generate random stored name
            stored_name = generate_stored_name(original_name)
            file_path = UPLOAD_FOLDER / stored_name

            try:
                # Use streaming encryption
                stored_size = encrypt_file_streaming(file, file_path, user_id, session.get('email'))
            except Exception as exc:
                errors.append(f'Encryption failed for {original_name}')
                # Clean up partial file if exists
                if file_path.exists():
                    file_path.unlink()
                continue

            # Check quota (use stored size)
            can_upload, error = check_quota(user_id, stored_size)
            if not can_upload:
                errors.append(f'{error}: {original_name}')
                # Remove the encrypted file since quota exceeded
                if file_path.exists():
                    file_path.unlink()
                continue

            mime_type = mimetypes.guess_type(original_name)[0]

            # Save to database
            db.execute('''
                INSERT INTO files (original_name, stored_name, mime_type, size, stored_size, folder_id, owner_id, is_encrypted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (original_name, stored_name, mime_type, file_size, stored_size, target_folder_id, user_id, 1))

            # Update user space
            update_user_space(user_id, stored_size)
            uploaded += 1

    db.commit()

    return jsonify({
        'success': True,
        'count': uploaded,
        'errors': errors if errors else None
    })


@app.route('/file/<int:file_id>/thumbnail')
@login_required
def get_thumbnail(file_id):
    """Get thumbnail for image/video files."""
    db = get_db()
    user_id = session['user_id']

    file = db.execute('''
        SELECT f.* FROM files f
        WHERE f.id = ? AND (
            f.owner_id = ?
            OR EXISTS (SELECT 1 FROM user_shares us WHERE us.file_id = f.id AND us.shared_with_id = ?)
        )
    ''', (file_id, user_id, user_id)).fetchone()

    if not file:
        abort(404)

    file_type = get_file_type(file['mime_type'])
    if file_type not in ['image', 'video']:
        abort(404)

    file_path = UPLOAD_FOLDER / file['stored_name']
    if not file_path.exists():
        abort(404)

    try:
        data = load_file_bytes(file)
    except Exception:
        abort(404)

    # For images, return the image directly (browser will handle resizing)
    if file_type == 'image':
        return send_file(io.BytesIO(data), mimetype=file['mime_type'])
    else:
        # For video, return a small placeholder SVG instead of the full video
        # This avoids downloading large video files just for thumbnails
        video_placeholder = b'''<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100">
            <rect width="100" height="100" fill="#374151"/>
            <polygon points="40,30 70,50 40,70" fill="#9CA3AF"/>
        </svg>'''
        return send_file(io.BytesIO(video_placeholder), mimetype='image/svg+xml')


@app.route('/folder/<int:folder_id>/download')
@login_required
def download_folder(folder_id):
    """Download folder as streaming ZIP archive."""
    db = get_db()
    user_id = session['user_id']

    folder = db.execute(
        'SELECT * FROM folders WHERE id = ? AND owner_id = ?',
        (folder_id, user_id)
    ).fetchone()

    if not folder:
        flash('Folder not found.', 'error')
        return redirect(url_for('index'))

    def collect_folder_entries(fid, path=''):
        """
        Generator that yields (file_path, file_row) tuples for all files in folder recursively.
        This collects all files first before streaming to avoid database issues during streaming.
        """
        # Get files in folder
        files = db.execute(
            'SELECT * FROM files WHERE folder_id = ? AND owner_id = ?',
            (fid, user_id)
        ).fetchall()

        for file in files:
            yield (path + file['original_name'], file)

        # Get subfolders
        subfolders = db.execute(
            'SELECT * FROM folders WHERE parent_id = ? AND owner_id = ?',
            (fid, user_id)
        ).fetchall()

        for subfolder in subfolders:
            yield from collect_folder_entries(subfolder['id'], path + subfolder['name'] + '/')

    def generate_zip_entries():
        """Generator that yields stream-zip member tuples for streaming ZIP creation."""
        # Collect all entries first (to avoid issues with db connection during streaming)
        entries = list(collect_folder_entries(folder_id, folder['name'] + '/'))

        for file_path, file_row in entries:
            try:
                # Create a generator for the file data
                def file_data_generator(fr=file_row):
                    yield from stream_file_data(fr)

                # Get modification time (or use current time)
                try:
                    mtime = datetime.strptime(file_row['created_at'], '%Y-%m-%d %H:%M:%S')
                except (ValueError, TypeError):
                    mtime = datetime.now()

                yield (
                    file_path,
                    mtime,
                    0o644,
                    ZIP_64,
                    file_data_generator()
                )
            except Exception:
                # Skip files that can't be read
                continue

    def generate_zip():
        """Generator that yields ZIP archive bytes."""
        yield from stream_zip(generate_zip_entries())

    response = Response(generate_zip(), mimetype='application/zip')
    response.headers['Content-Disposition'] = f'attachment; filename="{folder["name"]}.zip"'
    return response


@app.route('/file/<int:file_id>/download')
@login_required
def download_file(file_id):
    """Download a file."""
    db = get_db()
    user_id = session['user_id']

    # Check ownership or shared access
    file = db.execute('''
        SELECT f.* FROM files f
        WHERE f.id = ? AND (
            f.owner_id = ?
            OR EXISTS (SELECT 1 FROM user_shares us WHERE us.file_id = f.id AND us.shared_with_id = ?)
        )
    ''', (file_id, user_id, user_id)).fetchone()

    if not file:
        flash('File not found.', 'error')
        return redirect(url_for('index'))

    file_path = UPLOAD_FOLDER / file['stored_name']
    if not file_path.exists():
        flash('File not found on server.', 'error')
        return redirect(url_for('index'))

    try:
        return stream_file_response(file, as_attachment=True, download_name=file['original_name'])
    except InvalidToken:
        flash('File could not be decrypted.', 'error')
        return redirect(url_for('index'))
    except Exception as exc:
        flash(f'Failed to read file: {exc}', 'error')
        return redirect(url_for('index'))


@app.route('/file/<int:file_id>/view')
@login_required
def view_file(file_id):
    """View/preview a file."""
    db = get_db()
    user_id = session['user_id']

    file = db.execute('''
        SELECT f.* FROM files f
        WHERE f.id = ? AND (
            f.owner_id = ?
            OR EXISTS (SELECT 1 FROM user_shares us WHERE us.file_id = f.id AND us.shared_with_id = ?)
        )
    ''', (file_id, user_id, user_id)).fetchone()

    if not file:
        flash('File not found.', 'error')
        return redirect(url_for('index'))

    file_path = UPLOAD_FOLDER / file['stored_name']
    if not file_path.exists():
        flash('File not found on server.', 'error')
        return redirect(url_for('index'))

    try:
        return stream_file_response(file, as_attachment=False)
    except InvalidToken:
        flash('File could not be decrypted.', 'error')
        return redirect(url_for('index'))
    except Exception as exc:
        flash(f'Failed to read file: {exc}', 'error')
        return redirect(url_for('index'))


@app.route('/file/<int:file_id>/preview')
@login_required
def preview_file(file_id):
    """Preview file in media player."""
    db = get_db()
    user_id = session['user_id']

    file = db.execute('''
        SELECT f.* FROM files f
        WHERE f.id = ? AND (
            f.owner_id = ?
            OR EXISTS (SELECT 1 FROM user_shares us WHERE us.file_id = f.id AND us.shared_with_id = ?)
        )
    ''', (file_id, user_id, user_id)).fetchone()

    if not file:
        flash('File not found.', 'error')
        return redirect(url_for('index'))

    return render_template('preview.html', file=file, get_file_type=get_file_type)


@app.route('/file/<int:file_id>/rename', methods=['POST'])
@login_required
def rename_file(file_id):
    """Rename a file."""
    db = get_db()
    file = db.execute(
        'SELECT * FROM files WHERE id = ? AND owner_id = ?',
        (file_id, session['user_id'])
    ).fetchone()

    if not file:
        flash('File not found.', 'error')
        return redirect(url_for('index'))

    name = request.form.get('name', '').strip()
    if not name:
        flash('File name is required.', 'error')
        return redirect(url_for('index', folder=file['folder_id']))

    # Keep original extension
    orig_ext = Path(file['original_name']).suffix
    new_ext = Path(name).suffix
    if new_ext.lower() != orig_ext.lower():
        name = name + orig_ext

    name = secure_filename(name)

    if not is_safe_filename(name):
        flash('Invalid file extension.', 'error')
        return redirect(url_for('index', folder=file['folder_id']))

    db.execute('UPDATE files SET original_name = ? WHERE id = ?', (name, file_id))
    db.commit()

    flash('File renamed successfully.', 'success')
    return redirect(url_for('index', folder=file['folder_id']))


@app.route('/file/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    """Delete a file."""
    db = get_db()
    file = db.execute(
        'SELECT * FROM files WHERE id = ? AND owner_id = ?',
        (file_id, session['user_id'])
    ).fetchone()

    if not file:
        flash('File not found.', 'error')
        return redirect(url_for('index'))

    folder_id = file['folder_id']

    # Delete physical file
    file_path = UPLOAD_FOLDER / file['stored_name']
    if file_path.exists():
        file_path.unlink()

    # Delete from database
    db.execute('DELETE FROM files WHERE id = ?', (file_id,))

    # Update user space
    update_user_space(session['user_id'], -get_effective_stored_size(file))
    db.commit()

    flash('File deleted successfully.', 'success')
    return redirect(url_for('index', folder=folder_id))


@app.route('/file/<int:file_id>/move', methods=['POST'])
@login_required
def move_file(file_id):
    """Move a file to a different folder."""
    db = get_db()
    file = db.execute(
        'SELECT * FROM files WHERE id = ? AND owner_id = ?',
        (file_id, session['user_id'])
    ).fetchone()

    if not file:
        return jsonify({'error': 'File not found'}), 404

    target_folder_id = request.form.get('folder_id', type=int)

    # Verify target folder exists and belongs to user
    if target_folder_id:
        folder = db.execute(
            'SELECT * FROM folders WHERE id = ? AND owner_id = ?',
            (target_folder_id, session['user_id'])
        ).fetchone()
        if not folder:
            return jsonify({'error': 'Target folder not found'}), 404

    db.execute('UPDATE files SET folder_id = ? WHERE id = ?', (target_folder_id, file_id))
    db.commit()

    return jsonify({'success': True})


# ==================== Routes: Sharing ====================
@app.route('/share/file/<int:file_id>', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    """Share a file with others."""
    db = get_db()
    file = db.execute(
        'SELECT * FROM files WHERE id = ? AND owner_id = ?',
        (file_id, session['user_id'])
    ).fetchone()

    if not file:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'File not found'}), 404
        flash('File not found.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        share_type = request.form.get('share_type')

        if share_type == 'link':
            # Create external share link
            token = secrets.token_urlsafe(32)
            expires_days = request.form.get('expires_days', type=int)
            password = request.form.get('password', '').strip()

            expires_at = None
            if expires_days:
                expires_at = datetime.now() + timedelta(days=expires_days)

            password_hash = None
            if password:
                password_hash = generate_password_hash(password)

            db.execute('''
                INSERT INTO share_links (token, file_id, created_by, password_hash, expires_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (token, file_id, session['user_id'], password_hash, expires_at))
            db.commit()

            share_url = url_for('access_share_link', token=token, _external=True)

            # Return JSON for AJAX requests
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': True, 'share_url': share_url})

            flash(f'Share link created: {share_url}', 'success')

        elif share_type == 'user':
            # Share with specific user
            email = request.form.get('email', '').strip().lower()
            permission = request.form.get('permission', 'read')

            user = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
            if not user:
                flash('User not found.', 'error')
                return redirect(url_for('share_file', file_id=file_id))

            if user['id'] == session['user_id']:
                flash('Cannot share with yourself.', 'error')
                return redirect(url_for('share_file', file_id=file_id))

            # Check if already shared
            existing = db.execute('''
                SELECT id FROM user_shares WHERE file_id = ? AND shared_with_id = ?
            ''', (file_id, user['id'])).fetchone()

            if existing:
                db.execute('UPDATE user_shares SET permission = ? WHERE id = ?',
                           (permission, existing['id']))
            else:
                db.execute('''
                    INSERT INTO user_shares (file_id, owner_id, shared_with_id, permission)
                    VALUES (?, ?, ?, ?)
                ''', (file_id, session['user_id'], user['id'], permission))

            db.commit()
            flash(f'File shared with {email}.', 'success')

        return redirect(url_for('share_file', file_id=file_id))

    # Get existing shares
    share_links = db.execute(
        'SELECT * FROM share_links WHERE file_id = ?', (file_id,)
    ).fetchall()

    user_shares = db.execute('''
        SELECT us.*, u.email, u.name
        FROM user_shares us
        JOIN users u ON us.shared_with_id = u.id
        WHERE us.file_id = ?
    ''', (file_id,)).fetchall()

    return render_template('share.html', file=file, share_links=share_links,
                           user_shares=user_shares, item_type='file')


@app.route('/share/folder/<int:folder_id>', methods=['GET', 'POST'])
@login_required
def share_folder(folder_id):
    """Share a folder with others."""
    db = get_db()
    folder = db.execute(
        'SELECT * FROM folders WHERE id = ? AND owner_id = ?',
        (folder_id, session['user_id'])
    ).fetchone()

    if not folder:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Folder not found'}), 404
        flash('Folder not found.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        share_type = request.form.get('share_type')

        if share_type == 'link':
            token = secrets.token_urlsafe(32)
            expires_days = request.form.get('expires_days', type=int)
            password = request.form.get('password', '').strip()

            expires_at = None
            if expires_days:
                expires_at = datetime.now() + timedelta(days=expires_days)

            password_hash = None
            if password:
                password_hash = generate_password_hash(password)

            db.execute('''
                INSERT INTO share_links (token, folder_id, created_by, password_hash, expires_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (token, folder_id, session['user_id'], password_hash, expires_at))
            db.commit()

            share_url = url_for('access_share_link', token=token, _external=True)

            # Return JSON for AJAX requests
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': True, 'share_url': share_url})

            flash(f'Share link created: {share_url}', 'success')

        elif share_type == 'user':
            email = request.form.get('email', '').strip().lower()
            permission = request.form.get('permission', 'read')

            user = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
            if not user:
                flash('User not found.', 'error')
                return redirect(url_for('share_folder', folder_id=folder_id))

            if user['id'] == session['user_id']:
                flash('Cannot share with yourself.', 'error')
                return redirect(url_for('share_folder', folder_id=folder_id))

            existing = db.execute('''
                SELECT id FROM user_shares WHERE folder_id = ? AND shared_with_id = ?
            ''', (folder_id, user['id'])).fetchone()

            if existing:
                db.execute('UPDATE user_shares SET permission = ? WHERE id = ?',
                           (permission, existing['id']))
            else:
                db.execute('''
                    INSERT INTO user_shares (folder_id, owner_id, shared_with_id, permission)
                    VALUES (?, ?, ?, ?)
                ''', (folder_id, session['user_id'], user['id'], permission))

            db.commit()
            flash(f'Folder shared with {email}.', 'success')

        return redirect(url_for('share_folder', folder_id=folder_id))

    share_links = db.execute(
        'SELECT * FROM share_links WHERE folder_id = ?', (folder_id,)
    ).fetchall()

    user_shares = db.execute('''
        SELECT us.*, u.email, u.name
        FROM user_shares us
        JOIN users u ON us.shared_with_id = u.id
        WHERE us.folder_id = ?
    ''', (folder_id,)).fetchall()

    return render_template('share.html', folder=folder, share_links=share_links,
                           user_shares=user_shares, item_type='folder')


@app.route('/s/<token>', methods=['GET', 'POST'])
def access_share_link(token):
    """Access a shared file/folder via external link."""
    db = get_db()
    share = db.execute('''
        SELECT sl.*, f.original_name as file_name, f.stored_name, f.mime_type,
               f.owner_id, f.is_encrypted, fo.name as folder_name
        FROM share_links sl
        LEFT JOIN files f ON sl.file_id = f.id
        LEFT JOIN folders fo ON sl.folder_id = fo.id
        WHERE sl.token = ?
    ''', (token,)).fetchone()

    if not share:
        flash('Share link not found.', 'error')
        return redirect(url_for('login'))

    # Check expiration
    if share['expires_at']:
        try:
            expires_at = datetime.strptime(share['expires_at'], '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            try:
                expires_at = datetime.strptime(share['expires_at'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                expires_at = datetime.fromisoformat(share['expires_at'])
        if expires_at < datetime.now():
            flash('Share link has expired.', 'error')
        return redirect(url_for('login'))

    # Check password
    if share['password_hash']:
        if request.method == 'POST':
            password = request.form.get('password', '')
            if not check_password_hash(share['password_hash'], password):
                flash('Incorrect password.', 'error')
                return render_template('share_password.html', token=token)
            session[f'share_{token}'] = True
        elif not session.get(f'share_{token}'):
            return render_template('share_password.html', token=token)

    # Update download count
    db.execute('UPDATE share_links SET download_count = download_count + 1 WHERE token = ?',
               (token,))
    db.commit()

    if share['file_id']:
        # Serve file using streaming
        file_path = UPLOAD_FOLDER / share['stored_name']
        if not file_path.exists():
            flash('File not found.', 'error')
            return redirect(url_for('login'))

        try:
            # Create a file row dict for stream_file_response
            file_row = {
                'stored_name': share['stored_name'],
                'mime_type': share['mime_type'],
                'original_name': share['file_name'],
                'owner_id': share['owner_id'],
                'is_encrypted': share['is_encrypted'],
                'size': 0  # We need to get the actual size
            }
            # Get the actual file size from db
            file_info = db.execute('SELECT size FROM files WHERE id = ?', (share['file_id'],)).fetchone()
            if file_info:
                file_row['size'] = file_info['size']

            return stream_file_response(file_row, as_attachment=True, download_name=share['file_name'])
        except InvalidToken:
            flash('File could not be decrypted.', 'error')
            return redirect(url_for('login'))
        except Exception as exc:
            flash(f'Failed to read file: {exc}', 'error')
            return redirect(url_for('login'))

    elif share['folder_id']:
        # List folder contents
        files = db.execute('''
            SELECT * FROM files WHERE folder_id = ?
        ''', (share['folder_id'],)).fetchall()

        subfolders = db.execute('''
            SELECT * FROM folders WHERE parent_id = ?
        ''', (share['folder_id'],)).fetchall()

        return render_template('shared_folder.html', share=share, files=files,
                               folders=subfolders, format_size=format_size)

    flash('Invalid share link.', 'error')
    return redirect(url_for('login'))


@app.route('/share/link/<int:link_id>/delete', methods=['POST'])
@login_required
def delete_share_link(link_id):
    """Delete a share link."""
    db = get_db()
    link = db.execute(
        'SELECT * FROM share_links WHERE id = ? AND created_by = ?',
        (link_id, session['user_id'])
    ).fetchone()

    if not link:
        flash('Share link not found.', 'error')
        return redirect(url_for('index'))

    db.execute('DELETE FROM share_links WHERE id = ?', (link_id,))
    db.commit()

    flash('Share link deleted.', 'success')

    if link['file_id']:
        return redirect(url_for('share_file', file_id=link['file_id']))
    else:
        return redirect(url_for('share_folder', folder_id=link['folder_id']))


@app.route('/share/user/<int:share_id>/delete', methods=['POST'])
@login_required
def delete_user_share(share_id):
    """Remove user share."""
    db = get_db()
    share = db.execute(
        'SELECT * FROM user_shares WHERE id = ? AND owner_id = ?',
        (share_id, session['user_id'])
    ).fetchone()

    if not share:
        flash('Share not found.', 'error')
        return redirect(url_for('index'))

    db.execute('DELETE FROM user_shares WHERE id = ?', (share_id,))
    db.commit()

    flash('User share removed.', 'success')

    if share['file_id']:
        return redirect(url_for('share_file', file_id=share['file_id']))
    else:
        return redirect(url_for('share_folder', folder_id=share['folder_id']))


# ==================== Routes: Admin ====================
@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard."""
    db = get_db()

    users = db.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    pending_users = db.execute('SELECT * FROM users WHERE is_approved = 0').fetchall()
    invitations = db.execute('''
        SELECT i.*, u.name as created_by_name
        FROM invitations i
        JOIN users u ON i.created_by = u.id
        ORDER BY i.created_at DESC
    ''').fetchall()

    # System stats
    total_files = db.execute('SELECT COUNT(*) as count FROM files').fetchone()['count']
    total_size = get_system_used_space()
    system_quota = int(db.execute("SELECT value FROM settings WHERE key = 'system_quota'").fetchone()['value'])

    return render_template('admin.html',
                           users=users,
                           pending_users=pending_users,
                           invitations=invitations,
                           total_files=total_files,
                           total_size=total_size,
                           system_quota=system_quota,
                           format_size=format_size)


@app.route('/admin/user/<int:user_id>/approve', methods=['POST'])
@admin_required
def approve_user(user_id):
    """Approve a pending user."""
    db = get_db()
    db.execute('UPDATE users SET is_approved = 1 WHERE id = ?', (user_id,))
    db.commit()
    flash('User approved.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete a user."""
    if user_id == session['user_id']:
        flash('Cannot delete yourself.', 'error')
        return redirect(url_for('admin_dashboard'))

    db = get_db()

    # Delete user's files from storage
    files = db.execute('SELECT stored_name FROM files WHERE owner_id = ?', (user_id,)).fetchall()
    for file in files:
        file_path = UPLOAD_FOLDER / file['stored_name']
        if file_path.exists():
            file_path.unlink()

    # Delete user (cascades to files, folders, shares)
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()

    flash('User deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/quota', methods=['POST'])
@admin_required
def set_user_quota(user_id):
    """Set user's storage quota."""
    quota_mb = request.form.get('quota', type=int, default=1024)
    quota = quota_mb * 1024 * 1024  # Convert to bytes

    db = get_db()
    db.execute('UPDATE users SET quota = ? WHERE id = ?', (quota, user_id))
    db.commit()

    flash('User quota updated.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/<int:user_id>/role', methods=['POST'])
@admin_required
def set_user_role(user_id):
    """Set user's role."""
    if user_id == session['user_id']:
        flash('Cannot change your own role.', 'error')
        return redirect(url_for('admin_dashboard'))

    role = request.form.get('role', 'user')
    if role not in ('admin', 'user'):
        role = 'user'

    db = get_db()
    db.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
    db.commit()

    flash('User role updated.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/invitation/create', methods=['POST'])
@admin_required
def create_invitation():
    """Create an invitation link."""
    max_uses = request.form.get('max_uses', type=int, default=1)
    expires_days = request.form.get('expires_days', type=int)
    auto_approve = request.form.get('auto_approve') == 'on'

    token = secrets.token_urlsafe(32)
    expires_at = None
    if expires_days:
        expires_at = datetime.now() + timedelta(days=expires_days)

    db = get_db()
    db.execute('''
        INSERT INTO invitations (token, created_by, max_uses, auto_approve, expires_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (token, session['user_id'], max_uses, int(auto_approve), expires_at))
    db.commit()

    invite_url = url_for('register', invite=token, _external=True)
    flash(f'Invitation created: {invite_url}', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/invitation/<int:invite_id>/delete', methods=['POST'])
@admin_required
def delete_invitation(invite_id):
    """Delete an invitation."""
    db = get_db()
    db.execute('DELETE FROM invitations WHERE id = ?', (invite_id,))
    db.commit()
    flash('Invitation deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/settings', methods=['POST'])
@admin_required
def update_settings():
    """Update system settings."""
    db = get_db()

    system_quota_gb = request.form.get('system_quota', type=int, default=10)
    system_quota = system_quota_gb * 1024 * 1024 * 1024

    default_quota_mb = request.form.get('default_quota', type=int, default=1024)
    default_quota = default_quota_mb * 1024 * 1024

    require_approval = '1' if request.form.get('require_approval') == 'on' else '0'

    db.execute("UPDATE settings SET value = ? WHERE key = 'system_quota'", (str(system_quota),))
    db.execute("UPDATE settings SET value = ? WHERE key = 'default_user_quota'", (str(default_quota),))
    db.execute("UPDATE settings SET value = ? WHERE key = 'require_approval'", (require_approval,))
    db.commit()

    flash('Settings updated.', 'success')
    return redirect(url_for('admin_dashboard'))


# ==================== Routes: API ====================
@app.route('/api/token', methods=['POST'])
@login_required
def create_api_token():
    """Create an API token. The token is shown only once and stored as a hash."""
    name = request.form.get('name', 'API Token')
    # Generate the plain token to show to user (only once)
    plain_token = secrets.token_urlsafe(32)
    # Store the hash in database for security
    token_hash = hash_api_token(plain_token)

    db = get_db()
    db.execute('''
        INSERT INTO api_tokens (token, user_id, name)
        VALUES (?, ?, ?)
    ''', (token_hash, session['user_id'], name))
    db.commit()

    # Show plain token only once - it cannot be recovered
    flash(f'API Token created (copy it now, it won\'t be shown again): {plain_token}', 'success')
    return redirect(url_for('settings_page'))


@app.route('/api/token/<int:token_id>/delete', methods=['POST'])
@login_required
def delete_api_token(token_id):
    """Delete an API token."""
    db = get_db()
    db.execute('DELETE FROM api_tokens WHERE id = ? AND user_id = ?',
               (token_id, session['user_id']))
    db.commit()
    flash('API token deleted.', 'success')
    return redirect(url_for('settings_page'))


@app.route('/api/upload', methods=['POST'])
@csrf.exempt  # API uses token authentication, not session
@api_auth_required
def api_upload():
    """API endpoint for file upload."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    folder_id = request.form.get('folder_id', type=int)

    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400

    original_name = secure_filename(file.filename)

    if not is_safe_filename(original_name):
        return jsonify({'error': 'File type not allowed'}), 400

    # Get file size by seeking to end
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Reset to beginning
    user_id = g.api_user['user_id']

    # Generate random stored name
    stored_name = generate_stored_name(original_name)
    file_path = UPLOAD_FOLDER / stored_name

    try:
        # Use streaming encryption
        stored_size = encrypt_file_streaming(file, file_path, user_id, g.api_user.get('email'))
    except Exception as exc:
        # Clean up partial file if exists
        if file_path.exists():
            file_path.unlink()
        return jsonify({'error': f'Encryption failed: {exc}'}), 500

    can_upload, error = check_quota(user_id, stored_size)
    if not can_upload:
        # Remove the encrypted file since quota exceeded
        if file_path.exists():
            file_path.unlink()
        return jsonify({'error': error}), 400

    mime_type = mimetypes.guess_type(original_name)[0]

    db = get_db()
    cursor = db.execute('''
        INSERT INTO files (original_name, stored_name, mime_type, size, stored_size, folder_id, owner_id, is_encrypted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (original_name, stored_name, mime_type, file_size, stored_size, folder_id, user_id, 1))

    update_user_space(user_id, stored_size)
    db.commit()

    return jsonify({
        'success': True,
        'file_id': cursor.lastrowid,
        'name': original_name,
        'size': file_size
    })


@app.route('/api/files')
@api_auth_required
def api_list_files():
    """API endpoint to list files."""
    folder_id = request.args.get('folder_id', type=int)
    user_id = g.api_user['user_id']

    db = get_db()
    files = db.execute('''
        SELECT id, original_name, mime_type, size, created_at
        FROM files WHERE owner_id = ? AND folder_id IS ?
    ''', (user_id, folder_id)).fetchall()

    folders = db.execute('''
        SELECT id, name, created_at
        FROM folders WHERE owner_id = ? AND parent_id IS ?
    ''', (user_id, folder_id)).fetchall()

    return jsonify({
        'files': [dict(f) for f in files],
        'folders': [dict(f) for f in folders]
    })


@app.route('/api/file/<int:file_id>')
@api_auth_required
def api_download_file(file_id):
    """API endpoint to download a file."""
    user_id = g.api_user['user_id']

    db = get_db()
    file = db.execute(
        'SELECT * FROM files WHERE id = ? AND owner_id = ?',
        (file_id, user_id)
    ).fetchone()

    if not file:
        return jsonify({'error': 'File not found'}), 404

    file_path = UPLOAD_FOLDER / file['stored_name']
    if not file_path.exists():
        return jsonify({'error': 'File not found on server'}), 404

    try:
        return stream_file_response(file, as_attachment=True, download_name=file['original_name'])
    except InvalidToken:
        return jsonify({'error': 'File could not be decrypted'}), 500
    except Exception as exc:
        return jsonify({'error': f'Failed to read file: {exc}'}), 500


@app.route('/api/file/<int:file_id>', methods=['DELETE'])
@csrf.exempt  # API uses token authentication, not session
@api_auth_required
def api_delete_file(file_id):
    """API endpoint to delete a file."""
    user_id = g.api_user['user_id']

    db = get_db()
    file = db.execute(
        'SELECT * FROM files WHERE id = ? AND owner_id = ?',
        (file_id, user_id)
    ).fetchone()

    if not file:
        return jsonify({'error': 'File not found'}), 404

    file_path = UPLOAD_FOLDER / file['stored_name']
    if file_path.exists():
        file_path.unlink()

    db.execute('DELETE FROM files WHERE id = ?', (file_id,))
    update_user_space(user_id, -get_effective_stored_size(file))
    db.commit()

    return jsonify({'success': True})


# ==================== Routes: Settings ====================
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings_page():
    """User settings page."""
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_profile':
            name = request.form.get('name', '').strip()
            if name:
                db.execute('UPDATE users SET name = ? WHERE id = ?', (name, session['user_id']))
                session['name'] = name
                db.commit()
                flash('Profile updated.', 'success')

        elif action == 'change_password':
            current = request.form.get('current_password', '')
            new = request.form.get('new_password', '')
            confirm = request.form.get('confirm_password', '')

            if not check_password_hash(user['password_hash'], current):
                flash('Current password is incorrect.', 'error')
            elif len(new) < 6:
                flash('New password must be at least 6 characters.', 'error')
            elif new != confirm:
                flash('Passwords do not match.', 'error')
            else:
                db.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                           (generate_password_hash(new), session['user_id']))
                db.commit()
                flash('Password changed.', 'success')

        return redirect(url_for('settings_page'))

    api_tokens = db.execute(
        'SELECT * FROM api_tokens WHERE user_id = ?', (session['user_id'],)
    ).fetchall()

    return render_template('settings.html', user=user, api_tokens=api_tokens, format_size=format_size)


# ==================== Error Handlers ====================
@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error='Page not found'), 404


@app.errorhandler(413)
def file_too_large(e):
    flash('File too large. Maximum size is 100MB.', 'error')
    return redirect(url_for('index'))


@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error='Server error'), 500


# ==================== Context Processor ====================
@app.context_processor
def inject_globals():
    """Inject global variables into templates."""
    return {
        'current_year': datetime.now().year,
        'app_name': APP_NAME,
        'site_url': SITE_URL,
        'site_description': SITE_DESCRIPTION,
        'og_image': OG_IMAGE,
        'content_domain': CONTENT_DOMAIN,
        'app_domain': APP_DOMAIN
    }


def content_url(path):
    """
    Generate URL for content serving.
    If CONTENT_DOMAIN is configured, use it for file URLs.
    Otherwise, use the normal URL.
    """
    if CONTENT_DOMAIN:
        # Build URL with content domain
        scheme = 'https' if not os.environ.get('FLASK_DEBUG', '0') == '1' else 'http'
        return f"{scheme}://{CONTENT_DOMAIN}{path}"
    return path


# Register template filter for content URLs
app.jinja_env.filters['content_url'] = content_url


# ==================== Main ====================
def main():
    """Main entry point."""
    with app.app_context():
        init_db()
        create_admin_user()

    # Debug mode should only be enabled in development
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'

    print("Starting PyFileStorage server...")
    print("Default admin: admin@local.host / admin123")
    if debug_mode:
        print("WARNING: Debug mode is enabled. Do not use in production!")
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)


if __name__ == '__main__':
    main()
