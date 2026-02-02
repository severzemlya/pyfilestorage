"""
Migrate encrypted files from Fernet (v1) to AES-GCM streaming format (v2).

Usage:
  python app/migrate_encryption_v1_to_v2.py --dry-run
  python app/migrate_encryption_v1_to_v2.py --backup

Notes:
  - This script decrypts with Fernet (v1) and re-encrypts with AES-GCM (v2).
  - Large files may consume memory during v1 decrypt (Fernet requires full ciphertext).
"""

import argparse
import base64
import json
import os
import sqlite3
import sys
from io import BytesIO
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dotenv import load_dotenv
import secrets


ENCRYPTION_CHUNK_SIZE = 64 * 1024


def load_settings(base_dir):
    settings_file = base_dir / 'settings.json'
    default_settings = {
        'upload_folder': 'uploads',
        'database_path': 'storage.db'
    }
    try:
        if settings_file.exists():
            with open(settings_file, 'r') as f:
                settings = json.load(f)
                for key, value in default_settings.items():
                    if key not in settings:
                        settings[key] = value
                return settings
    except (json.JSONDecodeError, IOError) as exc:
        print(f'Warning: Could not load settings.json: {exc}')
    return default_settings


def get_secret():
    secret = os.environ.get('FILE_ENCRYPTION_SECRET') or os.environ.get('SECRET_KEY')
    if not secret:
        raise RuntimeError('FILE_ENCRYPTION_SECRET or SECRET_KEY is required')
    return secret


def derive_user_key_v1(user_id, email, secret):
    if not email:
        raise ValueError('Email is required for encryption')
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'pyfilestorage',
        info=f'user:{user_id}:{email}'.encode('utf-8')
    )
    return base64.urlsafe_b64encode(hkdf.derive(secret.encode('utf-8')))


def derive_user_key_v2(user_id, email, secret):
    if not email:
        raise ValueError('Email is required for encryption')
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'pyfilestorage_v2',
        info=f'user:{user_id}:{email}'.encode('utf-8')
    )
    return hkdf.derive(secret.encode('utf-8'))


def derive_chunk_nonce(base_nonce, chunk_index):
    index_bytes = chunk_index.to_bytes(12, 'big')
    return bytes(a ^ b for a, b in zip(base_nonce, index_bytes))


def decrypt_v1(ciphertext, user_id, email, secret):
    key = derive_user_key_v1(user_id, email, secret)
    return Fernet(key).decrypt(ciphertext)


def encrypt_stream_v2(input_file, output_path, user_id, email, secret):
    key = derive_user_key_v2(user_id, email, secret)
    base_nonce = secrets.token_bytes(12)
    total_stored_size = 12

    with open(output_path, 'wb') as out:
        out.write(base_nonce)

        chunk_index = 0
        while True:
            chunk = input_file.read(ENCRYPTION_CHUNK_SIZE)
            if not chunk:
                break

            chunk_nonce = derive_chunk_nonce(base_nonce, chunk_index)
            cipher = Cipher(algorithms.AES(key), modes.GCM(chunk_nonce))
            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(chunk) + encryptor.finalize()
            encrypted_chunk = ciphertext + encryptor.tag

            chunk_size = len(encrypted_chunk)
            out.write(chunk_size.to_bytes(4, 'big'))
            out.write(encrypted_chunk)

            total_stored_size += 4 + chunk_size
            chunk_index += 1

    return total_stored_size


def recalc_used_space(db):
    rows = db.execute('SELECT owner_id, COALESCE(SUM(stored_size), 0) AS total FROM files GROUP BY owner_id').fetchall()
    for row in rows:
        db.execute('UPDATE users SET used_space = ? WHERE id = ?', (row['total'], row['owner_id']))


def main():
    parser = argparse.ArgumentParser(description='Migrate encrypted files from v1 (Fernet) to v2 (AES-GCM).')
    parser.add_argument('--dry-run', action='store_true', help='Scan and report without changing files')
    parser.add_argument('--limit', type=int, default=0, help='Limit number of files to migrate')
    parser.add_argument('--max-size-mb', type=int, default=0, help='Skip files larger than this size (MB)')
    parser.add_argument('--backup', action='store_true', help='Keep .bak copies of original encrypted files')
    parser.add_argument('--no-recalc-used-space', action='store_true', help='Skip recalculating users.used_space')
    parser.add_argument('--db-path', type=str, default='', help='Override database path')
    parser.add_argument('--upload-folder', type=str, default='', help='Override upload folder path')
    args = parser.parse_args()

    load_dotenv()

    base_dir = Path(__file__).parent.absolute()
    settings = load_settings(base_dir)
    secret = get_secret()

    db_path = Path(args.db_path) if args.db_path else (base_dir / settings.get('database_path', 'storage.db'))
    upload_folder = Path(args.upload_folder) if args.upload_folder else (base_dir / settings.get('upload_folder', 'uploads'))

    if not db_path.exists():
        print(f'Database not found: {db_path}')
        return 1
    if not upload_folder.exists():
        print(f'Upload folder not found: {upload_folder}')
        return 1

    max_size_bytes = args.max_size_mb * 1024 * 1024 if args.max_size_mb else 0

    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row

    users = db.execute('SELECT id, email FROM users').fetchall()
    user_emails = {row['id']: row['email'] for row in users}

    files = db.execute('''
        SELECT id, stored_name, owner_id, is_encrypted, size, stored_size
        FROM files
        WHERE is_encrypted = 1
        ORDER BY id
    ''').fetchall()

    migrated = 0
    skipped = 0
    failed = 0

    for row in files:
        if args.limit and migrated >= args.limit:
            break

        owner_id = row['owner_id']
        email = user_emails.get(owner_id)
        if not email:
            print(f"[skip] file_id={row['id']} missing owner email")
            skipped += 1
            continue

        file_path = upload_folder / row['stored_name']
        if not file_path.exists():
            print(f"[skip] file_id={row['id']} missing file: {file_path}")
            skipped += 1
            continue

        if max_size_bytes and file_path.stat().st_size > max_size_bytes:
            print(f"[skip] file_id={row['id']} exceeds max size")
            skipped += 1
            continue

        try:
            encrypted_data = file_path.read_bytes()
            try:
                plaintext = decrypt_v1(encrypted_data, owner_id, email, secret)
            except InvalidToken:
                print(f"[skip] file_id={row['id']} not v1 or already migrated")
                skipped += 1
                continue

            if args.dry_run:
                print(f"[dry-run] file_id={row['id']} would migrate")
                migrated += 1
                continue

            temp_path = file_path.with_suffix(file_path.suffix + '.v2tmp')
            stored_size = encrypt_stream_v2(BytesIO(plaintext), temp_path, owner_id, email, secret)

            if args.backup:
                backup_path = file_path.with_suffix(file_path.suffix + '.bak')
                if backup_path.exists():
                    backup_path.unlink()
                file_path.replace(backup_path)
            else:
                file_path.unlink()

            temp_path.replace(file_path)

            db.execute('UPDATE files SET stored_size = ? WHERE id = ?', (stored_size, row['id']))
            migrated += 1
            print(f"[ok] file_id={row['id']} migrated")
        except Exception as exc:
            failed += 1
            print(f"[fail] file_id={row['id']} error={exc}")

    if not args.dry_run:
        if not args.no_recalc_used_space:
            recalc_used_space(db)
        db.commit()

    print(f"Done. migrated={migrated} skipped={skipped} failed={failed}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
