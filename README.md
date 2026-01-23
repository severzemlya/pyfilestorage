# PyFileStorage

A lightweight, secure web file storage server built with Python and Flask.

## Features

- **User Management**: Admin and user roles with approval workflow
- **Invitation System**: Create invitation links with expiration, usage limits, and auto-approval options
- **File Sharing**: External share links and user-to-user sharing with read/write permissions
- **Authentication**: Email/password and Google OAuth2.0 login
- **Modern UI**: Clean black & white design with dark mode support
- **File Search**: Search files and folders by name
- **Drag & Drop**: Upload files and folders by dragging and dropping
- **Folder Upload/Download**: Upload entire folders with structure preserved, download folders as ZIP archives
- **Upload Progress**: Real-time upload progress indicator with percentage and size
- **Toast Notifications**: Non-intrusive popup notifications in bottom-left corner
- **Thumbnail Preview**: Visual thumbnails for images and videos in file list
- **Storage Indicator**: Compact storage usage display in footer
- **Media Player**: Built-in preview for images, videos, audio, and PDFs
- **API Access**: RESTful API for programmatic file uploads
- **Folder Management**: Create, rename, and organize folders
- **Security**: Blocks dangerous file types (.exe, .php, etc.), randomizes stored filenames
- **Quota System**: Per-user and system-wide storage quotas
- **SQLite Database**: Lightweight data storage

## Installation

1. Clone the repository:
```bash
git clone https://github.com/severzemlya/pyfilestorage.git
cd pyfilestorage
```

2. Create a virtual environment and install dependencies:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Copy environment template and configure it:
```bash
cp .env.example .env
```

4. Run the server:
```bash
python app/main.py
```

5. Open your browser and navigate to `http://localhost:5000`

## Default Admin Account

- **Email**: admin@local.host
- **Password**: admin123

**Important**: Change the default password immediately after first login!

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key for sessions | Random generated |
| `ADMIN_EMAIL` | Default admin email | admin@local.host |
| `ADMIN_PASSWORD` | Default admin password | admin123 |
| `FLASK_DEBUG` | Enable debug mode (set to '1' for development) | 0 |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | (not set) |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | (not set) |
| `FILE_ENCRYPTION_SECRET` | Master secret for per-user file encryption | (not set) |
| `APP_DOMAIN` | Main application domain (for domain separation security) | (not set) |
| `CONTENT_DOMAIN` | Separate domain for file serving (XSS protection) | (not set) |
| `UPLOAD_FOLDER` | Absolute path for file storage (can be different drive) | uploads/ |
| `TURNSTILE_SITE_KEY` | Cloudflare Turnstile site key (bot protection) | (not set) |
| `TURNSTILE_SECRET_KEY` | Cloudflare Turnstile secret key (bot protection) | (not set) |

### Cloudflare Turnstile (Bot Protection)

Cloudflare Turnstile is a CAPTCHA alternative that helps protect forms from bots without user friction.

1. Go to the [Cloudflare Dashboard](https://dash.cloudflare.com/turnstile) and create a new Turnstile widget
2. Set `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` in your `.env` file

When both keys are configured, Turnstile protection is automatically enabled on:
- Login page
- Registration page
- Password-protected share links

If these variables are not set, the application works normally without bot protection.

### Domain Separation (Security)

For enhanced security against XSS attacks via uploaded files, you can configure domain separation:

- `APP_DOMAIN`: The main domain where authenticated operations occur (e.g., `app.example.com`)
- `CONTENT_DOMAIN`: A separate domain for serving uploaded content (e.g., `content.example.com`)

When both are configured:
- Session cookies are only sent to `APP_DOMAIN`
- `CONTENT_DOMAIN` can only serve file content (view/download), not perform authenticated operations
- This prevents malicious uploaded files from stealing session cookies

### Custom Upload Folder

By default, files are stored in the `uploads/` folder relative to the app directory.
You can specify an absolute path via `UPLOAD_FOLDER` environment variable to store files on a different drive or location:

```bash
# Linux/macOS
UPLOAD_FOLDER=/mnt/storage/pyfilestorage/uploads

# Windows
UPLOAD_FOLDER=D:\storage\pyfilestorage\uploads
```

### Google OAuth Setup

Create a Google OAuth client and set `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` in `.env`.
Add the following authorized redirect URI in Google Cloud Console:

- `http://localhost:5000/login/google/callback`

If these variables are not set, the Google login button is hidden.

### File Encryption Notes

Uploaded files are encrypted at rest using a per-user key derived from `FILE_ENCRYPTION_SECRET`.
Set `FILE_ENCRYPTION_SECRET` (or `SECRET_KEY`) to a stable value before production use.
If the secret changes, encrypted files may become unreadable.

## API Usage

### Authentication

All API requests require an API token in the `X-API-Token` header.

Generate tokens from Settings > API Tokens. **Important**: The token is shown only once during creation and is stored securely hashed in the database. Copy it immediately!

### Upload File

```bash
curl -X POST \
  -H "X-API-Token: YOUR_TOKEN" \
  -F "file=@/path/to/file.jpg" \
  http://localhost:5000/api/upload
```

### List Files

```bash
curl -H "X-API-Token: YOUR_TOKEN" \
  http://localhost:5000/api/files
```

### Download File

```bash
curl -H "X-API-Token: YOUR_TOKEN" \
  http://localhost:5000/api/file/1 -o downloaded_file.jpg
```

### Delete File

```bash
curl -X DELETE \
  -H "X-API-Token: YOUR_TOKEN" \
  http://localhost:5000/api/file/1
```

## Security Features

- Blocked dangerous file extensions (.exe, .php, .bat, etc.)
- Randomized stored filenames to prevent direct access attacks
- Per-user file encryption at rest with on-demand decryption for preview/download
- Password protection for share links
- User approval workflow
- Session-based authentication
- CSRF protection via Flask-WTF
- Content-Security-Policy (CSP) headers to prevent XSS
- API token hashing for secure storage
- Domain separation support for XSS/session hijacking prevention
- Secure session cookie configuration (HTTPOnly, SameSite)
- Cloudflare Turnstile bot protection (optional)

## Screenshots

The application features a clean, modern interface with:
- Light and dark theme support
- Responsive design optimized for mobile devices
  - Touch-friendly buttons and controls
  - Mobile-optimized admin dashboard tables
  - Clipboard copy functionality with iOS Safari support
- Icon-based visual elements
- Drag-and-drop file and folder uploads
- Visual thumbnails for images and videos
- Real-time upload progress indicator
- Toast notifications for upload status
- Storage usage indicator in footer

## License

MIT License
