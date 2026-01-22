# PyFileStorage

A lightweight, secure web file storage server built with Python and Flask.

## Features

- **User Management**: Admin and user roles with approval workflow
- **Invitation System**: Create invitation links with expiration, usage limits, and auto-approval options
- **File Sharing**: External share links and user-to-user sharing with read/write permissions
- **Authentication**: Email/password and Google OAuth2.0 login
- **Modern UI**: Clean black & white design with dark mode support
- **File Search**: Search files and folders by name
- **Drag & Drop**: Upload files by dragging and dropping
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

Generate tokens from Settings > API Tokens.

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

## Screenshots

The application features a clean, modern interface with:
- Light and dark theme support
- Responsive design for mobile devices
- Icon-based visual elements
- Drag-and-drop file uploads

## License

MIT License
