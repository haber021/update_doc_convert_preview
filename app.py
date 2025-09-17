import os
import logging
import mimetypes
from flask import Flask, request
from flask_login import LoginManager
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from extensions import db, mail

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///qr_document_system.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['QR_FOLDER'] = os.path.join(app.static_folder, 'qr_codes')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
# Static version for cache-busting of static assets
app.config['STATIC_VERSION'] = os.environ.get('STATIC_VERSION', '1')
# Optional path to LibreOffice/soffice binary for Word->PDF conversion
app.config['SOFFICE_PATH'] = os.environ.get('SOFFICE_PATH', '')

# Create upload directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['QR_FOLDER'], exist_ok=True)

# Email configuration - FIXED
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ('true', '1', 'yes')
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'False').lower() in ('true', '1', 'yes')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', os.environ.get('EMAIL_HOST_USER', ''))
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', os.environ.get('EMAIL_HOST_PASSWORD', ''))
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

# Debug email configuration
logging.debug(f"Email config - Server: {app.config['MAIL_SERVER']}")
logging.debug(f"Email config - Port: {app.config['MAIL_PORT']}")
logging.debug(f"Email config - Use TLS: {app.config['MAIL_USE_TLS']}")
logging.debug(f"Email config - Username: {app.config['MAIL_USERNAME']}")
logging.debug(f"Email config - Password set: {bool(app.config['MAIL_PASSWORD'])}")

# Initialize extensions
db.init_app(app)
mail.init_app(app)

# MIME type fixes
try:
    mimetypes.add_type('font/woff2', '.woff2')
except Exception:
    pass

# Inject static version into templates for cache-busting
@app.context_processor
def inject_static_version():
    return {'static_version': app.config.get('STATIC_VERSION', '1')}

# Inject pending edit requests count for admins into all templates
@app.context_processor
def inject_pending_edit_count():
    """Inject a single pending count for the navbar bell icon.
    Includes unresolved edit requests and unresolved access requests (download/print/update).
    """
    try:
        from flask_login import current_user as _cu
        if not getattr(_cu, 'is_authenticated', False) or not _cu.can_access_admin():
            return {'pending_edit_count': 0}
        from models import AccessLog
        from sqlalchemy import desc

        # Count unresolved edit requests
        edit_raw = AccessLog.query.filter_by(action='request_edit').order_by(desc(AccessLog.timestamp)).limit(200).all()
        pending_edit = 0
        for req in edit_raw:
            resolved = AccessLog.query.filter(
                AccessLog.document_id == req.document_id,
                AccessLog.user_id == req.user_id,
                AccessLog.action.in_(['edit_grant', 'request_edit_reject']),
                AccessLog.timestamp >= req.timestamp
            ).first()
            if not resolved:
                pending_edit += 1

        # Count unresolved access requests (download/print/update/open/email)
        access_raw = AccessLog.query.filter(AccessLog.action.in_([
                                        'request_download', 'request_print', 'request_update', 'request_open', 'request_email'
                                    ]))\
                                    .order_by(desc(AccessLog.timestamp)).limit(300).all()
        pending_access = 0
        for req in access_raw:
            kind = req.action.replace('request_', '')
            resolved = AccessLog.query.filter(
                AccessLog.document_id == req.document_id,
                AccessLog.user_id == req.user_id,
                AccessLog.action.in_([f'{kind}_grant', f'request_{kind}_reject']),
                AccessLog.timestamp >= req.timestamp
            ).first()
            if not resolved:
                pending_access += 1

        pending_total = pending_edit + pending_access
        return {'pending_edit_count': pending_total}
    except Exception:
        return {'pending_edit_count': 0}

# Global response header normalization and security
@app.after_request
def set_secure_headers(resp):
    try:
        # X-Content-Type-Options
        resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
        # Remove deprecated/unwanted headers
        for h in ['X-XSS-Protection', 'X-Frame-Options', 'Expires']:
            if h in resp.headers:
                resp.headers.pop(h, None)
        # Prefer Cache-Control over Expires for dynamic HTML
        ct = resp.headers.get('Content-Type', '')
        if ct.startswith('text/html'):
            resp.headers['Cache-Control'] = 'no-store'
        # Set CSP with frame-ancestors instead of X-Frame-Options
        resp.headers.setdefault('Content-Security-Policy', "default-src 'self' https: data: blob:; img-src 'self' data: https: blob:; script-src 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; frame-ancestors 'self';")
        # Normalize charset for textual responses
        textual_types = ('text/html', 'text/css', 'application/json', 'application/javascript')
        if any(ct.startswith(t) for t in textual_types):
            main = ct.split(';')[0]
            resp.headers['Content-Type'] = f"{main}; charset=utf-8"
        # Ensure correct font content-type and no charset
        path = request.path or ''
        if path.endswith('.woff2'):
            resp.headers['Content-Type'] = 'font/woff2'
        if resp.headers.get('Content-Type', '').startswith('font/'):
            resp.headers['Content-Type'] = resp.headers['Content-Type'].split(';')[0]
    except Exception:
        pass
    return resp

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Create tables and initialize data
with app.app_context():
    import models
    import auth
    import routes
    db.create_all()
        
    # Ensure new columns are present for existing deployments (lightweight migration)
    # Add 'document_number' to documents table if it doesn't exist (SQLite)
    try:
        from sqlalchemy import text
        conn = db.engine.connect()
        res = conn.execute(text("PRAGMA table_info('document')"))
        cols = [row[1] for row in res.fetchall()]
        if 'document_number' not in cols:
            app.logger.info("Adding 'document_number' column to document table")
            conn.execute(text("ALTER TABLE document ADD COLUMN document_number VARCHAR"))
            # Backfill existing documents with a human-friendly code
            docs = conn.execute(text("SELECT id FROM document")).fetchall()
            for (doc_id,) in docs:
                code = f"DOC{int(doc_id):06d}"
                conn.execute(text("UPDATE document SET document_number = :code WHERE id = :id"), {'code': code, 'id': doc_id})
            app.logger.info('Backfilled document_number for existing documents')
        conn.close()
    except Exception as e:
        app.logger.warning(f'Could not run light migration for document_number: {e}')
    
    # Create default admin user if not exists
    from models import User, Role, DocumentType
    from werkzeug.security import generate_password_hash
    
    # Create roles if they don't exist
    roles = ['Admin', 'Teacher', 'Student', 'Registrar']
    for role_name in roles:
        if not Role.query.filter_by(name=role_name).first():
            role = Role(name=role_name)
            db.session.add(role)
    
    # Create document types if they don't exist
    document_types = [
        ('Form 137', 'Official academic record for students'),
        ('Certificate', 'Various certificates and credentials'),
        ('Grades', 'Grade reports and transcripts'),
        ('ID Documents', 'Identification documents'),
        ('Diploma', 'Academic diplomas and degrees'),
        ('Other', 'Other document types')
    ]
    for type_name, description in document_types:
        if not DocumentType.query.filter_by(name=type_name).first():
            doc_type = DocumentType(name=type_name, description=description)
            db.session.add(doc_type)
    
    # Create default admin user
    admin_role = Role.query.filter_by(name='Admin').first()
    if not User.query.filter_by(username='admin').first():
        admin_user = User(
            username='admin',
            email='admin@school.edu',
            password_hash=generate_password_hash('admin123'),
            first_name='System',
            last_name='Administrator',
            role=admin_role
        )
        db.session.add(admin_user)
    
    db.session.commit()
    logging.info("Database tables created and default admin user initialized")
