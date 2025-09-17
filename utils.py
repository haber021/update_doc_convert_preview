import os
import qrcode
import uuid
from datetime import datetime, timedelta
from flask import request, url_for
from sqlalchemy import func, desc
from sklearn.linear_model import LinearRegression
import numpy as np
from app import app
from extensions import db
from models import Document, DocumentType, AccessLog, User
import textwrap

# Optional Pillow imports for annotating QR images with document info
try:
    from PIL import Image, ImageDraw, ImageFont
except Exception:
    Image = None
    ImageDraw = None
    ImageFont = None
import pytz

def _get_db_dialect_name():
    """Return the current DB dialect name in a safe way with fallbacks."""
    try:
        # Prefer the session bind if available
        bind = getattr(db.session, 'bind', None)
        if bind is not None and getattr(bind, 'dialect', None) is not None:
            return bind.dialect.name

        # Fall back to db.engine if present
        engine = getattr(db, 'engine', None)
        if engine is not None and getattr(engine, 'dialect', None) is not None:
            return engine.dialect.name

        # Fall back to using get_engine with current_app
        from flask import current_app
        if hasattr(db, 'get_engine'):
            engine = db.get_engine(current_app)
            if engine is not None and getattr(engine, 'dialect', None) is not None:
                return engine.dialect.name
    except Exception:
        pass

    # Default to sqlite when detection fails
    return 'sqlite'

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png', 'gif'}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_document_folder(extension):
    """Get the folder name for organizing documents by type"""
    folder_map = {
        'pdf': 'pdf',
        'doc': 'doc',
        'docx': 'docx',
        'txt': 'txt',
        'jpg': 'images',
        'jpeg': 'images',
        'png': 'images',
        'gif': 'images'
    }
    return folder_map.get(extension.lower(), 'other')


def resolve_document_file_path(document):
    """Resolve the on-disk absolute/relative path for a document file.

    Tries the stored file_path, then falls back to joining UPLOAD_FOLDER with
    the stored file_path (if relative) and finally with the original filename.
    Returns a path string if found, otherwise None.
    """
    try:
        file_path = (document.file_path or '').strip()
        # If the stored path exists (absolute or relative), use it
        if file_path and os.path.exists(file_path):
            return file_path
        # Try relative to UPLOAD_FOLDER
        uploads = app.config.get('UPLOAD_FOLDER', 'uploads')
        if file_path:
            candidate = os.path.join(uploads, file_path)
            if os.path.exists(candidate):
                return candidate
        if document.filename:
            candidate = os.path.join(uploads, document.filename)
            if os.path.exists(candidate):
                return candidate
    except Exception:
        pass
    return None


def generate_qr_code(document_id):
    """Generate QR code for a document"""
    # Lookup document details early so we can include them in both the QR payload and annotation
    doc = None
    title = ''
    dtype = ''
    owner_name = ''
    try:
        doc = Document.query.get(document_id)
        if doc:
            title = (doc.title or '')
            dtype = (doc.document_type.name if getattr(doc, 'document_type', None) else '')
            owner_name = (doc.owner.get_full_name() if getattr(doc, 'owner', None) else '')
    except Exception:
        doc = None

    # Prefer the public landing page URL first so phone cameras open a minimal page with ID+title
    landing_url = None
    try:
        if doc and getattr(doc, 'document_number', None):
            # try code-based landing (e.g., /qr/code/DOC000123)
            landing_url = url_for('qr_landing_by_code', code=doc.document_number, _external=True)
        else:
            landing_url = url_for('qr_landing', doc_id=document_id, _external=True)
    except Exception:
        # url_for may fail when called outside request/app context (scripts). Try request.url_root then fallback.
        try:
            base = request.url_root
        except Exception:
            base = app.config.get('BASE_URL', 'http://localhost:5000/')
        if doc and getattr(doc, 'document_number', None):
            landing_url = f"{base.rstrip('/')}/qr/code/{doc.document_number}"
        else:
            landing_url = f"{base.rstrip('/')}/qr/{document_id}"

    # Create QR payload: document number first so scanners show it, then landing URL and title
    try:
        if doc and getattr(doc, 'document_number', None):
            doc_code = doc.document_number
        else:
            doc_code = f"DOC{int(document_id):06d}"
    except Exception:
        doc_code = f"DOC{document_id}"

    qr_parts = [f"Document Number: {doc_code}", landing_url]
    if title:
        qr_parts.append(title)

    qr_data = "\n".join(qr_parts)
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)
    
    # Create QR code image
    img = qr.make_image(fill_color="black", back_color="white")
    # Optionally annotate the QR image with human-readable document info
    try:
        if Image is not None and ImageDraw is not None:
            # Ensure PIL Image instance
            pil_img = img.convert('RGB') if hasattr(img, 'convert') else Image.fromarray(img)

            # Try to lookup document details
            title = ''
            dtype = ''
            owner_name = ''
            try:
                doc = Document.query.get(document_id)
                if doc:
                    title = (doc.title or '')
                    dtype = (doc.document_type.name if getattr(doc, 'document_type', None) else '')
                    owner_name = (doc.owner.get_full_name() if getattr(doc, 'owner', None) else '')
            except Exception:
                pass

            # Compose annotation lines: prominent document code (header) then wrapped title and optional meta
            try:
                if doc and getattr(doc, 'document_number', None):
                    header = f"{doc.document_number}"
                else:
                    header = f"DOC{int(document_id):06d}"
            except Exception:
                header = f"DOC{document_id}"

            # Wrap title to max width and limit lines
            title_lines = []
            if title:
                wrapped = textwrap.wrap(title, width=34)
                title_lines = wrapped[:3]

            meta_parts = [p for p in [dtype, owner_name] if p]
            meta_line = ' - '.join(meta_parts) if meta_parts else None

            # We'll draw header (larger) and then title_lines and meta_line below
            lines = [header] + title_lines
            if meta_line:
                lines.append(meta_line)

            # Choose fonts: header_font (bigger) and body_font
            header_font = None
            body_font = None
            try:
                header_font = ImageFont.truetype('arial.ttf', 18)
                body_font = ImageFont.truetype('arial.ttf', 14)
            except Exception:
                try:
                    header_font = ImageFont.truetype('DejaVuSans.ttf', 18)
                    body_font = ImageFont.truetype('DejaVuSans.ttf', 14)
                except Exception:
                    if ImageFont:
                        header_font = ImageFont.load_default()
                        body_font = ImageFont.load_default()

            # Measure total text height and max width
            draw_tmp = ImageDraw.Draw(pil_img)
            text_padding_v = 8
            max_text_w = 0
            total_text_h = 0
            # measure header separately
            for i, line in enumerate(lines):
                use_font = header_font if i == 0 else body_font
                if use_font:
                    tw, th = draw_tmp.textsize(line, font=use_font)
                else:
                    tw, th = draw_tmp.textsize(line)
                max_text_w = max(max_text_w, tw)
                total_text_h += th + 4
            total_text_h += text_padding_v

            # Create new image with space for text below QR
            new_w = max(pil_img.width, max_text_w + 20)
            new_h = pil_img.height + total_text_h + 10
            new_img = Image.new('RGB', (new_w, new_h), color='white')
            # Center QR horizontally
            qr_x = (new_w - pil_img.width) // 2
            new_img.paste(pil_img, (qr_x, 0))

            draw = ImageDraw.Draw(new_img)
            # Draw each line centered, header larger
            current_y = pil_img.height + 6
            for i, line in enumerate(lines):
                use_font = header_font if i == 0 else body_font
                if use_font:
                    tw, th = draw.textsize(line, font=use_font)
                else:
                    tw, th = draw.textsize(line)
                x = (new_w - tw) // 2
                draw.text((x, current_y), line, fill='black', font=use_font)
                current_y += th + 4

            save_img = new_img
        else:
            # Pillow not available, fall back to raw QR image
            save_img = img
    except Exception:
        save_img = img

    # Save QR code inside the static/qr_codes folder and return a path relative to static
    qr_filename = f"qr_{document_id}_{uuid.uuid4().hex[:8]}.png"
    qr_abs_path = os.path.join(app.config['QR_FOLDER'], qr_filename)
    try:
        # If save_img is a PIL Image, use save; else assume qrcode PilImage and call save
        if hasattr(save_img, 'save'):
            save_img.save(qr_abs_path)
        else:
            img.save(qr_abs_path)
    except Exception as e:
        app.logger.error(f"Failed to save QR code image: {e}")
        # As a fallback, try to save using img
        try:
            img.save(qr_abs_path)
        except Exception:
            pass

    # Return path relative to the static folder so templates can use url_for('static', filename=...)
    static_relative_path = os.path.join('qr_codes', qr_filename).replace('\\', '/')
    return static_relative_path

def log_user_action(user_id, action, document_id=None, details=None):
    """Log user actions for audit trail"""
    log = AccessLog(
        user_id=user_id,
        document_id=document_id,
        action=action,
        ip_address=request.remote_addr if request else None,
        user_agent=request.headers.get('User-Agent') if request else None,
        details=details
    )
    db.session.add(log)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to log user action: {e}")

def get_document_stats():
    """Get comprehensive document statistics"""
    stats = {}
    
    # Basic counts
    stats['total_documents'] = Document.query.filter_by(is_active=True).count()
    stats['total_users'] = User.query.filter_by(is_active=True).count()
    stats['total_downloads'] = AccessLog.query.filter_by(action='download').count()
    
    # Document type distribution
    doc_type_stats = db.session.query(
        DocumentType.name,
        func.count(Document.id).label('count')
    ).join(Document).filter(Document.is_active == True).group_by(DocumentType.name).all()
    
    stats['document_types'] = {
        'labels': [stat.name for stat in doc_type_stats],
        'data': [stat.count for stat in doc_type_stats]
    }
    
    # Monthly access trends (last 6 months)
    start_date = datetime.utcnow() - timedelta(days=180)
    # Use dialect-specific month truncation: sqlite lacks date_trunc, use strftime
    dialect_name = _get_db_dialect_name()
    if dialect_name == 'sqlite':
        month_expr = func.strftime('%Y-%m', AccessLog.timestamp).label('month')
    else:
        month_expr = func.date_trunc('month', AccessLog.timestamp).label('month')

    monthly_stats = db.session.query(
        month_expr,
        func.count(AccessLog.id).label('count')
    ).filter(
        AccessLog.timestamp >= start_date,
        AccessLog.action.in_(['view', 'download'])
    ).group_by('month').order_by('month').all()

    def fmt_month(m):
        try:
            return m.strftime('%Y-%m')
        except Exception:
            return str(m)

    stats['monthly_access'] = {
        'labels': [fmt_month(stat.month) for stat in monthly_stats],
        'data': [stat.count for stat in monthly_stats]
    }
    
    # Top accessed documents
    top_docs = Document.query.filter_by(is_active=True).order_by(desc(Document.access_count)).limit(5).all()
    stats['top_documents'] = [
        {'title': doc.title, 'access_count': doc.access_count}
        for doc in top_docs
    ]
    
    # Recent activity (last 24 hours)
    yesterday = datetime.utcnow() - timedelta(days=1)
    stats['recent_activity'] = AccessLog.query.filter(
        AccessLog.timestamp >= yesterday
    ).count()
    
    return stats

def predict_document_requests():
    """Generate predictive analytics for document requests"""
    predictions = []
    
    try:
        # Get historical data for each document type
        doc_types = DocumentType.query.all()
        
        for doc_type in doc_types:
            # Get monthly access data for the last 12 months (dialect-aware)
            start_date = datetime.utcnow() - timedelta(days=365)
            dialect_name = _get_db_dialect_name()
            if dialect_name == 'sqlite':
                month_expr = func.strftime('%Y-%m', AccessLog.timestamp).label('month')
            else:
                month_expr = func.date_trunc('month', AccessLog.timestamp).label('month')

            monthly_data = db.session.query(
                month_expr,
                func.count(AccessLog.id).label('count')
            ).join(Document).filter(
                Document.document_type_id == doc_type.id,
                AccessLog.timestamp >= start_date,
                AccessLog.action.in_(['view', 'download'])
            ).group_by('month').order_by('month').all()
            
            if len(monthly_data) >= 3:  # Need at least 3 months of data
                # Prepare data for prediction
                months = []
                counts = []
                
                for i, data in enumerate(monthly_data):
                    months.append(i)
                    counts.append(data.count)
                
                # Simple linear regression for trend prediction
                if len(months) > 1:
                    X = np.array(months).reshape(-1, 1)
                    y = np.array(counts)
                    
                    model = LinearRegression()
                    model.fit(X, y)
                    
                    # Predict next month
                    next_month_pred = model.predict([[len(months)]])[0]
                    current_month_avg = np.mean(counts[-3:]) if len(counts) >= 3 else np.mean(counts)
                    
                    # Calculate percentage change
                    if current_month_avg > 0:
                        change_percent = ((next_month_pred - current_month_avg) / current_month_avg) * 100
                        
                        if abs(change_percent) > 5:  # Only show significant changes
                            trend = "increase" if change_percent > 0 else "decrease"
                            predictions.append({
                                'document_type': doc_type.name,
                                'trend': trend,
                                'change_percent': abs(change_percent),
                                'message': f"{doc_type.name} requests expected to {trend} by {abs(change_percent):.1f}% next month"
                            })
    
    except Exception as e:
        app.logger.error(f"Error generating predictions: {e}")
        predictions.append({
            'document_type': 'General',
            'trend': 'stable',
            'change_percent': 0,
            'message': 'Insufficient data for predictions. Continue collecting data for better insights.'
        })
    
    # Add seasonal predictions
    current_month = datetime.utcnow().month
    seasonal_predictions = get_seasonal_predictions(current_month)
    predictions.extend(seasonal_predictions)
    
    return predictions

def get_seasonal_predictions(current_month):
    """Get seasonal predictions based on school calendar"""
    seasonal_predictions = []
    
    # Define seasonal patterns for different document types
    seasonal_patterns = {
        'Form 137': {
            3: "Graduation season approaching - expect 40% increase in Form 137 requests",
            4: "Peak graduation season - Form 137 requests typically increase by 60%",
            5: "Post-graduation period - Form 137 requests remain elevated",
            6: "Summer enrollment period - moderate increase in Form 137 requests"
        },
        'Certificate': {
            3: "Graduation season - Certificate requests expected to rise by 50%",
            4: "Peak certificate issuance period",
            5: "Continued high demand for certificates",
            8: "Back-to-school season - increased certificate requests for transfers"
        },
        'Grades': {
            1: "Mid-year assessment period - increased grade record requests",
            3: "End of school year - high demand for grade reports",
            6: "Summer applications - moderate increase in grade requests",
            8: "New school year preparations - increased grade verification requests"
        }
    }
    
    for doc_type, monthly_messages in seasonal_patterns.items():
        if current_month in monthly_messages:
            seasonal_predictions.append({
                'document_type': doc_type,
                'trend': 'seasonal_increase',
                'change_percent': 0,
                'message': monthly_messages[current_month]
            })
    
    return seasonal_predictions

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"


def convert_to_manila_time(dt, format_str='%Y-%m-%d %H:%M:%S'):
    """Convert a naive or timezone-aware datetime to Asia/Manila timezone and return formatted string.

    Args:
        dt: datetime.datetime instance (naive assumed to be UTC).
        format_str: strftime format string to return.

    Returns:
        Formatted datetime string in Asia/Manila timezone.
    """
    try:
        tz_ph = pytz.timezone('Asia/Manila')
        # If naive, assume UTC then convert
        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            import datetime as _dt
            # treat naive as UTC
            dt = dt.replace(tzinfo=pytz.UTC)
        manila_dt = dt.astimezone(tz_ph)
        return manila_dt.strftime(format_str)
    except Exception:
        try:
            # Best-effort fallback: format original dt
            return dt.strftime(format_str)
        except Exception:
            return ''

def get_user_recent_activity(user_id, limit=10):
    """Get recent activity for a specific user"""
    return AccessLog.query.filter_by(user_id=user_id).order_by(desc(AccessLog.timestamp)).limit(limit).all()

def cleanup_old_files():
    """Cleanup old uploaded files and QR codes (for maintenance)"""
    # This function can be called periodically to clean up files
    # for documents that have been deleted or are very old
    try:
        # Find documents that have been marked as inactive for more than 30 days
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        old_documents = Document.query.filter(
            Document.is_active == False,
            Document.updated_at < cutoff_date
        ).all()
        
        for doc in old_documents:
            # Remove files if they exist
            if doc.file_path and os.path.exists(doc.file_path):
                os.remove(doc.file_path)
            
            if doc.qr_code_path:
                qr_abs = os.path.join(app.static_folder, doc.qr_code_path) if not os.path.isabs(doc.qr_code_path) else doc.qr_code_path
                if os.path.exists(qr_abs):
                    os.remove(qr_abs)
            
            # Remove database record
            db.session.delete(doc)
        
        db.session.commit()
        return len(old_documents)
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error during file cleanup: {e}")
        return 0


from email_sender import send_email as _send_email_impl


def send_email(subject: str, recipients: list, body: str, attachments: list = None, reply_to: str = None) -> bool:
    """Wrapper around centralized email sender. Returns True on success."""
    try:
        return _send_email_impl(subject, recipients, body, attachments=attachments, reply_to=reply_to)
    except Exception as e:
        app.logger.error(f"utils.send_email wrapper failed: {e}")
        return False
