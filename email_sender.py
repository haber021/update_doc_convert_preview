import smtplib
import logging
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from flask_mail import Message
from flask import current_app
from extensions import mail, db
import os
from datetime import datetime
from models import Document, User, AccessLog
try:
    # Python 3.9+ zoneinfo in stdlib
    from zoneinfo import ZoneInfo
    MANILA_TIMEZONE = ZoneInfo('Asia/Manila')
except Exception:
    # Fallback: use UTC offset if zoneinfo unavailable
    MANILA_TIMEZONE = None

def send_email(subject, recipients, body, attachments=None, reply_to=None):
    """
    Send email using Flask-Mail with fallback to direct SMTP
    """
    # Try Flask-Mail first
    try:
        msg = Message(
            subject=subject,
            recipients=recipients,
            body=body,
            reply_to=reply_to
        )
        
        # Add attachments if any
        if attachments:
            for file_path, filename, mime_type in attachments:
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        msg.attach(filename, mime_type, f.read())
                else:
                    logging.warning(f"Attachment file not found: {file_path}")
        
        mail.send(msg)
        logging.info(f"Email sent successfully to {recipients}")
        return True
        
    except Exception as e:
        # Provide clearer guidance on authentication failures
        msg = str(e)
        logging.error(f"Flask-Mail failed: {msg}")
        if isinstance(e, smtplib.SMTPAuthenticationError) or '535' in msg or 'Authentication' in msg:
            logging.error("SMTP authentication failed. If you're using Gmail, enable 2FA and create an App Password (see https://support.google.com/accounts/answer/185833). Regular account passwords are often rejected.")
        # Fallback to direct SMTP
        try:
            return send_email_direct_smtp(subject, recipients, body, attachments, reply_to)
        except Exception as smtp_error:
            logging.error(f"Direct SMTP also failed: {smtp_error}")
            return False

def send_email_direct_smtp(subject, recipients, body, attachments=None, reply_to=None):
    """
    Fallback email sending using direct SMTP
    """
    try:
        # Get config (support both MAIL_* and EMAIL_* keys)
        smtp_server = current_app.config.get('MAIL_SERVER') or current_app.config.get('EMAIL_HOST', 'smtp.gmail.com')
        smtp_port = current_app.config.get('MAIL_PORT') or current_app.config.get('EMAIL_PORT', 587)
        username = current_app.config.get('MAIL_USERNAME') or current_app.config.get('EMAIL_HOST_USER')
        password = current_app.config.get('MAIL_PASSWORD') or current_app.config.get('EMAIL_HOST_PASSWORD')
        use_tls = current_app.config.get('MAIL_USE_TLS', True)
        use_ssl = current_app.config.get('MAIL_USE_SSL', False)
        ssl_port = current_app.config.get('MAIL_SSL_PORT', 465)

        # Create message
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = username or current_app.config.get('DEFAULT_FROM_EMAIL', 'no-reply@localhost')
        msg['To'] = ', '.join(recipients)
        if reply_to:
            msg['Reply-To'] = reply_to

        # Add body
        msg.attach(MIMEText(body, 'plain'))

        # Add attachments
        if attachments:
            for file_path, filename, mime_type in attachments:
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        part = MIMEApplication(f.read(), Name=filename)
                        part['Content-Disposition'] = f'attachment; filename="{filename}"'
                        msg.attach(part)

        # Ensure we have credentials
        if not username or not password:
            logging.error("SMTP credentials are not configured (MAIL_USERNAME / MAIL_PASSWORD or EMAIL_HOST_USER / EMAIL_HOST_PASSWORD). Aborting send.")
            return False

        # Helper to safely quit server
        def safe_quit(srv):
            try:
                srv.quit()
            except Exception:
                pass

        # Try SSL first if configured
        if use_ssl:
            try:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port or ssl_port, timeout=15)
                server.login(username, password)
                server.sendmail(msg['From'], recipients, msg.as_string())
                safe_quit(server)
                logging.info(f"Direct SMTP_SSL email sent successfully to {recipients}")
                return True
            except Exception as e_ssl:
                logging.error(f"SMTP_SSL send failed: {e_ssl}")
                # fall through to TLS attempt below

        # Try STARTTLS (common case)
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=15)
        try:
            server.ehlo()
            if use_tls:
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
            try:
                server.login(username, password)
                server.sendmail(msg['From'], recipients, msg.as_string())
                logging.info(f"Direct SMTP email sent successfully to {recipients}")
                return True
            except smtplib.SMTPAuthenticationError as auth_err:
                logging.error(f"SMTP authentication failed during login: {auth_err}")
                logging.error("If using Gmail, enable 2FA and create an App Password (https://support.google.com/accounts/answer/185833).")
                safe_quit(server)
                # Try fallback to SMTP_SSL on standard SSL port
                try:
                    logging.info("Attempting SMTP_SSL fallback on port %s", ssl_port)
                    server_ssl = smtplib.SMTP_SSL(smtp_server, ssl_port, timeout=15)
                    server_ssl.login(username, password)
                    server_ssl.sendmail(msg['From'], recipients, msg.as_string())
                    safe_quit(server_ssl)
                    logging.info(f"Direct SMTP_SSL fallback email sent successfully to {recipients}")
                    return True
                except Exception as e2:
                    logging.error(f"SMTP_SSL fallback failed: {e2}")
                    return False
        finally:
            safe_quit(server)

    except Exception as e:
        logging.error(f"Direct SMTP email failed: {e}")
        return False


def get_manila_time():
    """
    Get current time in Manila timezone

    Returns:
        datetime: Current time in Manila timezone
    """
    if MANILA_TIMEZONE is not None:
        return datetime.now(MANILA_TIMEZONE)
    # Fallback: use UTC time +8 hours
    try:
        from datetime import timedelta
        return datetime.utcnow() + timedelta(hours=8)
    except Exception:
        return datetime.utcnow()


def send_document_to_owner(document_id, additional_message=None):
    """
    Automatically send an uploaded document to the document owner via email
    """
    try:
        # Get the document
        document = Document.query.get(document_id)
        if not document:
            logging.error(f"Document {document_id} not found")
            return False
        
        # Get the owner
        owner = User.query.get(document.owner_id)
        if not owner or not owner.email:
            logging.error(f"Document owner not found or has no email address")
            return False
        
        # Get the uploader
        uploader = User.query.get(document.uploaded_by_id)
        uploader_name = uploader.get_full_name() if uploader else "System"
        
        # Create email content
        subject = f"New Document Uploaded: {document.title}"
        
        # Create document link
        try:
            if document.document_number:
                link = current_app.config.get('APP_BASE_URL', '') + url_for('qr_landing_by_code', code=document.document_number)
            else:
                link = current_app.config.get('APP_BASE_URL', '') + url_for('qr_landing', doc_id=document.id)
        except Exception:
            link = "Please log in to the system to view your document"
        
        # Compose email body (formatted letter)
        body_lines = [
            f"{get_manila_time().strftime('%B %d, %Y')}",
            "",
            f"To: {owner.get_full_name()}",
            f"Owner Email: {owner.email}",
            "",
            f"Subject: Notification of New Document Upload — {document.title}",
            "",
            f"Dear {owner.get_full_name()},",
            "",
            "This is to notify you that a new document has been uploaded and assigned to you in the Institutional Document Management System.",
            "",
            "Document Summary:",
            "────────────────────────────────────────────────────",
            f"Title:            {document.title}",
            f"Document ID:      {document.document_number or ('#' + str(document.id))}",
            f"Document Type:    {document.document_type.name if document.document_type else 'N/A'}",
            f"Uploaded by:      {uploader_name}",
            f"Original File:    {document.filename}",
            f"File Size:        {(document.file_size / 1024 / 1024):.2f} MB" if getattr(document, 'file_size', None) else "File Size:        N/A",
            f"Uploaded at:      {document.created_at.strftime('%Y-%m-%d %H:%M:%S')} (GMT+8)",
            "────────────────────────────────────────────────────",
            "",
            f"You can view the document here: {link}",
            ""
        ]
        
        if additional_message:
            body_lines.extend(["Additional message:", additional_message, ""])
        
        body_lines.extend([
            "If you require assistance or have questions about this document, please contact the Help Desk.",
            "",
            "Thank you,",
            "Document Management System",
            ""
        ])
        
        body = "\n".join(body_lines)
        
        # Prepare attachment
        attachments = None
        if document.file_path and os.path.exists(document.file_path):
            mimetype = document.file_type or 'application/octet-stream'
            attachments = [(document.file_path, document.filename, mimetype)]
        
        # Send email to owner
        success = send_email(subject, [owner.email], body, attachments=attachments)
        
        if success:
            # Log the action
            from utils import log_user_action
            log_user_action(document.uploaded_by_id, 'auto_email', document.id, 
                          f"Automatically sent document to owner {owner.email}")
            logging.info(f"Document {document_id} automatically sent to owner {owner.email}")
        else:
            logging.error(f"Failed to automatically send document {document_id} to owner {owner.email}")
        
        return success
        
    except Exception as e:
        logging.error(f"Error in send_document_to_owner for document {document_id}: {e}")
        return False


def notify_document_upload_success(document_id, uploader_id):
    """
    Notify the uploader that their document was successfully uploaded and sent to the owner
    """
    try:
        # Get the document
        document = Document.query.get(document_id)
        if not document:
            return False
        
        # Get the uploader
        uploader = User.query.get(uploader_id)
        if not uploader or not uploader.email:
            return False
        
        # Get the owner
        owner = User.query.get(document.owner_id)
        owner_name = owner.get_full_name() if owner else "the owner"
        
        # Create email content
        subject = f"Document Upload Confirmation: {document.title}"
        
        body_lines = [
            f"{get_manila_time().strftime('%B %d, %Y')}",
            "",
            f"{uploader.get_full_name()}",
            f"{uploader.get_role_display() if hasattr(uploader, 'get_role_display') else ''}",
            f"{uploader.department if hasattr(uploader, 'department') else ''}",
            "",
            f"SUBJECT: CONFIRMATION OF DOCUMENT UPLOAD",
            "",
            f"Dear {uploader.get_full_name()},",
            "",
            "This letter confirms the successful upload of your document to the Institutional Document Management System.",
            "",
            "DOCUMENT DETAILS",
            "────────────────────────────────────────────────────",
            f"Title:               {document.title}",
            f"Document ID:         {document.document_number or ('#' + str(document.id))}",
            f"Classification:      {document.document_type.name if document.document_type else 'N/A'}",
            f"Assigned Owner:      {owner_name}",
            f"Original File Name:  {document.filename}",
            f"Upload Timestamp:    {document.created_at.strftime('%Y-%m-%d %H:%M:%S')} (GMT+8)",
            "────────────────────────────────────────────────────",
            "",
            "The document has been transmitted to the assigned owner. Please retain this confirmation for your records.",
            "",
            "If you need support, contact the Help Desk during business hours.",
            "",
            "Sincerely,",
            "",
            "Document Management System Administrator",
            "Office of Information Technology",
            "",
            "cc: Digital Records Archive"
        ]
        
        body = "\n".join(body_lines)
        
        # Send notification to uploader
        success = send_email(subject, [uploader.email], body)
        
        if success:
            logging.info(f"Upload success notification sent to uploader {uploader.email}")
        else:
            logging.warning(f"Failed to send upload success notification to {uploader.email}")
        
        return success
        
    except Exception as e:
        logging.error(f"Error in notify_document_upload_success: {e}")
        return False