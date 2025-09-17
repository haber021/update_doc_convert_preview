from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from extensions import db

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    users = db.relationship('User', backref='role', lazy='dynamic')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    student_id = db.Column(db.String(20), unique=True, nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    uploaded_documents = db.relationship('Document', foreign_keys='Document.uploaded_by_id', backref='uploader', lazy='dynamic')
    owned_documents = db.relationship('Document', foreign_keys='Document.owner_id', backref='owner', lazy='dynamic')
    access_logs = db.relationship('AccessLog', backref='user', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.username}>'
    
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def has_role(self, role_name):
        return self.role and self.role.name == role_name
    
    def can_access_admin(self):
        return self.has_role('Admin')
    
    def can_upload_documents(self):
        return self.has_role('Admin') or self.has_role('Teacher') or self.has_role('Registrar')

class DocumentType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    documents = db.relationship('Document', backref='document_type', lazy='dynamic')

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)
    file_type = db.Column(db.String(50))
    qr_code_path = db.Column(db.String(500))
    qr_code_data = db.Column(db.Text)  # Stores the QR code content
    # Human-friendly unique document code, set after insert (e.g., DOC000123)
    document_number = db.Column(db.String(50), unique=True, nullable=True)
    
    # Foreign keys
    document_type_id = db.Column(db.Integer, db.ForeignKey('document_type.id'), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    access_count = db.Column(db.Integer, default=0)
    
    # Relationships
    access_logs = db.relationship('AccessLog', backref='document', lazy='dynamic')
    owner_details = db.relationship('OwnerDocumentDetails', backref='document', uselist=False, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Document {self.title}>'
    
    def increment_access(self):
        self.access_count += 1
        db.session.commit()

class OwnerDocumentDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False, unique=True)
    first_name = db.Column(db.String(50), nullable=True)
    middle_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    address = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<OwnerDocumentDetails doc={self.document_id}>'


class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)  # view, download, upload, delete, etc.
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    details = db.Column(db.Text)  # Additional details about the action
    
    def __repr__(self):
        return f'<AccessLog {self.user.username} - {self.action}>'

class SystemSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    description = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @staticmethod
    def get_setting(key, default_value=None):
        setting = SystemSettings.query.filter_by(key=key).first()
        return setting.value if setting else default_value
    
    @staticmethod
    def set_setting(key, value, description=None):
        setting = SystemSettings.query.filter_by(key=key).first()
        if setting:
            setting.value = value
            setting.updated_at = datetime.utcnow()
        else:
            setting = SystemSettings(key=key, value=value, description=description)
            db.session.add(setting)
        db.session.commit()
