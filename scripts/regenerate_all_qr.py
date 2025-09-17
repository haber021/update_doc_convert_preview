"""Regenerate annotated QR images for all documents.
Run from project root:
    python scripts\regenerate_all_qr.py
"""
import sys
import os
# Ensure project root is on sys.path so local imports resolve
proj_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if proj_root not in sys.path:
    sys.path.insert(0, proj_root)

from app import app
from extensions import db
from models import Document
from utils import generate_qr_code
import os

with app.app_context():
    print('Running regenerate_all_qr.py')
    print('Project root:', proj_root)
    docs = Document.query.all()
    print(f'Found {len(docs)} documents')
    count = 0
    for doc in docs:
        try:
            print('Processing doc', doc.id)
            # Ensure document_number exists
            if not doc.document_number:
                doc.document_number = f"DOC{int(doc.id):06d}"
                db.session.add(doc)
                db.session.flush()

            # Remove old QR if exists
            if doc.qr_code_path:
                old = os.path.join(app.static_folder, doc.qr_code_path)
                if os.path.exists(old):
                    try:
                        os.remove(old)
                    except Exception:
                        pass

            new_rel = generate_qr_code(doc.id)
            print('Generated QR ->', new_rel)
            doc.qr_code_path = new_rel
            db.session.add(doc)
            count += 1
        except Exception as e:
            print(f"Failed for doc {doc.id}: {e}")
    db.session.commit()
    print(f"Regenerated QR for {count} documents")
