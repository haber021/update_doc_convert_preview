import sys
import os
# Ensure project root is on sys.path so local imports resolve
proj_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if proj_root not in sys.path:
    sys.path.insert(0, proj_root)

"""One-off migration script: add document_number column and backfill codes.
Run from project root: python scripts\backfill_doc_numbers.py
"""
from app import app
from extensions import db
from sqlalchemy import text
from app import app
from extensions import db
from models import Document
from utils import generate_qr_code

with app.app_context():
    conn = db.engine.connect()
    try:
        res = conn.execute(text("PRAGMA table_info('document')"))
        cols = [row[1] for row in res.fetchall()]
        print('Existing columns:', cols)
        if 'document_number' not in cols:
            print("Adding column 'document_number' to document table...")
            conn.execute(text("ALTER TABLE document ADD COLUMN document_number VARCHAR"))
        # Backfill any missing values
        docs = conn.execute(text("SELECT id, document_number FROM document")).fetchall()
        updated = 0
        for doc_id, doc_number in docs:
            if not doc_number:
                code = f"DOC{int(doc_id):06d}"
                conn.execute(text("UPDATE document SET document_number = :code WHERE id = :id"), {'code': code, 'id': doc_id})
                updated += 1
        print(f'Backfilled document_number for {updated} documents')
    finally:
        conn.close()
    print('Done')
