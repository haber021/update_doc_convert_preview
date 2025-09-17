#!/usr/bin/env python3
"""
Script to reorganize existing uploaded documents into subfolders based on file type.
This script moves files from the root uploads directory into organized subfolders
and updates the database with the new file paths.
"""

import os
import sys
import shutil
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app import app, db
from models import Document
from utils import get_document_folder

def get_file_extension(filename):
    """Extract file extension from filename"""
    if '.' not in filename:
        return ''
    return filename.rsplit('.', 1)[1].lower()

def organize_existing_files():
    """Move existing files into organized subfolders and update database"""
    with app.app_context():
        print("Starting document reorganization...")

        # Get upload folder from config
        upload_folder = app.config.get('UPLOAD_FOLDER', 'uploads')
        upload_path = Path(upload_folder)

        if not upload_path.exists():
            print(f"Upload folder {upload_folder} does not exist.")
            return

        # Get all documents from database
        documents = Document.query.filter_by(is_active=True).all()
        print(f"Found {len(documents)} active documents to process.")

        moved_count = 0
        error_count = 0

        for doc in documents:
            try:
                # Skip if file_path is already in a subfolder (contains '/')
                if doc.file_path and '/' in doc.file_path:
                    print(f"Skipping {doc.filename} - already in subfolder")
                    continue

                # Get current file path
                current_path = upload_path / doc.filename
                if not current_path.exists():
                    print(f"Warning: File {doc.filename} not found at {current_path}")
                    continue

                # Determine target folder
                extension = get_file_extension(doc.filename)
                target_folder = get_document_folder(extension)
                target_dir = upload_path / target_folder

                # Create target directory if it doesn't exist
                target_dir.mkdir(exist_ok=True)

                # Generate new filename with UUID if not already present
                if '_' not in doc.filename or len(doc.filename.split('_')[0]) != 36:
                    import uuid
                    new_filename = f"{uuid.uuid4()}_{doc.filename}"
                else:
                    new_filename = doc.filename

                # Move file to new location
                target_path = target_dir / new_filename
                shutil.move(str(current_path), str(target_path))

                # Update database with new file path
                new_file_path = f"{target_folder}/{new_filename}"
                doc.file_path = new_file_path

                print(f"Moved {doc.filename} -> {new_file_path}")
                moved_count += 1

            except Exception as e:
                print(f"Error processing {doc.filename}: {e}")
                error_count += 1

        # Commit all changes
        try:
            db.session.commit()
            print(f"\nReorganization complete!")
            print(f"Files moved: {moved_count}")
            print(f"Errors: {error_count}")
        except Exception as e:
            db.session.rollback()
            print(f"Error committing changes: {e}")

def verify_organization():
    """Verify that files are properly organized"""
    with app.app_context():
        print("\nVerifying organization...")

        upload_folder = app.config.get('UPLOAD_FOLDER', 'uploads')
        upload_path = Path(upload_folder)

        # Check subfolders
        subfolders = [f for f in upload_path.iterdir() if f.is_dir()]
        print(f"Found subfolders: {[f.name for f in subfolders]}")

        # Check files in each subfolder
        for subfolder in subfolders:
            files = list(subfolder.glob('*'))
            print(f"{subfolder.name}/: {len(files)} files")

        # Check for files still in root
        root_files = [f for f in upload_path.glob('*') if f.is_file()]
        if root_files:
            print(f"Warning: {len(root_files)} files still in root directory:")
            for f in root_files:
                print(f"  {f.name}")
        else:
            print("All files are properly organized in subfolders.")

if __name__ == "__main__":
    print("Document Organization Script")
    print("=" * 40)

    organize_existing_files()
    verify_organization()

    print("\nScript completed successfully!")
