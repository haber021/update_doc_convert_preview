# Overview

This is a QR Code-Based Document Storage & Management System with Predictive Analytics built for educational institutions. The system allows users to upload, manage, and access documents through QR codes, with role-based access control for different user types (Admin, Teacher, Student, Registrar). It includes features like document scanning via QR codes, analytics dashboard with predictive insights, and comprehensive user management.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Template Engine**: Jinja2 templating with Flask for server-side rendering
- **UI Framework**: Bootstrap 5 with dark theme for responsive design
- **JavaScript Libraries**: Chart.js for analytics visualization, HTML5-QRCode for camera-based scanning
- **Styling**: Custom CSS with CSS variables for consistent theming
- **Interactive Features**: QR code scanning (camera and file upload), real-time analytics charts, file upload with drag-and-drop

## Backend Architecture
- **Web Framework**: Flask with modular blueprint structure
- **Authentication**: Flask-Login for session management with role-based access control
- **Password Security**: Werkzeug for password hashing and verification
- **File Handling**: Werkzeug utilities for secure file uploads with size limits (16MB)
- **QR Code Generation**: qrcode library for generating document access QR codes
- **Predictive Analytics**: scikit-learn with LinearRegression for document usage predictions

## Data Storage Solutions
- **Database**: SQLAlchemy ORM with SQLite as default (configurable for other databases)
- **Database Models**: User, Role, Document, DocumentType, AccessLog, SystemSettings
- **File Storage**: Local filesystem for document uploads and QR code images
- **Session Management**: Flask sessions with configurable secret key

## Authentication and Authorization
- **Multi-Role System**: Admin, Teacher, Student, Registrar with different permission levels
- **Session-Based Authentication**: Flask-Login with remember me functionality
- **Role-Based Access Control**: Method-level permissions for document operations
- **Audit Trail**: AccessLog model tracks all user actions for security monitoring

## External Dependencies
- **Core Framework**: Flask, Flask-SQLAlchemy, Flask-Login
- **File Processing**: Werkzeug, qrcode, PIL (via qrcode)
- **Data Analysis**: pandas, scikit-learn, numpy for predictive analytics
- **Frontend Assets**: Bootstrap 5, Font Awesome icons, Chart.js
- **QR Scanning**: HTML5-QRCode library for browser-based scanning
- **Security**: Werkzeug security utilities for password management