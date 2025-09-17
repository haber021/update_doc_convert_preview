from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail

# Centralized extensions container to avoid circular imports
db = SQLAlchemy()
# Flask-Mail extension (initialized in app factory / startup)
mail = Mail()
