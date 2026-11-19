"""
config.py — ShadowTrace Application Configuration
Member 4 Security: Separates dev/prod settings, no hardcoded secrets.
"""
import os
import secrets


class Config:
    """Base configuration shared by all environments."""
    # Secret key: read from environment, never hardcoded
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    # Database: stored in instance/ which is outside public static/
    DATABASE_PATH = os.environ.get(
        'DATABASE_PATH',
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'shadowtrace.db')
    )

    # Upload storage: outside static/ to prevent direct URL access
    UPLOAD_FOLDER = os.environ.get(
        'UPLOAD_FOLDER',
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    )

    # Generated PDF reports: outside static/
    REPORTS_FOLDER = os.environ.get(
        'REPORTS_FOLDER',
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
    )

    # Backups: outside static/
    BACKUPS_FOLDER = os.environ.get(
        'BACKUPS_FOLDER',
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
    )

    # Upload size limit: 16 MB
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))

    # Allowed file extensions for uploads
    ALLOWED_EXTENSIONS = {'csv'}

    # Session cookie security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


class DevelopmentConfig(Config):
    """Development-only settings. Never use in production."""
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False  # Allow HTTP on localhost


class ProductionConfig(Config):
    """
    Production settings.
    Set FLASK_ENV=production in environment.
    Debug MUST be off. HTTPS MUST be enabled externally (nginx/caddy).
    """
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True   # Cookies only sent over HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    PREFERRED_URL_SCHEME = 'https'


# Select config based on environment variable
config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
}

def get_config():
    env = os.environ.get('FLASK_ENV', 'development').lower()
    return config_map.get(env, DevelopmentConfig)
