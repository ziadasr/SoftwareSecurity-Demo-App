import os
from dotenv import load_dotenv

# Load environment variables from .env file (REQUIRED)
load_dotenv()

# --- Security Configuration ---
# Load SECRET_KEY from environment (required for production)
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("CRITICAL: SECRET_KEY must be set in .env file for security!")

DB_NAME = os.getenv("DB_NAME")
if not DB_NAME:
    raise ValueError("CRITICAL: DB_NAME must be set in .env file!")

# Password Security
MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH"))
if not os.getenv("MIN_PASSWORD_LENGTH"):
    raise ValueError("CRITICAL: MIN_PASSWORD_LENGTH must be set in .env file!")

BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS"))
if not os.getenv("BCRYPT_ROUNDS"):
    raise ValueError("CRITICAL: BCRYPT_ROUNDS must be set in .env file!")

# Brute-Force Lockout
LOCKOUT_THRESHOLD = int(os.getenv("LOCKOUT_THRESHOLD"))
if not os.getenv("LOCKOUT_THRESHOLD"):
    raise ValueError("CRITICAL: LOCKOUT_THRESHOLD must be set in .env file!")

LOCKOUT_PERIOD_SECONDS = int(os.getenv("LOCKOUT_PERIOD_SECONDS"))
if not os.getenv("LOCKOUT_PERIOD_SECONDS"):
    raise ValueError("CRITICAL: LOCKOUT_PERIOD_SECONDS must be set in .env file!")

# Session/JWT Configuration
SESSION_DURATION_MINUTES = int(os.getenv("SESSION_DURATION_MINUTES"))
if not os.getenv("SESSION_DURATION_MINUTES"):
    raise ValueError("CRITICAL: SESSION_DURATION_MINUTES must be set in .env file!")

# Logging
LOG_FILE = os.getenv("LOG_FILE")
if not LOG_FILE:
    raise ValueError("CRITICAL: LOG_FILE must be set in .env file!")

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# --- Validation Configuration ---
# Parse comma-separated roles from .env
ALLOWED_ROLES_STR = os.getenv("ALLOWED_ROLES")
if not ALLOWED_ROLES_STR:
    raise ValueError("CRITICAL: ALLOWED_ROLES must be set in .env file!")
ALLOWED_ROLES = [role.strip() for role in ALLOWED_ROLES_STR.split(",")]

MAX_EMAIL_LENGTH = int(os.getenv("MAX_EMAIL_LENGTH"))
if not os.getenv("MAX_EMAIL_LENGTH"):
    raise ValueError("CRITICAL: MAX_EMAIL_LENGTH must be set in .env file!")

MAX_NAME_LENGTH = int(os.getenv("MAX_NAME_LENGTH"))
if not os.getenv("MAX_NAME_LENGTH"):
    raise ValueError("CRITICAL: MAX_NAME_LENGTH must be set in .env file!")

# Ensure the logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")