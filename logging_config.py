import logging
import json
import datetime
from config import LOG_FILE, LOG_LEVEL

# Custom Formatter for Structured Logging (JSON-like)
class StructuredFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            "timestamp": datetime.datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "module": record.module,
            "message": record.getMessage(),
        }
        # Add extra fields if they exist (e.g., user_email, ip_address)
        if hasattr(record, 'user_email'):
            log_data['user_email'] = record.user_email
        if hasattr(record, 'role'):
            log_data['role'] = record.role

        # NEVER leak sensitive info like 'password' in logs
        if 'password' in log_data['message'].lower():
             log_data['message'] = 'Password field mentioned, message sanitized.'

        return json.dumps(log_data)

def setup_logging():
    logger = logging.getLogger('portal_app')
    logger.setLevel(LOG_LEVEL)

    # Prevent logs from bubbling up to the root logger which might have a different config
    logger.propagate = False

    # File Handler for permanent storage
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(StructuredFormatter())

    # Console Handler for immediate feedback (optional, but useful)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))

    # Add handlers only if not already added to prevent duplicate logs
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger

# Global logger instance
logger = setup_logging()