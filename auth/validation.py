import re
from config import (
    ALLOWED_ROLES, 
    MIN_PASSWORD_LENGTH, 
    MAX_EMAIL_LENGTH, 
    MAX_NAME_LENGTH
)

def validate_name(name):
    # Checks for length limits
    if not name or not (1 < len(name) <= MAX_NAME_LENGTH):
        raise ValueError(f"Name must be between 2 and {MAX_NAME_LENGTH} characters.")

def validate_email(email):
    # Validates email format and length
    # University email specific validation is simplified here
    if not email or len(email) > MAX_EMAIL_LENGTH:
        raise ValueError(f"Email length exceeds limit of {MAX_EMAIL_LENGTH} characters.")
    
    # Simple regex for general email format
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.fullmatch(email_regex, email):
        raise ValueError("Invalid email format.")

def validate_password_strength(password):
    # Enforces password strength requirements:
    # - Minimum length
    # - At least one uppercase letter
    # - At least one lowercase letter
    # - At least one digit
    # - At least one special character
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")

    #creates a dictionary of lambda functions to check for each requirement ---> p is the password being checked
    checks = {
        'lowercase': lambda p: re.search(r"[a-z]", p),
        'uppercase': lambda p: re.search(r"[A-Z]", p),
        'digit': lambda p: re.search(r"[0-9]", p),
        'special': lambda p: re.search(r"[!@#$%^&*(),.?\":{}|<>]", p)
    }

    if not all(check(password) for check in checks.values()):
        raise ValueError("Password must include an uppercase letter, a lowercase letter, a digit, and a special character.")

def validate_role(role):
    # Checks if the provided role is allowed (Role-Based Access Control)
    if role not in ALLOWED_ROLES:
        raise ValueError(f"Invalid role provided. Must be one of: {', '.join(ALLOWED_ROLES)}")

def validate_registration_data(name, email, password, role):
    # Central function to validate all registration inputs
    validate_name(name)
    validate_email(email)
    validate_password_strength(password)
    validate_role(role)





