import bcrypt
import time
import secrets
from datetime import datetime, timedelta
from models.user import User
from config import LOCKOUT_PERIOD_SECONDS, SECRET_KEY, SESSION_DURATION_MINUTES, LOCKOUT_THRESHOLD
from logging_config import logger

# Simple Session Store (in a real app, this would be a secure Redis or DB)
# Key: session_token | Value: {'user_email': str, 'expiry': datetime}
SESSION_STORE = {} 

def generate_session_token(user_email, role):
    # Generates a secure, cryptographically random session token and stores
    # it with an expiration time. This replaces JWT for simplicity but
    # fulfills the 'Session token generation' requirement securely.
    token = secrets.token_urlsafe(32) # Generate a strong, random token
    expiry = datetime.now() + timedelta(minutes=SESSION_DURATION_MINUTES)
    
    # In a real app, the session secret (SECRET_KEY) would be used to sign a JWT for a more stateless approach. For simplicity, we use a token map.
    SESSION_STORE[token] = {
        'user_email': user_email,
        'role': role,
        'expiry': expiry
    }
    
    logger.info(
        "Session token generated successfully.", 
        extra={'user_email': user_email, 'role': role}
    )
    return token

def authenticate_session(session_token):
    # Authenticates a user based on their session token.
    session_data = SESSION_STORE.get(session_token)
    
    if not session_data:
        return None, "Invalid session token."
    
    if datetime.now() > session_data['expiry']:
        del SESSION_STORE[session_token] # Delete expired session
        return None, "Session expired."
        
    # Valid session
    user = User.get_by_email(session_data['user_email'])
    return user, None

def login_user(email, password):
    # The main login function, enforcing all security requirements.
    # Prevents Brute Force and Credential Stuffing.
    # 1. Look up user by email (prevents Credential Stuffing if email is unknown)
    user = User.get_by_email(email)
    
    # Record the time of the login attempt for lockout calculation
    current_time = time.time()
    
    # Logging all authentication attempts is a security requirement
    log_extra = {'user_email': email}

    if user is None:
        logger.warning("Login failed: Unknown email.", extra=log_extra)
        # Use generic error message for security (prevents user enumeration)
        raise ValueError("Invalid email or password.")

    # 2. Account Lockout Check (Brute-Force Prevention)
    if user.is_locked:
        # Check if the lockout period has expired
        time_since_last_attempt = current_time - user.last_login_attempt
        if time_since_last_attempt < LOCKOUT_PERIOD_SECONDS:
            logger.warning("Login failed: Account is locked.", extra=log_extra)
            # Safe Error Message
            raise ValueError(
                f"Account is locked. Try again in {int(LOCKOUT_PERIOD_SECONDS - time_since_last_attempt)} seconds."
            )
        #f fomart string
        else:
            # Lockout period expired, reset the state
            user.update_login_state(is_success=True, last_attempt_time=current_time)
            logger.info("Account unlocked after timeout.", extra=log_extra)

    # 3. Password Verification
    # bcrypt.checkpw is resistant to timing attacks
    password_bytes = password.encode('utf-8')
    hash_bytes = user.password_hash.encode('utf-8')

    if bcrypt.checkpw(password_bytes, hash_bytes):
        # 4. SUCCESS: Reset attempts, log, and generate token
        user.update_login_state(is_success=True, last_attempt_time=current_time)
        session_token = generate_session_token(user.email, user.role)
        logger.info(
            "Successful login.", 
            extra={'user_email': user.email, 'role': user.role}
        )
        return user, session_token
    else:
        # 5. FAILURE: Increment attempts, log, and update DB
        user.update_login_state(is_success=False, last_attempt_time=current_time)
        logger.warning(
            f"Login failed: Invalid password. Attempt {user.failed_attempts} / {LOCKOUT_THRESHOLD}.",
            extra=log_extra
        )
        # Use generic error message for security (prevents password hint)
        raise ValueError("Invalid email or password.")