import bcrypt
from auth.validation import validate_registration_data
from models.user import User
from config import BCRYPT_ROUNDS

def register_user(name, email, password, role):
    try:
        # 1. Server-Side Input Validation
        validate_registration_data(name, email, password, role)

        # 2. Check for existing user (optional, but good practice)
        if User.get_by_email(email):
            raise ValueError("A user with this email already exists.")

        # 3. Secure Password Hashing
        # bcrypt handles salting internally, providing a strong, adaptive hash
        salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS) #returns smth like b'$2b$12$KIXQJ5j6K9u1h8H6jFhOe.'
        password_bytes = password.encode('utf-8') #convert to binary "MyPassword123!" → b'MyPassword123!'
        # Store as string for DB
        password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8') # b'$2b$12$KIXQJ5j6K9u1h8H6jFhOe...' → '$2b$12$KIXQJ5j6K9u1h8H6jFhOe...'

        # 4. Create and Save User Model
        user = User(
            name=name,
            email=email,
            role=role,
            password_hash=password_hash
        )
        user.save()
        return user
        
    except ValueError as e:
        # Catch validation and integrity errors, and re-raise a safe, user-friendly message
        raise e
    except Exception as e:
        # Centralized Error Handling: Catch unexpected errors
        print(f"DEBUG: Internal Error: {e}") # Log full error internally
        # Safe Error Message for the user
        raise Exception("An unexpected error occurred during registration. Please try again.")
    


# ValueError: Expected errors we can explain to the user clearly
# Exception: Unexpected errors we need to hide (security: don't leak system details) 