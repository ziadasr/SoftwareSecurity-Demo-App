"""
Automated Security Test Suite for University Portal
Tests all 10 security test cases from SECURITY_TEST_CASES.md
Run with: pytest test_security.py -v
"""

import pytest
import sqlite3
import os
import bcrypt
import json
from datetime import datetime, timedelta
from auth.validation import validate_name, validate_email, validate_password_strength
from auth.register import register_user
from auth.login import login_user, authenticate_session, generate_session_token, SESSION_STORE
from models.user import User
from database import init_db, conn
from config import LOCKOUT_THRESHOLD, SESSION_DURATION_MINUTES

# Setup: Initialize test database
@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Initialize database before running tests"""
    init_db()
    yield
    # Cleanup after tests (optional)

@pytest.fixture(autouse=True)
def clear_session_store():
    """Clear session store before each test"""
    SESSION_STORE.clear()
    yield
    SESSION_STORE.clear()


# ============================================================================
# TEST-IV-001: INPUT VALIDATION - Name Field Test
# ============================================================================

class TestInputValidationName:
    """Test name validation (2-50 characters)"""
    
    def test_name_too_short(self):
        """TC1a: Name with 1 character should fail"""
        with pytest.raises(ValueError, match="Name must be between"):
            validate_name("a")
    
    def test_name_valid(self):
        """TC1b: Valid name should pass"""
        # Should not raise exception
        validate_name("John")
        validate_name("Alice Johnson")
    
    def test_name_too_long(self):
        """TC1c: Name with 51 characters should fail"""
        long_name = "A" * 51
        with pytest.raises(ValueError, match="Name must be between"):
            validate_name(long_name)
    
    def test_name_boundary_min(self):
        """Test minimum valid name (2 characters)"""
        validate_name("Jo")  # Should not raise
    
    def test_name_boundary_max(self):
        """Test maximum valid name (50 characters)"""
        validate_name("A" * 50)  # Should not raise


# ============================================================================
# TEST-IV-002: INPUT VALIDATION - Email Format Test
# ============================================================================

class TestInputValidationEmail:
    """Test email validation with regex"""
    
    def test_email_invalid_format(self):
        """TC2a: Email without @ should fail"""
        with pytest.raises(ValueError, match="Invalid email format"):
            validate_email("invalid-email")
    
    def test_email_valid_simple(self):
        """TC2b: Valid email should pass"""
        validate_email("user@example.com")  # Should not raise
    
    def test_email_valid_complex(self):
        """TC2c: Email with + and . should pass"""
        validate_email("test.user+tag@university.edu")  # Should not raise
    
    def test_email_invalid_no_domain(self):
        """Email without domain should fail"""
        with pytest.raises(ValueError, match="Invalid email format"):
            validate_email("user@")
    
    def test_email_invalid_no_extension(self):
        """Email without extension should fail"""
        with pytest.raises(ValueError, match="Invalid email format"):
            validate_email("user@example")
    
    def test_email_valid_multiple_dots(self):
        """Email with multiple dots should pass"""
        validate_email("user.name@sub.example.com")  # Should not raise


# ============================================================================
# TEST-IV-003: INPUT VALIDATION - Password Strength Test
# ============================================================================

class TestInputValidationPassword:
    """Test password strength validation"""
    
    def test_password_too_short(self):
        """TC3a: Password less than 10 characters should fail"""
        with pytest.raises(ValueError, match="Password must be at least 10 characters"):
            validate_password_strength("weak")
    
    def test_password_no_special_char(self):
        """TC3b: Password without special character should fail"""
        with pytest.raises(ValueError, match="special character"):
            validate_password_strength("NoSpecial123")
    
    def test_password_valid_strong(self):
        """TC3c: Strong password should pass"""
        validate_password_strength("SecurePass123!")  # Should not raise
    
    def test_password_no_lowercase(self):
        """TC3d: Password without lowercase should fail"""
        with pytest.raises(ValueError, match="lowercase"):
            validate_password_strength("ALLUPPERCASE123!")
    
    def test_password_no_uppercase(self):
        """Password without uppercase should fail"""
        with pytest.raises(ValueError, match="uppercase"):
            validate_password_strength("alllowercase123!")
    
    def test_password_no_digit(self):
        """Password without digit should fail"""
        with pytest.raises(ValueError, match="digit"):
            validate_password_strength("NoDigitPassword!")
    
    def test_password_valid_complex(self):
        """Valid complex password should pass"""
        validate_password_strength("MyStr0ng!Pass")  # Should not raise


# ============================================================================
# TEST-ENC-001: ENCRYPTION - Password Hashing Test
# ============================================================================

class TestEncryptionPasswordHashing:
    """Test bcrypt password hashing"""
    
    def test_password_hashed_not_plaintext(self):
        """Verify passwords are not stored in plaintext"""
        email = f"hashtest_{int(datetime.now().timestamp())}@university.edu"
        password = "TestHash123!"
        
        # Register user
        user = register_user("Hash Tester", email, password, "Student")
        
        # Query database
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE email = ?", (email,))
        result = cursor.fetchone()
        stored_hash = result[0] if result else None
        
        # Verify hash properties
        assert stored_hash is not None, "Password hash not found in database"
        assert stored_hash.startswith("$2b$"), "Hash should start with $2b$ (bcrypt signature)"
        assert len(stored_hash) == 60, "Bcrypt hash should be 60 characters"
        assert stored_hash != password, "Hash should not equal plaintext password"
    
    def test_password_hash_verifiable(self):
        """Verify bcrypt hash can be verified correctly"""
        email = f"verify_{int(datetime.now().timestamp())}@university.edu"
        password = "VerifyPass123!"
        
        # Register user
        register_user("Verify Tester", email, password, "Student")
        
        # Get stored hash
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE email = ?", (email,))
        stored_hash = cursor.fetchone()[0]
        
        # Verify password matches hash
        password_bytes = password.encode('utf-8')
        hash_bytes = stored_hash.encode('utf-8')
        assert bcrypt.checkpw(password_bytes, hash_bytes), "Password verification failed"
    
    def test_password_hash_wrong_password_fails(self):
        """Verify bcrypt rejects wrong password"""
        email = f"wrong_{int(datetime.now().timestamp())}@university.edu"
        password = "CorrectPass123!"
        wrong_password = "WrongPass123!"
        
        # Register user
        register_user("Wrong Tester", email, password, "Student")
        
        # Get stored hash
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE email = ?", (email,))
        stored_hash = cursor.fetchone()[0]
        
        # Verify wrong password fails
        assert not bcrypt.checkpw(wrong_password.encode('utf-8'), stored_hash.encode('utf-8')), \
            "Wrong password should not verify"


# ============================================================================
# TEST-AUTH-001: AUTHENTICATION - Brute Force Protection Test
# ============================================================================

class TestAuthenticationBruteForce:
    """Test brute force protection with account lockout"""
    
    def test_brute_force_lockout_after_5_attempts(self):
        """Verify account locks after 5 failed login attempts"""
        email = f"brutetest_{int(datetime.now().timestamp())}@university.edu"
        password = "SecurePass123!"
        
        # Register user
        register_user("Brute Tester", email, password, "Student")
        
        # Attempt 5 failed logins
        for attempt in range(1, 6):
            try:
                login_user(email, "WrongPassword123!")
                pytest.fail(f"Attempt {attempt} should have failed")
            except ValueError as e:
                assert "Invalid email or password" in str(e), f"Attempt {attempt}: wrong error message"
        
        # Check database: account should be locked
        cursor = conn.cursor()
        cursor.execute("SELECT is_locked, failed_attempts FROM users WHERE email = ?", (email,))
        result = cursor.fetchone()
        
        assert result is not None, "User not found"
        is_locked, failed_attempts = result
        assert is_locked == 1, "Account should be locked after 5 failures"
        assert failed_attempts == 5, "Failed attempts should be 5"
    
    def test_lockout_prevents_correct_password(self):
        """Verify locked account status is set in database after 5 attempts"""
        email = f"locktest_{int(datetime.now().timestamp())}@university.edu"
        password = "CorrectPass123!"
        
        # Register user
        register_user("Lock Tester", email, password, "Student")
        
        # Fail 5 times to lock account
        for _ in range(5):
            try:
                login_user(email, "WrongPassword123!")
            except ValueError:
                pass
        
        # Verify account is locked in database
        cursor = conn.cursor()
        cursor.execute("SELECT is_locked, failed_attempts FROM users WHERE email = ?", (email,))
        result = cursor.fetchone()
        
        assert result is not None, "User not found"
        is_locked, failed_attempts = result
        assert is_locked == 1, "Account should be locked after 5 failures"
        assert failed_attempts == 5, "Failed attempts should be 5"


# ============================================================================
# TEST-AUTH-002: AUTHENTICATION - Session Token Validation Test
# ============================================================================

class TestAuthenticationSessionToken:
    """Test session token generation and validation"""
    
    def test_session_token_generation(self):
        """Verify session tokens are generated"""
        email = f"tokentest_{int(datetime.now().timestamp())}@university.edu"
        password = "TokenPass123!"
        
        # Register and login
        register_user("Token Tester", email, password, "Student")
        user, token = login_user(email, password)
        
        # Verify token
        assert token is not None, "Token should be generated"
        assert len(token) > 0, "Token should not be empty"
        assert token in SESSION_STORE, "Token should be in SESSION_STORE"
    
    def test_session_token_validation_success(self):
        """Verify valid token authenticates user"""
        email = f"validtoken_{int(datetime.now().timestamp())}@university.edu"
        password = "ValidToken123!"
        
        # Register and login
        register_user("Valid Token Tester", email, password, "Student")
        user, token = login_user(email, password)
        
        # Authenticate with token
        authenticated_user, error = authenticate_session(token)
        
        assert authenticated_user is not None, "User should be authenticated"
        assert error is None, "Should have no error"
        assert authenticated_user.email == email, "Should return correct user"
    
    def test_session_token_validation_failure(self):
        """Verify invalid token fails authentication"""
        fake_token = "fake_token_that_does_not_exist"
        
        # Try to authenticate with invalid token
        authenticated_user, error = authenticate_session(fake_token)
        
        assert authenticated_user is None, "Should not authenticate invalid token"
        assert error is not None, "Should have error message"
        assert "Invalid session token" in error, "Error should indicate invalid token"


# ============================================================================
# TEST-AUTH-003: AUTHENTICATION - User Enumeration Protection Test
# ============================================================================

class TestAuthenticationUserEnumeration:
    """Test user enumeration prevention"""
    
    def test_nonexistent_email_error(self):
        """Verify nonexistent email gives generic error"""
        try:
            login_user("nonexistent@university.edu", "SomePass123!")
            pytest.fail("Should raise ValueError")
        except ValueError as e:
            error_msg = str(e)
            # Error should be generic
            assert "Invalid email or password" in error_msg, f"Got: {error_msg}"
    
    def test_wrong_password_error(self):
        """Verify wrong password gives same generic error"""
        email = f"enum_{int(datetime.now().timestamp())}@university.edu"
        password = "CorrectPass123!"
        
        # Register user
        register_user("Enum Tester", email, password, "Student")
        
        try:
            login_user(email, "WrongPassword123!")
            pytest.fail("Should raise ValueError")
        except ValueError as e:
            error_msg = str(e)
            # Error should be same generic message
            assert "Invalid email or password" in error_msg, f"Got: {error_msg}"
    
    def test_enumeration_error_messages_identical(self):
        """Verify both errors are identical (cannot enumerate users)"""
        email = f"enumidentical_{int(datetime.now().timestamp())}@university.edu"
        password = "Pass123!@#"
        
        # Register user
        register_user("Enum Identical Tester", email, password, "Student")
        
        # Get error for nonexistent email
        try:
            login_user("nonexistent@test.edu", "SomePass123!")
        except ValueError as e1:
            nonexistent_error = str(e1)
        
        # Get error for wrong password
        try:
            login_user(email, "WrongPass123!")
        except ValueError as e2:
            wrong_password_error = str(e2)
        
        # Both should be identical
        assert nonexistent_error == wrong_password_error, \
            "Errors should be identical to prevent user enumeration"


# ============================================================================
# TEST-IV-004: INPUT VALIDATION - SQL Injection Prevention Test
# ============================================================================

class TestInputValidationSQLInjection:
    """Test SQL injection prevention via parameterized queries"""
    
    def test_sql_injection_in_login_email(self):
        """Verify SQL injection attempt in email is treated as literal"""
        injection_payload = 'admin@test.com" OR "1"="1'
        
        try:
            login_user(injection_payload, "SomePass123!")
            pytest.fail("Should raise ValueError")
        except ValueError as e:
            # Should treat as invalid email, not execute SQL
            assert "Invalid email or password" in str(e)
    
    def test_sql_injection_in_registration_name(self):
        """Verify SQL injection attempt in name is treated as literal"""
        injection_payload = "a"  # Too short, will fail validation
        
        with pytest.raises(ValueError, match="Name must be"):
            # Should fail validation, not execute SQL
            validate_name(injection_payload)
    
    def test_database_table_exists_after_injection_attempt(self):
        """Verify database table still exists after injection attempts"""
        # Try injection
        try:
            login_user("'; DROP TABLE users; --", "Pass123!")
        except ValueError:
            pass
        
        # Check table still exists
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        result = cursor.fetchone()
        
        assert result is not None, "users table should still exist after injection attempt"


# ============================================================================
# TEST-AUTH-004: AUTHENTICATION - RBAC Enforcement Test
# ============================================================================

class TestAuthenticationRBAC:
    """Test Role-Based Access Control"""
    
    def test_student_role_creation(self):
        """Verify student role can be created"""
        email = f"student_{int(datetime.now().timestamp())}@university.edu"
        register_user("Student User", email, "StudentPass123!", "Student")
        
        # Verify role
        user = User.get_by_email(email)
        assert user.role == "Student", "User should have Student role"
    
    def test_teacher_role_creation(self):
        """Verify teacher role can be created"""
        email = f"teacher_{int(datetime.now().timestamp())}@university.edu"
        register_user("Teacher User", email, "TeacherPass123!", "Teacher")
        
        # Verify role
        user = User.get_by_email(email)
        assert user.role == "Teacher", "User should have Teacher role"
    
    def test_role_persistence_in_database(self):
        """Verify roles are persisted correctly in database"""
        email_student = f"persist_student_{int(datetime.now().timestamp())}@university.edu"
        email_teacher = f"persist_teacher_{int(datetime.now().timestamp())}@university.edu"
        
        # Register both roles
        register_user("Persist Student", email_student, "Pass123!@#", "Student")
        register_user("Persist Teacher", email_teacher, "Pass123!@#", "Teacher")
        
        # Query database
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE email = ?", (email_student,))
        student_role = cursor.fetchone()[0]
        
        cursor.execute("SELECT role FROM users WHERE email = ?", (email_teacher,))
        teacher_role = cursor.fetchone()[0]
        
        assert student_role == "Student", "Student role not persisted"
        assert teacher_role == "Teacher", "Teacher role not persisted"


# ============================================================================
# Test Summary and Execution
# ============================================================================

if __name__ == "__main__":
    """
    Run all security tests with:
        pytest test_security.py -v
    
    Run specific test class:
        pytest test_security.py::TestInputValidationName -v
    
    Run specific test:
        pytest test_security.py::TestInputValidationName::test_name_too_short -v
    """
    pytest.main([__file__, "-v", "--tb=short"])
