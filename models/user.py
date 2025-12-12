import sqlite3
from database import get_db_connection
from logging_config import logger
import config

class User:
    def __init__(self, name, email, role, password_hash=None, failed_attempts=0, is_locked=False, id=None):
        self.id = id
        self.name = name
        self.email = email
        self.role = role
        self.password_hash = password_hash
        self.failed_attempts = failed_attempts
        self.is_locked = is_locked

    @staticmethod
    def get_by_email(email):
        conn = get_db_connection()
        cursor = conn.cursor()
        # Parameterized Query to prevent SQL Injection
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user_row = cursor.fetchone()#gets the first row of the result
        
        if user_row:
            return User(
                id=user_row['id'],
                name=user_row['name'],
                email=user_row['email'],
                password_hash=user_row['password_hash'],
                role=user_row['role'],
                failed_attempts=user_row['failed_attempts'],
                is_locked=user_row['is_locked']
            )
        return None

    def save(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Parameterized Query for secure insertion
            cursor.execute("""
                INSERT INTO users (name, email, password_hash, role) 
                VALUES (?, ?, ?, ?)
            """, (self.name, self.email, self.password_hash, self.role))
            conn.commit()
            #automatically get the assigned id
            self.id = cursor.lastrowid
            logger.info("New user registered successfully.", extra={'user_email': self.email, 'role': self.role})
            # check if not NUll catchet
        except sqlite3.IntegrityError: 
            logger.warning("Registration failed: Email already exists.", extra={'user_email': self.email})
            # Raise an application-specific error instead of DB error
            raise ValueError("Registration failed: Email already exists.") 

    def update_login_state(self, is_success=True, last_attempt_time=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        if is_success:
            self.failed_attempts = 0
            self.is_locked = False
        else:
            self.failed_attempts += 1
            if self.failed_attempts >= config.LOCKOUT_THRESHOLD:
                self.is_locked = True
                logger.warning(
                    f"Account locked due to {self.failed_attempts} failed attempts.",
                    extra={'user_email': self.email}
                )

        # Update the database securely
        cursor.execute("""
            UPDATE users SET failed_attempts = ?, is_locked = ?, last_login_attempt = ?
            WHERE email = ?
        """, (self.failed_attempts, self.is_locked, last_attempt_time, self.email))
        conn.commit()

    @staticmethod
    def assign_subject(student_email, subject_name, teacher_email):
        # Allowed subjects
        ALLOWED_SUBJECTS = ["Mathematics", "Physics", "Computer Science", "English"]
        
        # Validate subject
        if subject_name not in ALLOWED_SUBJECTS:
            raise ValueError(f"Invalid subject. Allowed: {', '.join(ALLOWED_SUBJECTS)}")
        
        # Verify student exists and is a Student
        student = User.get_by_email(student_email)
        if not student:
            raise ValueError("Student email not found.")
        if student.role != "Student":
            raise ValueError("Can only assign subjects to Student role users.")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO subjects (student_email, subject_name, assigned_by)
                VALUES (?, ?, ?)
            """, (student_email, subject_name, teacher_email))
            conn.commit()
            logger.info(
                f"Subject assigned successfully.",
                extra={'teacher': teacher_email, 'student': student_email, 'subject': subject_name}
            )
        except Exception as e:
            if "UNIQUE constraint failed" in str(e):
                raise ValueError(f"Subject '{subject_name}' already assigned to this student.")
            logger.error(f"Subject assignment error: {e}")
            raise ValueError("Error assigning subject.")

    @staticmethod
    def get_subjects(student_email):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT subject_name, assigned_by, assigned_at FROM subjects
            WHERE student_email = ?
            ORDER BY assigned_at DESC
        """, (student_email,))
        subjects = cursor.fetchall()
        return subjects if subjects else []

    @staticmethod
    def get_all_students():
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, name, email FROM users
            WHERE role = 'Student'
            ORDER BY name ASC
        """)
        students = cursor.fetchall()
        return students if students else []

from auth import validation # Imported here to avoid circular dependency
from config import LOCKOUT_THRESHOLD