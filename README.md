# University Portal - Secure Access Application

A comprehensive, security-focused university portal application built with Python. This project implements advanced security mechanisms including password hashing, session management, brute-force protection, input validation, and role-based access control.

---

## 📋 Table of Contents

- [Features & Tools](#features--tools)
- [Security Metrics](#security-metrics)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [Project Structure](#project-structure)
- [User Roles](#user-roles)
- [Security Implementation Details](#security-implementation-details)
- [Testing](#testing)

---

## ✨ Features & Tools

### Core Technologies

- **Python 3.x** - Main programming language
- **SQLite3** - Lightweight, embedded database
- **Tkinter** - GUI framework for desktop application
- **bcrypt** - Secure password hashing
- **Logging** - Security event logging and auditing

### Key Features

- ✅ User Registration & Authentication
- ✅ Password Strength Validation
- ✅ Account Lockout Protection (Brute-Force Prevention)
- ✅ Session Token Management
- ✅ Role-Based Access Control (RBAC)
- ✅ Input Validation & Sanitization
- ✅ SQL Injection Prevention
- ✅ Comprehensive Security Logging
- ✅ CLI and GUI Interfaces

---

## 🔒 Security Metrics

### 1. **Password Security**

- **Minimum Length:** 10 characters
- **Required Components:** Uppercase, Lowercase, Digit, Special Character
- **Hashing Algorithm:** bcrypt with salting
- **Bcrypt Rounds:** 12 (configurable)
- **Example:** `SecurePass123!`

### 2. **Account Lockout Protection**

- **Failed Attempt Threshold:** 5 failed login attempts
- **Lockout Duration:** 15 minutes
- **Purpose:** Prevents brute-force attacks on user accounts
- **Logging:** All lockout events are recorded

### 3. **Session Management**

- **Session Token:** Cryptographically secure random tokens (32 bytes, URL-safe)
- **Session Duration:** 30 minutes (configurable)
- **Automatic Expiration:** Sessions expire after configured duration
- **Token Generation:** Uses `secrets.token_urlsafe()`

### 4. **Input Validation**

- **Name Field:** 2-50 characters only
- **Email Field:** RFC standard format validation with regex
- **Password Field:** Strength requirements (see Password Security)
- **Role Selection:** Whitelist validation against allowed roles

### 5. **Database Security**

- **SQL Injection Prevention:** Parameterized queries (prepared statements)
- **Data Integrity:** FOREIGN KEY constraints
- **User Isolation:** Email-based unique constraints
- **Timestamp Tracking:** Login attempt timestamps for lockout calculation

### 6. **Authorization & Access Control**

- **Role-Based Access Control (RBAC):** Three roles
  - **Student:** Can view assigned subjects
  - **Teacher:** Can view students and assign subjects
  - **Admin:** Full system access
- **Session Validation:** Every action requires valid session token
- **Permission Checking:** Role verification before sensitive operations

### 7. **Security Logging**

- **Event Logging:** All authentication attempts, lockouts, and errors logged
- **Log File:** Located in `logs/` directory
- **Timestamp:** All events timestamped with UTC time
- **Sensitive Data:** Passwords and tokens never logged

### 8. **Error Handling**

- **Safe Error Messages:** User-friendly messages without system details
- **No Information Leakage:** Internal errors hidden from users
- **Centralized Handling:** Consistent error response patterns

---

## 📦 Installation

### Step 1: Prerequisites

Ensure you have **Python 3.7 or higher** installed.

Check your Python version:

```bash
python --version
```

### Step 2: Clone/Download the Project

Navigate to the project directory:

```bash
cd university_portal
```

### Step 3: Install Dependencies (Automatic)

#### Option A: Using the Batch File (Windows) ⭐ **RECOMMENDED**

Simply double-click or run:

```bash
install_dependencies.bat
```

This will automatically:

- Check if Python is installed
- Upgrade pip
- Install all required dependencies from `requirements.txt`
- Display success/error messages

#### Option B: Manual Installation

If you prefer manual installation, open PowerShell/Terminal and run:

```bash
python -m pip install -r requirements.txt
```

**Note:** This project uses only Python's standard library, so there are minimal dependencies to install.

### Step 4: Configuration

Create a `.env` file in the root directory with the following content:

```ini
# Security Configuration
SECRET_KEY=your-super-secret-key-min-32-chars-12345678
DB_NAME=university_portal.db
MIN_PASSWORD_LENGTH=10
BCRYPT_ROUNDS=12

# Brute-Force Protection
LOCKOUT_THRESHOLD=5
LOCKOUT_PERIOD_SECONDS=900

# Session Management
SESSION_DURATION_MINUTES=30

# Logging
LOG_FILE=logs/university_portal.log
LOG_LEVEL=INFO

# Validation
ALLOWED_ROLES=Student,Teacher,Admin
MAX_EMAIL_LENGTH=120
MAX_NAME_LENGTH=50
```

---

## 🚀 Running the Application

### Option 1: CLI Interface (Command-Line)

Run the CLI version:

```bash
python main.py
```

You will see a menu:

```
========== University Portal ==========
1. Register
2. Login
3. Logout
4. View Profile
5. Manage Subjects (Students)
6. Assign Subjects (Teachers)
7. View Students (Teachers/Admin)
8. Exit
```

### Option 2: GUI Interface (Graphical)

Run the GUI version:

```bash
python gui.py
```

A graphical window will open with:

- Login screen
- Registration form
- Profile viewer
- Subject management interface
- User administration panel

### Step-by-Step Workflow

#### **Registration (New User)**

1. Start the application (CLI or GUI)
2. Select "Register" option
3. Enter a valid name (2-50 characters)
4. Enter a valid email (format: user@domain.com)
5. Enter a strong password with:
   - Minimum 10 characters
   - At least 1 uppercase letter
   - At least 1 lowercase letter
   - At least 1 digit
   - At least 1 special character (!@#$%^&\*)
6. Select a role (Student/Teacher/Admin)
7. Success! Account created

#### **Login**

1. Select "Login" option
2. Enter email and password
3. If credentials are correct, receive a session token
4. Session valid for 30 minutes
5. After logout or expiration, login again

#### **Account Lockout Scenario**

1. Enter incorrect password 5 times
2. Account locks for 15 minutes
3. Cannot login during lockout period
4. Can try again after 15 minutes

#### **Subject Management (Students)**

1. Login as a Student
2. View subjects assigned by Teachers
3. See assignment date and teacher name

#### **Subject Assignment (Teachers)**

1. Login as a Teacher
2. Assign subjects to students
3. Students receive assignment notifications
4. View all assigned subjects

---

## 📁 Project Structure

```
university_portal/
├── config.py                      # Configuration and environment variables
├── database.py                    # Database connection and initialization
├── gui.py                         # Tkinter GUI interface
├── logging_config.py              # Logging configuration
├── main.py                        # CLI interface
├── requirements.txt               # Project dependencies
├── SECURITY_TEST_CASES.md        # 35+ automated security tests
├── test_security.py              # Security test implementations
├── view_users.py                 # User management utilities
├── install_dependencies.bat      # Automatic installer (Windows)
│
├── auth/                         # Authentication module
│   ├── login.py                 # Login and session management
│   ├── register.py              # User registration
│   ├── validation.py            # Input validation functions
│   └── __pycache__/
│
├── models/                      # Data models
│   ├── user.py                  # User model and database operations
│   └── __pycache__/
│
├── logs/                        # Log files directory
│   └── university_portal.log   # Application log file
│
└── __pycache__/                # Python cache files
```

---

## 👥 User Roles

### **Student**

- Register and login
- View assigned subjects
- See assignment details (subject, teacher, date)
- Change password (if implemented)

### **Teacher**

- All Student features
- View list of students
- Assign subjects to students
- View assigned student list
- Manage subject assignments

### **Admin**

- All Teacher features
- User account management
- System-wide reports
- Access all user information
- System administration tasks

---

## 🔐 Security Implementation Details

### Password Hashing

- Uses **bcrypt** with configurable rounds (default 12)
- Each password salted individually
- Salting prevents rainbow table attacks
- Bcrypt automatically handles timing to prevent timing attacks

### Session Tokens

- Generated using `secrets.token_urlsafe(32)`
- Cryptographically secure random 32-byte tokens
- Stored in memory with expiration times
- Expired sessions automatically cleaned up

### Input Validation

- **Server-side validation** (not client-side only)
- Whitelist validation for roles
- Regex validation for email format
- Length and character restrictions on all inputs

### SQL Injection Prevention

- **Parameterized queries** throughout application
- No string concatenation in SQL
- Uses SQLite parameter binding (?)
- User input never directly interpolated in SQL

### Logging & Auditing

- All authentication attempts logged
- Login successes and failures recorded
- Account lockouts documented
- User role changes tracked
- Timestamp on every log entry

---

## 🧪 Testing

### Running Security Tests

Execute the automated security test suite:

```bash
python test_security.py
```

The test suite includes **35+ comprehensive tests** covering:

- Input validation (names, emails, passwords)
- Authentication (login, lockout, session)
- Authorization (role-based access)
- Database security (SQL injection prevention)
- Password strength requirements
- Session management

### Test Categories

1. **Input Validation Tests** (10 tests)
2. **Authentication Tests** (8 tests)
3. **Authorization Tests** (6 tests)
4. **Database Security Tests** (5 tests)
5. **Password Strength Tests** (4 tests)
6. **Session Management Tests** (2 tests)

See [SECURITY_TEST_CASES.md](SECURITY_TEST_CASES.md) for detailed test documentation.

---

## 🛠️ Troubleshooting

### Python not found

- Install Python from [python.org](https://www.python.org/)
- Ensure Python is added to system PATH

### Missing .env file

- Create `.env` file in the root directory with required variables
- Use the template provided above

### Database errors

- Delete `university_portal.db` to reset
- Database will recreate on next startup
- Check logs in `logs/` folder

### GUI not opening (Tkinter)

- On Windows: Should be included with Python
- On Linux: `sudo apt-get install python3-tk`
- On macOS: Included with Python installer

### Permission errors

- Run PowerShell/Terminal as Administrator
- Or navigate to project folder and run installer directly

---

## 📝 License

This project is a security demonstration for educational purposes.

---

## 🎯 Key Takeaways

✅ **Production-Ready Security:** Implements industry best practices
✅ **Comprehensive Validation:** Multi-layer input validation
✅ **Account Protection:** Brute-force and credential stuffing prevention
✅ **Secure Hashing:** Bcrypt with adaptive rounds
✅ **Session Management:** Cryptographically secure tokens
✅ **Audit Logging:** Complete security event tracking
✅ **Role-Based Access:** Fine-grained permission control
✅ **SQL Injection Prevention:** Parameterized queries throughout

---

**Happy and Secure Coding! 🔒**
