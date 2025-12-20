import os
import sys
# Import from sister modules/packages
from auth.register import register_user
from auth.login import login_user, authenticate_session
from models.user import User
from database import close_db_connection
from logging_config import logger # Assuming you created this file as recommended
from config import LOCKOUT_THRESHOLD

def get_input(prompt, is_secret=False):
    # Helper for reading input, safely handling passwords.
    if is_secret:
        import getpass
        return getpass.getpass(prompt)
    return input(prompt).strip()

def run_portal():
    # Simple command-line interface to demonstrate the portal's functionality.
    current_session_token = None
    current_user = None

    def enforce_auth(required_role=None):
        # Checks session token and RBAC.
        #Allows this nested function to modify the parent function's variable
        nonlocal current_session_token 
        nonlocal current_user
        
        if not current_session_token:
            print("\n❌ Error: You must be logged in to access this feature.")
            return False
        #authenticate_session returns two values: a user object and an error message (if any)
        user, error = authenticate_session(current_session_token)
        
        if error:
            print(f"\n❌ Error: {error}")
            
            # The session is invalid/expired, so clear the local state
            current_session_token = None
            current_user = None
            return False

        current_user = user
        # Teachers have access to all features
        if required_role and current_user.role == "Teacher":
            return True
        

        if required_role and current_user.role != required_role:
            logger.warning(
                f"Access denied. User '{current_user.email}' (Role: {current_user.role}) attempted to access '{required_role}' feature.",
                extra={'user_email': current_user.email, 'role': current_user.role}
            )
            print(f"\n❌ Access Denied. Only {required_role}s can view this.")
            return False
        
        logger.info(
            f"Access granted to feature for user.",
            extra={'user_email': current_user.email, 'role': current_user.role}
        )
        return True

    while True:
        print("\n--- University Portal (Secure Demo) ---")
        if current_user:
            print(f"Logged in as: **{current_user.email}** ({current_user.role})")
        else:
            print("Status: Logged Out")
        
        if not current_user:
            # Menu for logged-out users
            print("\n[1] Register New User")
            print("[2] Login")
            print("[0] Exit")
        else:
            # Menu for logged-in users (role-specific)
            if current_user.role == "Student":
                # Student Menu
                # print("\n[3] View Student Content (Student Role Only)")=================================
                print("[4] View My Subjects")
                print("[5] Logout")
            elif current_user.role == "Teacher":
                # Teacher Menu
                # print("\n[3] View Teacher Content (Teacher Role Only)") ============================
                print("[4] Assign Subject to Student")
                print("[5] View All Student Emails")
                print("[6] Logout")
            print("[0] Exit")
        
        choice = get_input("Enter your choice: ")
        
        try:
            if choice == '1':
                print("\n--- Registration ---")
                
                # Validate Name
                name_valid = False
                while not name_valid:
                    try:
                        from auth.validation import validate_name
                        name = get_input("Name: ")
                        validate_name(name)
                        name_valid = True
                    except ValueError as e:
                        print(f"\n❌ Error: {e}")
                
                # Validate Email
                email_valid = False
                while not email_valid:
                    try:
                        from auth.validation import validate_email
                        email = get_input("University Email: ")
                        validate_email(email)
                        if User.get_by_email(email):
                            raise ValueError("A user with this email already exists.")
                        email_valid = True
                    except ValueError as e:
                        print(f"\n❌ Error: {e}")
                
                # Validate Role
                role_valid = False
                while not role_valid:
                    try:
                        from config import ALLOWED_ROLES
                        print("\nSelect Role:")
                        for i, r in enumerate(ALLOWED_ROLES, 1):
                            print(f"[{i}] {r}")
                        role_choice = get_input("Enter your choice: ").strip()
                        
                        if role_choice.isdigit() and 1 <= int(role_choice) <= len(ALLOWED_ROLES):
                            role = ALLOWED_ROLES[int(role_choice) - 1]
                            role_valid = True
                        else:
                            raise ValueError(f"Invalid choice. Please select 1-{len(ALLOWED_ROLES)}")
                    except ValueError as e:
                        print(f"\n❌ Error: {e}")
                
                # Validate Password
                password_valid = False
                while not password_valid:
                    try:
                        from auth.validation import validate_password_strength
                        password = get_input("Password (min 10 chars, strong): ", is_secret=True)
                        validate_password_strength(password)
                        user = register_user(name, email, password, role)
                        print(f"\n✅ User '{user.email}' registered successfully as {user.role}.")
                        password_valid = True
                    except ValueError as e:
                        print(f"\n❌ Error: {e}")

            elif choice == '2':
                print("\n--- Login ---")
                email = get_input("University Email: ")
                
                retry = True
                while retry:
                    try:
                        password = get_input("Password: ", is_secret=True)
                        user, token = login_user(email, password)
                        current_session_token = token
                        current_user = user
                        print(f"\n✅ Welcome {user.name} and then ({user.role}). Session Token: {token[:8]}...")
                        print(f"   (Max {LOCKOUT_THRESHOLD} failed attempts before lockout!)")
                        retry = False
                    except ValueError as e:
                        print(f"\n❌ Error: {e}")
                        retry_choice = get_input("Try another password? (yes/no): ").lower()
                        retry = retry_choice in ['yes', 'y']
                        if not retry:
                            email = get_input("Or enter a different email (or press Enter to go back): ").strip()
                            if email:
                                retry = True
                            else:
                                break

            elif choice == '3':
                if current_user.role == "Student":
                    if enforce_auth(required_role="Student"):
                        print("\n🎉 STUDENT CONTENT: Access to your courses and grades.")
                elif current_user.role == "Teacher":
                    if enforce_auth(required_role="Teacher"):
                        print("\n📝 TEACHER CONTENT: Access to class rosters and grading interface.")
            
            elif choice == '4':
                if current_user.role == "Student":
                    # View My Subjects
                    if enforce_auth():
                        subjects = User.get_subjects(current_user.email)
                        if subjects:
                            print("\n📚 YOUR SUBJECTS:")
                            for i, subject in enumerate(subjects, 1):
                                print(f"{i}. {subject['subject_name']} (Assigned by: {subject['assigned_by']})")
                        else:
                            print("\n❌ No subjects assigned yet.")
                
                elif current_user.role == "Teacher":
                    # Assign Subject to Student
                    if enforce_auth():
                        print("\n--- Assign Subject to Student ---")
                        
                        # Get all students
                        students = User.get_all_students()
                        if not students:
                            print("❌ No students registered in the system.")
                        else:
                            # Display list of students
                            print("\nAvailable Students:")
                            for i, student in enumerate(students, 1):
                                print(f"[{i}] {student['email']} ({student['name']})")
                            
                            student_choice = get_input("Select student (enter number): ").strip()
                            
                            if student_choice.isdigit() and 1 <= int(student_choice) <= len(students):
                                selected_student = students[int(student_choice) - 1]
                                student_email = selected_student['email']
                                
                                # Display list of subjects
                                print("\nAvailable Subjects:")
                                subjects_list = ["Mathematics", "Physics", "Computer Science", "English"]
                                for i, subj in enumerate(subjects_list, 1):
                                    print(f"[{i}] {subj}")
                                
                                subject_choice = get_input("Select subject (1-4): ").strip()
                                
                                try:
                                    if subject_choice.isdigit() and 1 <= int(subject_choice) <= 4:
                                        subject_name = subjects_list[int(subject_choice) - 1]
                                        User.assign_subject(student_email, subject_name, current_user.email)
                                        print(f"\n✅ Subject '{subject_name}' assigned to {student_email}")
                                    else:
                                        print("\n❌ Invalid subject selection.")
                                except ValueError as e:
                                    print(f"\n❌ Error: {e}")
                            else:
                                print("\n❌ Invalid student selection.")
            
            elif choice == '5':
                if current_user.role == "Teacher":
                    # View All Student Emails
                    if enforce_auth():
                        students = User.get_all_students()
                        if students:
                            print("\n👥 ALL REGISTERED STUDENTS:")
                            for i, student in enumerate(students, 1):
                                print(f"{i}. {student['email']} ({student['name']})")
                        else:
                            print("\n❌ No students registered in the system.")
                
                elif current_user.role == "Student":
                    # Logout for Student
                    print(f"\n🚪 Logged out: {current_user.email}")
                    logger.info("User logged out.", extra={'user_email': current_user.email})
                    current_session_token = None
                    current_user = None
            
            elif choice == '6' and current_user and current_user.role == "Teacher":
                # Logout for Teacher
                print(f"\n🚪 Logged out: {current_user.email}")
                logger.info("User logged out.", extra={'user_email': current_user.email})
                current_session_token = None
                current_user = None

            elif choice == '0':
                print("Shutting down portal.")
                close_db_connection()
                sys.exit(0)

            elif choice not in ['1', '2'] and not current_user:
                 print("\n❌ Invalid choice or command requires login.")

            elif choice in ['3', '4', '5'] and not current_user:
                 print("\n❌ Please login first.")

        except ValueError as e:
            # Centralized Error Handling for user-facing errors (validation, login failure)
            print(f"\n❌ ERROR: {e}")
        except Exception as e:
            # Centralized Error Handling for unexpected errors (safe message only)
            print("\n❌ An unexpected system error occurred. Check logs for details.")
            logger.error(f"FATAL APPLICATION ERROR: {e}", exc_info=True)


if __name__ == "__main__":
    # Ensure all modules are loaded and setup is complete before running
    import config 
    import database
    import logging_config
    
    run_portal()