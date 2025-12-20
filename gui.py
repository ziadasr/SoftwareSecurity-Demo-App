"""
University Portal GUI
A standalone tkinter interface for the secure university portal.
Imports functions from existing auth and models modules.
Does NOT modify any existing code.
Same features as main.py CLI version.
"""

import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
from auth.validation import validate_name, validate_email, validate_password_strength
from auth.register import register_user
from auth.login import login_user, authenticate_session, SESSION_STORE
from models.user import User
from database import init_db, close_db_connection
from logging_config import logger
from config import ALLOWED_ROLES, LOCKOUT_THRESHOLD


class UniversityPortalGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("University Portal - Secure Access")
        self.root.geometry("600x700")
        self.root.resizable(False, False)
        
        # Initialize database
        init_db()
        
        # Current user tracking
        self.current_user = None
        self.current_token = None
        
        # Main frame
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Show login screen by default
        self.show_login_screen()
    
    def clear_frame(self):
        """Clear all widgets from main frame"""
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def verify_session(self):
        """Verify current session is still valid"""
        if not self.current_token:
            messagebox.showerror("Session Error", "You must be logged in")
            self.show_login_screen()
            return False
        
        auth_user, error = authenticate_session(self.current_token)
        if error:
            messagebox.showerror("Session Error", error)
            self.current_user = None
            self.current_token = None
            self.show_login_screen()
            return False
        
        self.current_user = auth_user
        return True
    
    # ==================== LOGIN SCREEN ====================
    def show_login_screen(self):
        """Display login screen"""
        self.clear_frame()
        
        # Title
        title = ttk.Label(self.main_frame, text="Login", font=("Arial", 20, "bold"))
        title.pack(pady=20)
        
        # Email field
        ttk.Label(self.main_frame, text="Email:").pack(anchor=tk.W, pady=(10, 0))
        email_entry = ttk.Entry(self.main_frame, width=40)
        email_entry.pack(pady=(0, 15))
        
        # Password field
        ttk.Label(self.main_frame, text="Password:").pack(anchor=tk.W, pady=(10, 0))
        password_entry = ttk.Entry(self.main_frame, width=40, show="*")
        password_entry.pack(pady=(0, 20))
        
        # Login button
        def login_action():
            email = email_entry.get().strip()
            password = password_entry.get()
            
            if not email or not password:
                messagebox.showerror("Error", "Email and password required")
                return
            
            try:
                user, token = login_user(email, password)
                self.current_user = user
                self.current_token = token
                messagebox.showinfo("Success", f"Welcome, {user.name}!")
                self.show_dashboard()
            except ValueError as e:
                messagebox.showerror("Login Failed", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}")
        
        login_btn = ttk.Button(
            self.main_frame, 
            text="Login", 
            command=login_action,
            width=20
        )
        login_btn.pack(pady=10)
        
        # Register link
        ttk.Label(self.main_frame, text="Don't have an account?").pack(pady=10)
        register_btn = ttk.Button(
            self.main_frame,
            text="Create Account",
            command=self.show_register_screen,
            width=20
        )
        register_btn.pack(pady=5)
    
    # ==================== REGISTER SCREEN ====================
    def show_register_screen(self):
        """Display registration screen"""
        self.clear_frame()
        
        # Title
        title = ttk.Label(self.main_frame, text="Create Account", font=("Arial", 20, "bold"))
        title.pack(pady=20)
        
        # Name field
        ttk.Label(self.main_frame, text="Full Name:").pack(anchor=tk.W, pady=(10, 0))
        name_entry = ttk.Entry(self.main_frame, width=40)
        name_entry.pack(pady=(0, 15))
        
        # Email field
        ttk.Label(self.main_frame, text="Email:").pack(anchor=tk.W, pady=(10, 0))
        email_entry = ttk.Entry(self.main_frame, width=40)
        email_entry.pack(pady=(0, 15))
        
        # Password field
        ttk.Label(self.main_frame, text="Password:").pack(anchor=tk.W, pady=(10, 0))
        password_entry = ttk.Entry(self.main_frame, width=40, show="*")
        password_entry.pack(pady=(0, 5))
        ttk.Label(self.main_frame, text="(Min 10 chars, uppercase, lowercase, digit, special char)", 
                  font=("Arial", 8)).pack(anchor=tk.W)
        
        # Role selection
        ttk.Label(self.main_frame, text="Role:").pack(anchor=tk.W, pady=(15, 0))
        role_var = tk.StringVar(value="Student")
        ttk.Radiobutton(self.main_frame, text="Student", variable=role_var, value="Student").pack(anchor=tk.W)
        ttk.Radiobutton(self.main_frame, text="Teacher", variable=role_var, value="Teacher").pack(anchor=tk.W, pady=(0, 20))
        
        # Register button
        def register_action():
            name = name_entry.get().strip()
            email = email_entry.get().strip()
            password = password_entry.get()
            role = role_var.get()
            
            if not all([name, email, password]):
                messagebox.showerror("Error", "All fields required")
                return
            
            try:
                # Validate inputs
                validate_name(name)
                validate_email(email)
                validate_password_strength(password)
                
                # Register
                user = register_user(name, email, password, role)
                messagebox.showinfo("Success", f"Account created! Welcome, {user.name}")
                self.show_login_screen()
            except ValueError as e:
                messagebox.showerror("Validation Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Registration failed: {str(e)}")
        
        register_btn = ttk.Button(
            self.main_frame,
            text="Create Account",
            command=register_action,
            width=20
        )
        register_btn.pack(pady=10)
        
        # Back to login
        ttk.Button(
            self.main_frame,
            text="Back to Login",
            command=self.show_login_screen,
            width=20
        ).pack(pady=5)
    
    # ==================== DASHBOARD ====================
    def show_dashboard(self):
        """Display user dashboard with role-based menu"""
        if not self.verify_session():
            return
        
        self.clear_frame()
        
        # Title
        title = ttk.Label(
            self.main_frame,
            text=f"Dashboard - {self.current_user.name}",
            font=("Arial", 18, "bold")
        )
        title.pack(pady=15)
        
        # User info
        info_frame = ttk.LabelFrame(self.main_frame, text="User Info", padding=10)
        info_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(info_frame, text=f"Name: {self.current_user.name}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Email: {self.current_user.email}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Role: {self.current_user.role}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"ID: {self.current_user.id}").pack(anchor=tk.W)
        
        # Button frame
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        if self.current_user.role == "Student":
            self._create_student_buttons(button_frame)
        elif self.current_user.role == "Teacher":
            self._create_teacher_buttons(button_frame)
        
        # Logout button
        ttk.Button(
            self.main_frame,
            text="Logout",
            command=self.logout,
            width=30
        ).pack(pady=10)
    
    def _create_student_buttons(self, parent):
        """Create student-specific buttons"""
        ttk.Button(
            parent,
            text="📚 View Student Content",
            command=self.view_student_content,
            width=40
        ).pack(pady=5)
        
        ttk.Button(
            parent,
            text="📖 View My Subjects",
            command=self.view_my_subjects,
            width=40
        ).pack(pady=5)
    
    def _create_teacher_buttons(self, parent):
        """Create teacher-specific buttons"""
        ttk.Button(
            parent,
            text="📝 View Teacher Content",
            command=self.view_teacher_content,
            width=40
        ).pack(pady=5)
        
        ttk.Button(
            parent,
            text="✏️ Assign Subject to Student",
            command=self.assign_subject,
            width=40
        ).pack(pady=5)
        
        ttk.Button(
            parent,
            text="👥 View All Student Emails",
            command=self.view_all_students,
            width=40
        ).pack(pady=5)
    
    def view_student_content(self):
        """Show student-only content"""
        if not self.verify_session():
            return
        
        if self.current_user.role != "Student":
            messagebox.showerror("Access Denied", "Only Students can access this feature")
            logger.warning(f"Unauthorized access attempt by {self.current_user.email}")
            return
        
        messagebox.showinfo(
            "Student Content",
            "🎉 STUDENT CONTENT:\n\nAccess to your courses and grades.\n\n✓ You can view assigned subjects\n✓ Submit assignments\n✓ Check grades"
        )
        logger.info(f"Student content accessed", extra={'user_email': self.current_user.email, 'role': 'Student'})
    
    def view_teacher_content(self):
        """Show teacher-only content"""
        if not self.verify_session():
            return
        
        if self.current_user.role != "Teacher":
            messagebox.showerror("Access Denied", "Only Teachers can access this feature")
            logger.warning(f"Unauthorized access attempt by {self.current_user.email}")
            return
        
        messagebox.showinfo(
            "Teacher Content",
            "📝 TEACHER CONTENT:\n\nAccess to class rosters and grading.\n\n✓ Assign subjects to students\n✓ Grade assignments\n✓ View all students"
        )
        logger.info(f"Teacher content accessed", extra={'user_email': self.current_user.email, 'role': 'Teacher'})
    
    def view_my_subjects(self):
        """Student: View assigned subjects"""
        if not self.verify_session():
            return
        
        subjects = User.get_subjects(self.current_user.email)
        
        self.clear_frame()
        ttk.Label(self.main_frame, text="My Subjects", font=("Arial", 16, "bold")).pack(pady=10)
        
        if subjects:
            text_widget = scrolledtext.ScrolledText(self.main_frame, height=15, width=70)
            text_widget.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
            
            text_widget.insert(tk.END, "📚 YOUR ASSIGNED SUBJECTS:\n\n")
            for i, subject in enumerate(subjects, 1):
                text_widget.insert(
                    tk.END,
                    f"{i}. {subject['subject_name']}\n   Assigned by: {subject['assigned_by']}\n   Date: {subject['assigned_at']}\n\n"
                )
            text_widget.config(state=tk.DISABLED)
        else:
            ttk.Label(self.main_frame, text="❌ No subjects assigned yet.", font=("Arial", 12)).pack(pady=20)
        
        ttk.Button(
            self.main_frame,
            text="← Back to Dashboard",
            command=self.show_dashboard,
            width=30
        ).pack(pady=10)
    
    def assign_subject(self):
        """Teacher: Assign subject to student"""
        if not self.verify_session():
            return
        
        if self.current_user.role != "Teacher":
            messagebox.showerror("Access Denied", "Only Teachers can assign subjects")
            return
        
        students = User.get_all_students()
        
        if not students:
            messagebox.showerror("No Students", "❌ No students registered in the system")
            return
        
        self.clear_frame()
        
        ttk.Label(self.main_frame, text="Assign Subject to Student", font=("Arial", 16, "bold")).pack(pady=10)
        
        # Student selection
        ttk.Label(self.main_frame, text="Select Student:").pack(anchor=tk.W, pady=(10, 5))
        
        student_var = tk.StringVar()
        student_combo = ttk.Combobox(
            self.main_frame,
            textvariable=student_var,
            values=[f"{s['email']} ({s['name']})" for s in students],
            state="readonly",
            width=50
        )
        student_combo.pack(pady=(0, 15))
        
        # Subject selection
        ttk.Label(self.main_frame, text="Select Subject:").pack(anchor=tk.W, pady=(10, 5))
        
        subjects_list = ["Mathematics", "Physics", "Computer Science", "English"]
        subject_var = tk.StringVar()
        subject_combo = ttk.Combobox(
            self.main_frame,
            textvariable=subject_var,
            values=subjects_list,
            state="readonly",
            width=50
        )
        subject_combo.pack(pady=(0, 20))
        
        def assign_action():
            if not student_var.get() or not subject_var.get():
                messagebox.showerror("Error", "Please select both student and subject")
                return
            
            try:
                student_email = student_var.get().split(" ")[0]
                subject_name = subject_var.get()
                
                User.assign_subject(student_email, subject_name, self.current_user.email)
                messagebox.showinfo("Success", f"✅ Subject '{subject_name}' assigned to {student_email}")
                self.show_dashboard()
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        
        ttk.Button(
            self.main_frame,
            text="Assign Subject",
            command=assign_action,
            width=30
        ).pack(pady=10)
        
        ttk.Button(
            self.main_frame,
            text="← Back to Dashboard",
            command=self.show_dashboard,
            width=30
        ).pack(pady=5)
    
    def view_all_students(self):
        """Teacher: View all registered students"""
        if not self.verify_session():
            return
        
        if self.current_user.role != "Teacher":
            messagebox.showerror("Access Denied", "Only Teachers can view all students")
            return
        
        students = User.get_all_students()
        
        self.clear_frame()
        ttk.Label(self.main_frame, text="All Registered Students", font=("Arial", 16, "bold")).pack(pady=10)
        
        if students:
            text_widget = scrolledtext.ScrolledText(self.main_frame, height=15, width=70)
            text_widget.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
            
            text_widget.insert(tk.END, "👥 ALL REGISTERED STUDENTS:\n\n")
            for i, student in enumerate(students, 1):
                text_widget.insert(tk.END, f"{i}. {student['email']} ({student['name']})\n")
            text_widget.config(state=tk.DISABLED)
        else:
            ttk.Label(self.main_frame, text="❌ No students registered in the system", font=("Arial", 12)).pack(pady=20)
        
        ttk.Button(
            self.main_frame,
            text="← Back to Dashboard",
            command=self.show_dashboard,
            width=30
        ).pack(pady=10)
    
    def logout(self):
        """Logout user"""
        if self.current_token and self.current_token in SESSION_STORE:
            del SESSION_STORE[self.current_token]
        
        if self.current_user:
            logger.info("User logged out.", extra={'user_email': self.current_user.email})
        
        self.current_user = None
        self.current_token = None
        messagebox.showinfo("Logout", "You have been logged out successfully")
        self.show_login_screen()


def main():
    root = tk.Tk()
    app = UniversityPortalGUI(root)
    
    def on_closing():
        """Handle window close event"""
        close_db_connection()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
