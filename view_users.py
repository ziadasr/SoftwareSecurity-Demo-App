"""
Utility script to view all registered users in the database.
"""

from database import get_db_connection

def view_all_users():
    """Display all registered users from the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, name, email, role, failed_attempts, is_locked FROM users")
        users = cursor.fetchall()
        
        if not users:
            print("\n❌ No users registered yet.")
            return
        
        print("\n" + "="*80)
        print("REGISTERED USERS IN DATABASE")
        print("="*80)
        
        for user in users:
            print(f"\nUser ID: {user['id']}")
            print(f"  Name: {user['name']}")
            print(f"  Email: {user['email']}")
            print(f"  Role: {user['role']}")
            print(f"  Failed Attempts: {user['failed_attempts']}")
            print(f"  Account Locked: {'Yes' if user['is_locked'] else 'No'}")
            print("-"*80)
        
        print(f"\nTotal Users: {len(users)}\n")
        
    except Exception as e:
        print(f"\n❌ Error retrieving users: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    view_all_users()
