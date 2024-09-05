from datetime import datetime
from logic.sys_logger import SysLogger
from logic.aaa_analyzer import AAAAnalyzer
from data.models.authorization import Authorization
from data.models.access_control import AccessControl
from data.models.authentication import Authentication
from data.models import AAAEvent
from data.dict_database import DictDatabase

def initialize_database():
    database = DictDatabase()

    # Example data setup for the database
    database.user_roles = {
        'admin_user': 'admin',
        'teacher_user': 'teacher',
        'student_user': 'student',
        'unknown_user': None
    }

    database.user_permissions = {
        'admin_user': ['manage_users', 'view_reports', 'edit_data', 'dashboard'],
        'teacher_user': ['edit_data', 'dashboard'],
        'student_user': ['view_reports', 'dashboard'],
        'unknown_user': []
    }

    database.add_known_ip('192.168.1.1')
    database.add_known_ip('192.168.1.2')
    database.add_known_mac('00:00:00:00:00:01')
    database.add_known_mac('00:00:00:00:00:02')

    database.add_resource_access('admin', ['manage_users', 'view_reports', 'edit_data', 'dashboard'])
    database.add_resource_access('teacher', ['edit_data', 'dashboard'])
    database.add_resource_access('student', ['view_reports', 'dashboard'])

    return database

def initialize_sys_logger(database, log_file):
    return SysLogger(database, log_file)

def initialize_aaa_analyzer(database, log_file):
    return AAAAnalyzer(database, log_file)

def process_event(database, user_id, status, ip_address, mac_address, action=None, resource=None):
    event = AAAEvent(
        user_id=user_id,
        timestamp=datetime.now(),
        ip_address=ip_address,
        mac_address=mac_address,
        status=status,
        action=action,
        resource=resource
    )

    aaa_analyzer = initialize_aaa_analyzer(database, 'system.log')
    countermeasures = aaa_analyzer.process_event(event)
    if action == 'login':
        if status == 'success':
            print(f"Authentication successful for {user_id}.")
        else:
            print(f"Authentication failed for {user_id}.")
    elif action == 'access':
        if status == 'success':
            print(f"Authorization successful for {user_id} to access {resource}.")
        else:
            print(f"Authorization failed for {user_id} to access {resource}.")
    if countermeasures:
                print(f"Countermeasures: {countermeasures}")

def admin_process_event(database, user_id, status, ip_address, mac_address, action=None, resource=None):
    process_event(database, user_id, status, ip_address, mac_address, action, resource)

def teacher_process_event(database, user_id, status, ip_address, mac_address, action=None, resource=None):
    process_event(database, user_id, status, ip_address, mac_address, action, resource)

def student_process_event(database, user_id, status, ip_address, mac_address, action=None, resource=None):
    process_event(database, user_id, status, ip_address, mac_address, action, resource)

def unknown_process_event(database, user_id, status, ip_address, mac_address, action=None, resource=None):
    process_event(database, user_id, status, ip_address, mac_address, action, resource)
    
def display_menu():
    print("\nAAA System Menu:")
    print("1. Admin Scenarios")
    print("2. Teacher Scenarios")
    print("3. Student Scenarios")
    print("4. Unknown User Scenarios")
    print("5. View Logs")
    print("6. Exit")

def view_logs(database):
    if database.logged_events:
        print("\nLogged Events:")
        for event in database.logged_events:
            print(event)
    else:
        print("\nNo logged events.")

def main():
    database = initialize_database()
    sys_logger = initialize_sys_logger(database, 'system.log')
    previous_logged_events = []

    while True:
        display_menu()
        choice = input("Enter your choice: ")

        if choice == '1':
            # Admin Scenarios
            print("Admin Scenarios:")
            admin_process_event(database, 'admin_user', 'success', '192.168.1.1', '00:00:00:00:00:01', 'login')
            admin_process_event(database, 'admin_user', 'success', '192.168.1.1', '00:00:00:00:00:01', 'access', 'manage_users')
            admin_process_event(database, 'admin_user', 'success', '192.168.1.1', '00:00:00:00:00:01', 'access', 'dashboard')
            admin_process_event(database, 'admin_user', 'failed', '192.168.1.6', '00:00:00:00:00:01', 'login')
            admin_process_event(database, 'admin_user', 'failed', '192.168.1.1', '00:00:00:00:00:06', 'access', 'manage_users')
        elif choice == '2':
            # Teacher Scenarios
            print("Teacher Scenarios:")
            teacher_process_event(database, 'teacher_user', 'success', '192.168.1.2', '00:00:00:00:00:02', 'login')
            teacher_process_event(database, 'teacher_user', 'success', '192.168.1.2', '00:00:00:00:00:02', 'access', 'edit_data')
            teacher_process_event(database, 'teacher_user', 'success', '192.168.1.2', '00:00:00:00:00:02', 'access', 'dashboard')
            teacher_process_event(database, 'teacher_user', 'failed', '192.168.1.7', '00:00:00:00:00:02', 'login')
            teacher_process_event(database, 'teacher_user', 'failed', '192.168.1.2', '00:00:00:00:00:07', 'access', 'edit_data')
        elif choice == '3':
            # Student Scenarios
            print("Student Scenarios:")
            student_process_event(database, 'student_user', 'success', '192.168.1.3', '00:00:00:00:00:03', 'login')
            student_process_event(database, 'student_user', 'success', '192.168.1.3', '00:00:00:00:00:03', 'access', 'view_reports')
            student_process_event(database, 'student_user', 'success', '192.168.1.3', '00:00:00:00:00:03', 'access', 'dashboard')
            student_process_event(database, 'student_user', 'failed', '192.168.1.8', '00:00:00:00:00:03', 'login')
            student_process_event(database, 'student_user', 'failed', '192.168.1.3', '00:00:00:00:00:08', 'access', 'view_reports')
        elif choice == '4':
            # Unknown User Scenarios
            print("Unknown User Scenarios:")
            unknown_process_event(database, 'unknown_user', 'failed', '192.168.1.4', '00:00:00:00:00:04', 'login')
            unknown_process_event(database, 'unknown_user', 'failed', '192.168.1.9', '00:00:00:00:00:04', 'access', 'view_reports')
            unknown_process_event(database, 'unknown_user', 'failed', '192.168.1.4', '00:00:00:00:00:09', 'access', 'dashboard')
        elif choice == '5':
            # View Logs
            view_logs(database)
        elif choice == '6':
            # Exit
            print("Exiting the system.")
            break
        else:
            print("Invalid choice. Please choose a valid option.")
            
if __name__ == "__main__":
    main()