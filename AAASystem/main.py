# main.py
from datetime import datetime
from data.models import AAAEvent
from logic.sys_logger import SysLogger
from logic.aaa_analyzer import AAAAnalyzer
from data.models.authorization import Authorization
from data.models.access import AccessControl
from data.models.authentication import Authentication
from data.database import DictDatabase


# Initialize the DictDatabase
database = DictDatabase()
sys_logger = SysLogger()
authenticator = Authentication(database)
authorizer = Authorization(database)
access_controller = AccessControl(database)
aaa_analyzer = AAAAnalyzer(database)

# Helper function to simulate an event and print results
def process_event(user_id, status, ip_address, mac_address, action, resource):
    # Create an AAAEvent object
    event = AAAEvent(user_id=user_id, timestamp=datetime.now(), ip_address=ip_address, mac_address=mac_address, status=status, action=action, resource=resource)

    # Log the event
    sys_logger.log_authentication(user_id, status, ip_address, mac_address, details=f"Processing event: {event}", severity="INFO")
    
    # Process authentication
    if not authenticator.verify(user_id, status, ip_address, mac_address):
        result = aaa_analyzer.process_event(event)
        print(f"Countermeasures: {result}")
    else:
        print(f"Authentication successful for {user_id}.")
        # Process authorization
        if authorizer.verify(user_id, action):
            print(f"Authorization successful for action: {action}.")
            # Process access
            if access_controller.verify_access(user_id, resource):
                print(f"Access granted to resource: {resource}.")
                # Log verified event
                database.log_verified_event(event)
            else:
                print(f"Access denied to resource: {resource}.")
                sys_logger.log_access(user_id, resource, "denied", ip_address, mac_address, severity="WARNING")
        else:
            print(f"Authorization failed for action: {action}.")
            sys_logger.log_authorization(user_id, action, "failed", ip_address, mac_address, severity="ALERT")

def display_menu():
    print("\nAAA System Menu")
    print("1. Test Admin Success")
    print("2. Test Teacher Authorization Failure")
    print("3. Test Student Access Failure")
    print("4. Test Unregistered User")
    print("5. Exit")

def main():
    while True:
        display_menu()
        choice = input("Enter your choice: ")

        if choice == '1':
            process_event('admin_user', 'success', '192.168.1.1', '00:00:00:00:00:01', 'manage_users', 'dashboard')
        elif choice == '2':
            process_event('teacher_user', 'success', '192.168.1.2', '00:00:00:00:00:02', 'edit_data', 'settings')
        elif choice == '3':
            process_event('student_user', 'success', '192.168.1.3', '00:00:00:00:00:03', 'edit_data', 'dashboard')
        elif choice == '4':
            process_event('unknown_user', 'failed', '192.168.1.4', '00:00:00:00:00:04', 'view_reports', 'dashboard')
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please select a valid option.")

        # Output logged events
        print("\nLogged Events:", database.logged_events)

if __name__ == "__main__":
    main()