import logging
import datetime
import os

from data.dict_database import DictDatabase
from data.models.audit_log import AuditLog 

class SysLogger:
    # Mapping of severity levels to their respective numeric values
    SEVERITY = {
        "EMERGENCY": 0,
        "ALERT": 1,
        "CRITICAL": 2,
        "ERROR": 3,
        "WARNING": 4,
        "NOTICE": 5,
        "INFO": 6,
        "DEBUG": 7
    }

    def __init__(self, database: DictDatabase, log_file='system.log'):
        """
        Initializes the SysLogger with the given database and log file.

        Args:
            database (DictDatabase): The database instance to store audit logs.
            log_file (str): The filename for the log file. Defaults to 'system.log'.
        """
        self.database = database
        
        log_file_path = os.path.join(os.path.dirname(__file__), log_file)
        logging.basicConfig(
            filename=log_file_path,
            level=logging.DEBUG,
            format='%(asctime)s %(levelname)s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def log_event(self, event_category, event_action, event_status, user_id, ip_address, mac_address, details, severity):
        """
        Handles the actual logging and audit log creation.

        Args:
            event_category (str): The category of the event (e.g., "Authentication").
            event_action (str): The action performed (e.g., "User Login").
            event_status (str): The status of the event (e.g., "success" or "failed").
            user_id (str): The ID of the user associated with the event.
            ip_address (str): The IP address from which the event originated.
            mac_address (str): The MAC address from which the event originated.
            details (str): Additional details about the event.
            severity (str): The severity level of the event.
        """
        # Construct the log message
        message = (
            f"User {user_id} performed {event_category} - {event_action} "
            f"with status {event_status} and details: {details} (Severity: {severity})"
        )
        
        # Log the message with the appropriate severity level
        logging.log(self.SEVERITY.get(severity, 6), message)  # Default to INFO if severity is invalid
        
        # Create an audit log entry
        audit_log_entry = AuditLog(
            user_id=user_id,
            event_category=event_category,
            event_action=event_action,
            event_status=event_status,
            timestamp=datetime.datetime.now(),
            ip_address=ip_address,
            mac_address=mac_address,
            details=details
        )
        
        # Store the log entry in DictDatabase
        self.database.log_verified_event(audit_log_entry)  # Adjust based on your DictDatabase method

    def log_authentication(self, user_id, status, ip_address, mac_address, details="", severity="INFO"):
        """
        Logs an authentication event.

        Args:
            user_id (str): The ID of the user attempting authentication.
            status (str): The result of the authentication attempt (e.g., "success" or "failed").
            ip_address (str): The IP address from which the authentication attempt was made.
            mac_address (str): The MAC address from which the authentication attempt was made.
            details (str): Additional details about the authentication event. Defaults to an empty string.
            severity (str): The severity level of the event. Defaults to "INFO".
        """
        self._log_event("Authentication", "User Login", status, user_id, ip_address, mac_address, details, severity)

    def log_authorization(self, user_id, action, status, ip_address, mac_address, details="", severity="INFO"):
        """
        Logs an authorization event.

        Args:
            user_id (str): The ID of the user for whom authorization was checked.
            action (str): The action that was authorized or denied.
            status (str): The result of the authorization attempt (e.g., "success" or "failed").
            ip_address (str): The IP address from which the authorization attempt was made.
            mac_address (str): The MAC address from which the authorization attempt was made.
            details (str): Additional details about the authorization event. Defaults to an empty string.
            severity (str): The severity level of the event. Defaults to "INFO".
        """
        self._log_event("Authorization", action, status, user_id, ip_address, mac_address, details, severity)

    def log_access(self, user_id, resource, status, ip_address, mac_address, details="", severity="INFO"):
        """
        Logs an access event.

        Args:
            user_id (str): The ID of the user attempting to access a resource.
            resource (str): The resource the user attempted to access.
            status (str): The result of the access attempt (e.g., "success" or "failed").
            ip_address (str): The IP address from which the access attempt was made.
            mac_address (str): The MAC address from which the access attempt was made.
            details (str): Additional details about the access event. Defaults to an empty string.
            severity (str): The severity level of the event. Defaults to "INFO".
        """
        self._log_event("Access", resource, status, user_id, ip_address, mac_address, details, severity)
