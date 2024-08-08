import logging
import datetime


class SysLogger:
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

    def __init__(self, log_file='system.log'):
        logging.basicConfig(
            filename=log_file,
            level=logging.DEBUG,
            format='%(asctime)s %(levelname)s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def _log_event(self, event_category, event_action, event_status, user_id, ip_address, mac_address, details, severity):
        """Private method to handle the actual logging and audit log creation."""
        message = f"User {user_id} performed {event_category} - {event_action} with status {event_status} and details: {details} (Severity: {severity})"
        logging.log(self.SEVERITY.get(severity, 6), message)  # Default to INFO if severity is invalid
        
        # Import inside method to avoid circular import issues
        from data.models import AuditLogModel
        # Create an audit log entry
        audit_log_entry =  AuditLogModel(
            user_id=user_id,
            event_category=event_category,
            event_action=event_action,
            event_status=event_status,
            timestamp=datetime.datetime.now(),
            ip_address=ip_address,
            mac_address=mac_address,
            details=details
        )
        audit_log_entry.save()

    def log_authentication(self, user_id, status, ip_address, mac_address, details="", severity="INFO"):
        """Log an authentication event."""
        self._log_event("Authentication", "User Login", status, user_id, ip_address, mac_address, details, severity)

    def log_authorization(self, user_id, action, status, ip_address, mac_address, details="", severity="INFO"):
        """Log an authorization event."""
        self._log_event("Authorization", action, status, user_id, ip_address, mac_address, details, severity)

    def log_access(self, user_id, resource, status, ip_address, mac_address, details="", severity="INFO"):
        """Log an access event."""
        self._log_event("Access", resource, status, user_id, ip_address, mac_address, details, severity)
