from data.models import Authentication, Authorization, AccessControl
from logic.sys_logger import SysLogger
from data.dict_database import DictDatabase
from datetime import datetime

class AAAAnalyzer:
    def __init__(self, database: DictDatabase, log_file):
        """
        Initializes the AAAAnalyzer with the given database and log file.

        Args:
            database (DictDatabase): The database instance for authentication, authorization, and access control.
            log_file (str): The path to the log file where events will be logged.
        """
        self.authenticator = Authentication(database)
        self.authorizer = Authorization(database)
        self.access_controller = AccessControl(database)
        self.logger = SysLogger(database, log_file)  
        self.database = database  

    def analyze_failed_event(self, event):
        """
        Analyzes a failed event to gather information about failed attempts, known IPs, and known MAC addresses.

        Args:
            event (AAAEvent): The event to analyze.

        Returns:
            dict: A dictionary containing the number of failed attempts, and whether
                  the IP and MAC address are known.
        """
        failed_attempts = self.authenticator.database.get_failed_attempts(event.user_id)
        known_ip = self.authenticator.database.is_known_ip(event.ip_address)
        known_mac = self.authenticator.database.is_known_mac(event.mac_address)
        
        return {
            "failed_attempts": failed_attempts,
            "known_ip": known_ip,
            "known_mac": known_mac
        }

    def propose_countermeasures(self, analysis_result):
        """
        Proposes countermeasures based on the analysis result of a failed event.

        Args:
            analysis_result (dict): The result of the failed event analysis.

        Returns:
            list: A list of proposed countermeasures based on the analysis.
        """
        countermeasures = []
        
        if analysis_result["failed_attempts"] > 3:
            countermeasures.append("Lock account (Severity: ALERT)")
        
        if not analysis_result["known_ip"]:
            countermeasures.append("Flag IP address for review (Severity: WARNING)")
        
        if not analysis_result["known_mac"]:
            countermeasures.append("Deny access from unknown MAC address (Severity: CRITICAL)")
        
        return countermeasures

    def process_event(self, event):
        # Step 1: Authentication
        if not self._authenticate_event(event):
            return ['Authentication failed']

        # Step 2: Authorization
        if not self._authorize_event(event):
            return ['Authorization failed']

        # Step 3: Access Control
        if not self._access_control_event(event):
            return ['Access denied']

        return None
    
    def _authenticate_event(self, event):
        authenticated = self.authenticator.verify(
            event.user_id, event.status, event.ip_address, event.mac_address
        )
        if authenticated:
            self._log_authentication_success(event)
        else:
            self._log_authentication_failure(event)
        
        return authenticated

    def _authorize_event(self, event):
        authorized = self.authorizer.verify(event.user_id, event.action)
        if authorized:
            self._log_authorization_success(event)
        else:
            self._log_authorization_failure(event)
        
        return authorized

    def _access_control_event(self, event):
        access_granted = self.access_controller.verify(event.user_id, event.resource)
        if access_granted:
            self._log_access_control_success(event)
        else:
            self._log_access_control_failure(event)
        
        return access_granted
    
    def _log_authentication_success(self, event):
        self.logger.log_event(
            event_category='Authentication',
            event_action='User Login',
            event_status='success',
            user_id=event.user_id,
            ip_address=event.ip_address,
            mac_address=event.mac_address,
            details='User authenticated successfully.',
            severity='INFO'
        )

    def _log_authentication_failure(self, event):
        self.logger.log_event(
            event_category='Authentication',
            event_action='User Login',
            event_status='failed',
            user_id=event.user_id,
            ip_address=event.ip_address,
            mac_address=event.mac_address,
            details='Authentication failed due to unrecognized IP or MAC address.',
            severity='WARNING'
        )

    def _log_authorization_success(self, event):
        self.logger.log_event(
            event_category='Authorization',
            event_action=event.action,
            event_status='success',
            user_id=event.user_id,
            ip_address=event.ip_address,
            mac_address=event.mac_address,
            details='User authorized successfully for action.',
            severity='INFO'
        )

    def _log_authorization_failure(self, event):
        self.logger.log_event(
            event_category='Authorization',
            event_action=event.action,
            event_status='failed',
            user_id=event.user_id,
            ip_address=event.ip_address,
            mac_address=event.mac_address,
            details='Authorization failed due to insufficient permissions.',
            severity='WARNING'
        )

    def _log_access_control_success(self, event):
        self.logger.log_event(
            event_category='Access Control',
            event_action=event.resource,
            event_status='success',
            user_id=event.user_id,
            ip_address=event.ip_address,
            mac_address=event.mac_address,
            details='Access granted to resource successfully.',
            severity='INFO'
        )

    def _log_access_control_failure(self, event):
        self.logger.log_event(
            event_category='Access Control',
            event_action=event.resource,
            event_status='failed',
            user_id=event.user_id,
            ip_address=event.ip_address,
            mac_address=event.mac_address,
            details='Access control failed due to denied resource access.',
            severity='WARNING'
        )