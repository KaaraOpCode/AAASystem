# logic/aaa_analyzer.py
from data.models import Authentication, Authorization, Access
from logic.sys_logger import SysLogger  # Ensure correct import path

class AAAAnalyzer:
    def __init__(self, database):
        self.authenticator = Authentication(database)
        self.authorizer = Authorization(database)
        self.access_controller = Access(database)
        self.logger = SysLogger()  # Initialize SysLogger

    def analyze_failed_event(self, event):
        failed_attempts = self.authenticator.database.get_failed_attempts(event.user_id)
        known_ip = self.authenticator.database.is_known_ip(event.ip_address)
        known_mac = self.authenticator.database.is_known_mac(event.mac_address)
        
        return {
            "failed_attempts": failed_attempts,
            "known_ip": known_ip,
            "known_mac": known_mac
        }

    def propose_countermeasures(self, analysis_result):
        countermeasures = []
        
        if analysis_result["failed_attempts"] > 3:
            countermeasures.append("Lock account (Severity: ALERT)")
        
        if not analysis_result["known_ip"]:
            countermeasures.append("Flag IP address for review (Severity: WARNING)")
        
        if not analysis_result["known_mac"]:
            countermeasures.append("Deny access from unknown MAC address (Severity: CRITICAL)")
        
        return countermeasures

    def process_event(self, event):
        self.logger.log_authentication(event.user_id, event.status, event.ip_address, event.mac_address, details=f"Processing event: {event}", severity="INFO")

        if not self.authenticator.verify(event.user_id, event.status, event.ip_address, event.mac_address):
            self.logger.log_authentication(event.user_id, "failed", event.ip_address, event.mac_address, details="Authentication failed.", severity="ERROR")
            analysis_result = self.analyze_failed_event(event)
            countermeasures = self.propose_countermeasures(analysis_result)
            self.logger.log_authentication(event.user_id, "failed", event.ip_address, event.mac_address, details=f"Countermeasures: {countermeasures}", severity="ALERT")
            return countermeasures

        if not self.authorizer.verify(event.user_id, event.action, event.status, event.ip_address, event.mac_address):
            self.logger.log_authorization(event.user_id, event.action, "failed", event.ip_address, event.mac_address, details="Authorization failed.", severity="ERROR")
            analysis_result = self.analyze_failed_event(event)
            countermeasures = self.propose_countermeasures(analysis_result)
            self.logger.log_authorization(event.user_id, event.action, "failed", event.ip_address, event.mac_address, details=f"Countermeasures: {countermeasures}", severity="ALERT")
            return countermeasures

        if not self.access_controller.verify(event.user_id, event.resource, event.status, event.ip_address, event.mac_address):
            self.logger.log_access(event.user_id, event.resource, "failed", event.ip_address, event.mac_address, details="Access control failed.", severity="ERROR")
            analysis_result = self.analyze_failed_event(event)
            countermeasures = self.propose_countermeasures(analysis_result)
            self.logger.log_access(event.user_id, event.resource, "failed", event.ip_address, event.mac_address, details=f"Countermeasures: {countermeasures}", severity="ALERT")
            return countermeasures
        
        self.authenticator.database.log_verified_event(event)
        self.logger.log_access(event.user_id, event.resource, "success", event.ip_address, event.mac_address, details="Logged verified event.", severity="INFO")
        return None
