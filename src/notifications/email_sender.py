# Email Notification Module

import json
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class EmailSender:
    """Email notification service with configuration, error handling, and templating."""
    
    def __init__(self, config_path: str = "config/email_config.json"):
        """Initialize with configuration file path."""
        self.config = self._load_configuration(config_path)
        self.template_dir = self.config.get("template_dir", "templates/email")
        
    def _load_configuration(self, config_path: str) -> Dict:
        """Load configuration from JSON file with error handling."""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_path}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            return {}
        
    def _load_template(self, template_name: str) -> Optional[str]:
        """Load email template from file."""
        template_path = f"{self.template_dir}/{template_name}.html"
        try:
            with open(template_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            logger.warning(f"Template not found: {template_path}")
            return None
            
    def send_email(self, recipient: str, subject: str, template_name: str, context: Dict) -> bool:
        """Send email using template and context."""
        try:
            # Load template
            template = self._load_template(template_name)
            if not template:
                return False
                
            # Render template with context
            content = self._render_template(template, context)
            
            # Send via configured service
            service = self.config.get("service", "smtp")
            success = self._send_via_service(recipient, subject, content, service)
            
            if success:
                logger.info(f"Email sent to {recipient}")
            else:
                logger.error(f"Failed to send email to {recipient}")
                
            return success
            
        except Exception as e:
            logger.exception(f"Error sending email: {e}")
            return False
            
    def _render_template(self, template: str, context: Dict) -> str:
        """Simple template rendering."""
        rendered = template
        for key, value in context.items():
            placeholder = f"{{{{ {key} }}}}"
            rendered = rendered.replace(placeholder, str(value))
        return rendered
        
    def _send_via_service(self, recipient: str, subject: str, content: str, service: str) -> bool:
        """Send email via configured service (smtp, sendgrid, etc)."""
        # Implementation details based on service
        return True


# Error handling decorator pattern
def handle_notification_errors(func):
    """Decorator to handle errors in notification methods."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Notification error in {func.__name__}: {e}")
            return False
    return wrapper