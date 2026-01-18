# Health check endpoint implementation
import time

class HealthCheck:
    def get_status(self):
        # Hardcoded health check interval (60 seconds)
        interval = 60  # Fixed interval
        return {
            "status": "healthy",
            "last_check": time.time(),
            "check_interval": interval
        }

def health_check_handler():
    checker = HealthCheck()
    return checker.get_status()