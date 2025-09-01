import logging
from django.http import HttpResponseForbidden
from django.utils import timezone
from .models import RequestLog, BlockedIP

logger = logging.getLogger(__name__)


class IPTrackingMiddleware:
    """
    Middleware to log requests and block blacklisted IPs.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)
        path = request.path
        timestamp = timezone.now()

        # Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip).exists():
            logger.warning(f"Blocked request from blacklisted IP: {ip}")
            return HttpResponseForbidden("Your IP has been blocked.")

        # Log request
        RequestLog.objects.create(ip_address=ip, path=path, timestamp=timestamp)
        logger.info(f"IP: {ip}, Path: {path}, Timestamp: {timestamp}")

        return self.get_response(request)

    def get_client_ip(self, request):
        """Extract client IP address, considering proxy headers."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip
