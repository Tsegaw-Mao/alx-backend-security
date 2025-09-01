import logging
from django.http import HttpResponseForbidden
from django.utils import timezone
from django.core.cache import cache
from ipgeolocation import geolocator
from .models import RequestLog, BlockedIP

logger = logging.getLogger(__name__)


class IPTrackingMiddleware:
    """
    Middleware to log requests, block blacklisted IPs,
    and enhance logs with geolocation.
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

        # Get geolocation (with cache)
        geo_data = self.get_geolocation(ip)
        country = geo_data.get("country_name") if geo_data else None
        city = geo_data.get("city") if geo_data else None

        # Log request
        RequestLog.objects.create(
            ip_address=ip,
            path=path,
            timestamp=timestamp,
            country=country,
            city=city,
        )
        logger.info(f"IP: {ip}, Path: {path}, Timestamp: {timestamp}, Country: {country}, City: {city}")

        return self.get_response(request)

    def get_client_ip(self, request):
        """Extract client IP address, considering proxy headers."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip

    def get_geolocation(self, ip):
        """Get geolocation data for an IP, cached for 24 hours."""
        cache_key = f"geo_{ip}"
        geo_data = cache.get(cache_key)
        if geo_data is None:
            try:
                geo_data = geolocator.get(ip)
                cache.set(cache_key, geo_data, timeout=60 * 60 * 24)  # 24 hours
            except Exception as e:
                logger.error(f"Geolocation lookup failed for {ip}: {e}")
                geo_data = {}
        return geo_data
