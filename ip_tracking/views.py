from django.http import JsonResponse
from django.contrib.auth import authenticate, login
# type: ignore
from ratelimit.decorators import ratelimit  # type: ignore

from .ratelimit_keys import user_or_ip


# Anonymous users: 5 requests/minute
# Authenticated users: 10 requests/minute
@ratelimit(key="ip", rate="5/m", method="POST", block=True)
@ratelimit(key="user_or_ip", rate="10/m", method="POST", block=True)
def login_view(request):
    """
    Example login view protected with rate limiting.
    """
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            return JsonResponse({"message": "Login successful"})
        else:
            return JsonResponse({"error": "Invalid credentials"}, status=400)

    return JsonResponse({"error": "POST request required"}, status=405)
