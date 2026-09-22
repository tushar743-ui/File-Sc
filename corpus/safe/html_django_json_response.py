import json

from django.http import HttpResponse


def profile(request):
    bio = request.GET.get("bio")
    return HttpResponse(json.dumps({"bio": bio}), content_type="application/json")
