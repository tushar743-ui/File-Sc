from django.http import HttpResponse


def profile(request):
    bio = request.GET.get("bio")
    return HttpResponse("<p>" + bio + "</p>")
