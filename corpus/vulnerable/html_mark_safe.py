from django.utils.safestring import mark_safe


def render_bio(request):
    bio = request.POST.get("bio")
    return mark_safe("<p>%s</p>" % bio)
