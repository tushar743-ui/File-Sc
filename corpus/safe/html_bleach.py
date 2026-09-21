import bleach
from django.utils.safestring import mark_safe


def render_bio(request):
    bio = bleach.clean(request.POST.get("bio", ""))
    return mark_safe("<p>%s</p>" % bio)
