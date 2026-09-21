from django.shortcuts import render


def report(request):
    from .models import Invoice

    status = request.GET.get("status")
    rows = Invoice.objects.raw("SELECT * FROM invoice WHERE status = '" + status + "'")
    return render(request, "report.html", {"rows": list(rows)})
