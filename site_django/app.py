# -*- coding: utf-8 -*-
"""
Mini site Django (OPTIONNEL, "pour aller plus loin").
Affiche les 50 vulnerabilites les plus prioritaires dans un tableau web.
Tout tient dans un seul fichier pour rester simple.

Prerequis : pip install django
Lancer    : python app.py    puis ouvrir http://127.0.0.1:8000
"""
import os
import pandas as pd
from django.conf import settings
from django.urls import path
from django.shortcuts import render
from django.core.management import execute_from_command_line

DOSSIER = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(DOSSIER, "..", "donnees_consolidees.csv")

settings.configure(
    DEBUG=True,
    SECRET_KEY="dev",
    ROOT_URLCONF=__name__,
    TEMPLATES=[{
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [DOSSIER],
    }],
)


# La vue : lit le CSV et envoie les 50 lignes les plus prioritaires au template
def index(request):
    df = pd.read_csv(CSV)
    if "Priorite" in df.columns:
        df = df.sort_values("Priorite", ascending=False)
    df = df.head(50).fillna("-").rename(columns={
        "ID ANSSI": "bulletin", "Score CVSS": "cvss",
        "Base Severity": "gravite", "Score EPSS": "epss",
    })
    return render(request, "index.html", {"lignes": df.to_dict("records")})


# L'URL "/" appelle la vue index
urlpatterns = [path("", index)]

if __name__ == "__main__":
    execute_from_command_line(["app.py", "runserver"])
