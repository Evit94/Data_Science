# -*- coding: utf-8 -*-
import os
import re
import json
import time
import requests
import feedparser
import pandas as pd
import urllib3
urllib3.disable_warnings()

# "local" = lire data/  |  "api" = requetes web
SOURCE = "api"
LIMITE = 9999 # S'utilise en local mais pas en api
HEADERS = {"User-Agent": "Projet-EFREI"}
DOSSIERS = {"Alerte": "alertes", "Avis": "Avis"}


# SEUL endroit qui differe entre mode local et api
def lire_json(chemin_local, url):
    if SOURCE == "local":
        if not os.path.exists(chemin_local):
            return None
        with open(chemin_local, encoding="utf-8") as f:
            return json.load(f)
    else:
        time.sleep(0.5)
        reponse = requests.get(url, headers=HEADERS, verify=False)
        return reponse.json() if reponse.status_code == 200 else None


# ETAPE 1 : liste des bulletins (type, identifiant, lien)
def lister_bulletins():
    bulletins = []
    for type_b, chemin in [("Alerte", "alerte"), ("Avis", "avis")]:
        if SOURCE == "local":
            for cid in sorted(os.listdir("data/" + DOSSIERS[type_b]))[:LIMITE]:
                lien = f"https://www.cert.ssi.gouv.fr/{chemin}/{cid}/"
                bulletins.append((type_b, cid, lien))
        else:
            url = f"https://www.cert.ssi.gouv.fr/{chemin}/feed/"
            contenu = requests.get(url, headers=HEADERS, verify=False).content
            for e in feedparser.parse(contenu).entries:
                cid = re.search(r"CERTFR-\d{4}-(ALE|AVI)-\d+", e.link).group()
                bulletins.append((type_b, cid, e.link))
    return bulletins


# ETAPE 3 : niveau de gravite depuis le score CVSS
def severite(cvss):
    if cvss is None: return "Inconnue"
    if cvss >= 9: return "Critique"
    if cvss >= 7: return "Elevee"
    if cvss >= 4: return "Moyenne"
    return "Faible"


# ETAPE 3 : extraction des champs utiles depuis la fiche MITRE
def infos_mitre(mitre):
    infos = {}
    if not mitre:
        return infos
    cna = mitre.get("containers", {}).get("cna", {})

    # la cle CVSS varie selon la version (cvssV3_1, cvssV3_0, cvssV4_0...)
    for bloc in (cna.get("metrics") or []):
        for cle, valeur in bloc.items():
            if cle.startswith("cvss"):
                infos["cvss"] = valeur.get("baseScore")

    try: infos["cwe"] = cna["problemTypes"][0]["descriptions"][0]["cweId"]
    except (KeyError, IndexError): pass

    try: infos["description"] = cna["descriptions"][0]["value"][:300]
    except (KeyError, IndexError): pass

    try:
        p = cna["affected"][0]
        infos["editeur"] = p.get("vendor")
        infos["produit"] = p.get("product")
        infos["versions"] = ", ".join(v["version"] for v in p.get("versions", []))
    except (KeyError, IndexError): pass

    return infos


# ETAPE 3 : score EPSS entre 0 et 1
def score_epss(epss):
    if epss and epss.get("data"):
        return float(epss["data"][0]["epss"])
    return None


# ETAPE 4 : niveau d'exploitabilite depuis le score EPSS
def niveau_epss(epss):
    if epss is None: return "Inconnu"
    if epss >= 0.5: return "Eleve"
    if epss >= 0.1: return "Moyen"
    return "Faible"


# ETAPES 2 et 4 : boucle principale -> une ligne par couple bulletin x CVE
def construire_tableau():
    lignes = []
    bulletins = lister_bulletins()
    for i, (type_b, cid, lien) in enumerate(bulletins, 1):
        if i % 10 == 0:
            print(f"  {i}/{len(bulletins)} bulletins charges...")
        bulletin = lire_json(f"data/{DOSSIERS[type_b]}/{cid}", lien + "json/")
        if not bulletin:
            continue
        titre = bulletin.get("title")
        date = (bulletin.get("revisions") or [{}])[0].get("revision_date", "")[:10]
        cves = [c["name"] for c in bulletin.get("cves", [])]

        for cve in cves:
            mitre = lire_json(f"data/mitre/{cve}", f"https://cveawg.mitre.org/api/cve/{cve}")
            epss  = lire_json(f"data/first/{cve}", f"https://api.first.org/data/v1/epss?cve={cve}")
            infos = infos_mitre(mitre)
            cvss  = infos.get("cvss")
            epss_val = score_epss(epss)
            # Priorite = gravite x probabilite d'exploitation (0 a 10)
            priorite = round(cvss * epss_val, 2) if (cvss and epss_val) else None
            lignes.append({
                "ID ANSSI": cid, "Titre ANSSI": titre, "Type": type_b, "Date": date,
                "CVE": cve, "Score CVSS": cvss, "Base Severity": severite(cvss),
                "CWE": infos.get("cwe"), "Score EPSS": epss_val,
                "Niveau EPSS": niveau_epss(epss_val), "Priorite": priorite, "Lien": lien,
                "Description": infos.get("description"), "Editeur": infos.get("editeur"),
                "Produit": infos.get("produit"), "Versions affectees": infos.get("versions"),
            })
    return lignes


# ETAPE 7 : email d'alerte pour les vulnerabilites critiques (CVSS >= 9)
def creer_email(df):
    critiques = df[df["Score CVSS"] >= 9].sort_values("Score EPSS", ascending=False)
    sujet = f"[ALERTE] {len(critiques)} vulnerabilites critiques detectees"
    corps = "Vulnerabilites a corriger en priorite :\n\n"
    for _, r in critiques.head(10).iterrows():
        corps += f"- {r['CVE']} ({r['Produit']}) : CVSS={r['Score CVSS']}, EPSS={r['Score EPSS']}\n"
    return sujet, corps


def envoyer_email(destinataire, sujet, corps):
    import smtplib
    from email.mime.text import MIMEText
    expediteur, mot_de_passe = "votre_email@gmail.com", "mot_de_passe_application"
    msg = MIMEText(corps, _charset="utf-8")
    msg["From"], msg["To"], msg["Subject"] = expediteur, destinataire, sujet
    serveur = smtplib.SMTP("smtp.gmail.com", 587)
    serveur.starttls()
    serveur.login(expediteur, mot_de_passe)
    serveur.sendmail(expediteur, destinataire, msg.as_string())
    serveur.quit()


# EXECUTION
print("Construction du tableau (SOURCE =", SOURCE, ")...")
df = pd.DataFrame(construire_tableau())
df.to_csv("donnees_consolidees.csv", index=False, encoding="utf-8-sig")
print(len(df), "lignes enregistrees dans donnees_consolidees.csv")

sujet, corps = creer_email(df)
print("\n" + sujet + "\n")
print(corps)
# envoyer_email("destinataire@email.com", sujet, corps)
