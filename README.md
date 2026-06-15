# Analyse des avis et alertes ANSSI + enrichissement des CVE

Ce projet collecte les **bulletins de sécurité de l'ANSSI** (avis et alertes), en
extrait les **CVE**, les **enrichit** (scores CVSS, types CWE, scores EPSS),
consolide le tout dans un **fichier CSV**, puis réalise des **visualisations** et
des modèles de **Machine Learning**. Il **génère** enfin une alerte email pour les
vulnérabilités critiques.

## 1. Fichiers du projet

| Fichier | Rôle |
|---|---|
| `pipeline_anssi.py` | Script principal : étapes 1 à 4 (extraction → enrichissement → CSV) + étape 7 (alerte/email). |
| `donnees_consolidees.csv` | Jeu de données consolidé et enrichi (produit par le script). |
| `analyse_anssi.ipynb` | Notebook : étape 5 (visualisations) + étape 6 (Machine Learning). |
| `analyse_anssi.html` | Export HTML du notebook. |
| `requirements.txt` | Bibliothèques à installer. |
| `data/` | Données pré-téléchargées : `alertes/`, `Avis/` (bulletins ANSSI), `mitre/` (CVSS, CWE), `first/` (EPSS). |

## 2. Installation

```bash
pip install -r requirements.txt
```

## 3. Utilisation

### Étape A — Produire le CSV

Dans `pipeline_anssi.py`, en haut du fichier, choisir la source des données :

```python
SOURCE = "local"   # "local" = dossier data/ (rapide)
                   # "api"   = requêtes web (RSS ANSSI + API MITRE + API FIRST)
LIMITE = 500       # nombre max de bulletins de chaque type (mettre ~5 en mode "api")
```

- **`"local"`** : lit les fichiers de `data/`, aucune requête réseau.
- **`"api"`** : interroge les serveurs, avec un **délai de 0.5 s** entre chaque requête
  (`DELAI_API`) pour ne pas les surcharger. À limiter avec `LIMITE`.

> Une seule fonction, `lire_json()`, gère la différence entre les deux modes : elle
> lit soit un fichier local, soit une URL. Le reste du programme est identique.

Lancer ensuite :

```bash
python pipeline_anssi.py
```

Cela crée `donnees_consolidees.csv` et affiche l'email d'alerte (étape 7).

### Étape B — Analyser et modéliser

Ouvrir `analyse_anssi.ipynb` (VS Code ou Jupyter) et exécuter les cellules.

## 4. Les 7 étapes

1. **Extraction des bulletins** — liste des avis/alertes (RSS en mode api, dossier `data/` en mode local).
2. **Extraction des CVE** — via la clé `cves` du JSON.
3. **Enrichissement** — pour chaque CVE : CVSS + CWE + produits affectés (MITRE) et EPSS (FIRST).
4. **Consolidation** — construction d'un **DataFrame pandas** (une ligne par couple bulletin × CVE) sauvegardé en **CSV**.
5. **Visualisation** — distribution CVSS, gravités, top CWE, top éditeurs, CVSS vs EPSS, par année.
6. **Machine Learning** — **KMeans** (groupes de vulnérabilités, validé par le score de silhouette) et **RandomForest** (prédiction de la gravité, validé par jeu de test + validation croisée).
7. **Alertes** — génération d'un email listant les vulnérabilités critiques (envoi réel optionnel).

## 5. Colonnes du CSV

`ID ANSSI`, `Titre ANSSI`, `Type`, `Date`, `CVE`, `Score CVSS`, `Base Severity`,
`CWE`, `Score EPSS`, `Niveau EPSS`, `Priorite`, `Lien`, `Description`, `Editeur`,
`Produit`, `Versions affectees`.

> `Priorite` = `Score CVSS` × `Score EPSS` : une faille n'est urgente que si elle est
> à la fois grave **et** réellement exploitée.

## 6. Usage responsable

Le mode **local** est privilégié pour éviter de surcharger les serveurs ; le mode
**api** applique un **délai de 0.5 s** entre les requêtes.

## 7. Pour aller plus loin : mini site Django (optionnel)

Le dossier `site_django/` contient une petite interface web (tout tient dans un seul
fichier `app.py` + un template `index.html`) qui lit le CSV et affiche les **50
vulnérabilités les plus prioritaires** dans un tableau.

```bash
pip install django
python site_django/app.py     # puis ouvrir http://127.0.0.1:8000
```

Cela montre qu'on peut transformer l'analyse en véritable outil consultable.
