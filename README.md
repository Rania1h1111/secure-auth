# SecureAuth — Formulaire d’identification sécurisé 

Projet réalisé dans le cadre du cours **Sécurité des Systèmes d’Information** (Février 2026).  
Objectif : créer un **formulaire d’identification sécurisé** avec :
- 1 logo
- 1 champ identifiant
- 1 champ mot de passe
- 3 boutons : **Reset**, **Valider**, **Créer un compte (Ajout compte)**

---

## 1) Technologies utilisées

- **Python 3**
- **Flask** (framework web)
- **SQLite** (base de données locale, fichier créé automatiquement)
- **Werkzeug Security** (hashage + vérification des mots de passe)

 Base SQLite générée automatiquement dans : `instance/app.db`

---

## 2) Prérequis


Outil recommandé
Visual Studio Code (VS Code) pour éditer et lancer le projet

Extensions conseillées dans VS Code :

Python (Microsoft)

Pylance

3) Installation & lancement (Windows / VS Code)
A. Ouvrir le projet
Ouvrir VS Code


B. Créer un environnement virtuel (venv)
Dans le terminal PowerShell à la racine du projet :

powershell
Copier le code
python -m venv .venv


powershell
Copier le code
py -m venv .venv
C. Activer l’environnement virtuel
powershell
Copier le code
.\.venv\Scripts\Activate

D. Installer toutes les bibliothèques nécessaires


powershell
Copier le code
python -m pip install -r requirements.txt
(ou)

powershell
Copier le code
py -m pip install -r requirements.txt
E. Lancer l’application
powershell
Copier le code
python app.py
Puis ouvrir dans le navigateur :

cpp
Copier le code
http://127.0.0.1:5000
4) Utilisation de l’application (fonctionnement)
 Connexion (Se connecter)
Remplir l’identifiant + mot de passe

Cliquer Se connecter

Si correct  message OK : Vous êtes connecté et redirection vers /home

Si incorrect  message Erreur : identifiant ou mot de passe incorrect

 Reset
Clique sur Reset : les champs se vident automatiquement (fonction HTML)

 Création de compte (Créer un compte / Ajout compte)
Permet de créer un nouvel utilisateur sans être connecté (conforme à l’énoncé)

Conditions :

identifiant >= 3 caractères

mot de passe >= 8 caractères

Si l’identifiant existe déjà → message d’erreur

5) Compte de test fourni
Un compte par défaut est créé automatiquement au premier lancement si la base est vide :

Identifiant : admin

Mot de passe : Admin123!

6) Explication technique (code)
Base de données (SQLite)
Une table users est créée automatiquement :

id (auto-incrément)

username (unique)

password_hash (hash du mot de passe)

Le fichier SQLite est stocké ici :

instance/app.db

Routes principales (Flask)
GET /  redirige vers /login

GET /login -> affiche la page login + inscription

POST /login -> vérifie identifiant + mot de passe

POST /add-account -> crée un utilisateur (hash + insertion SQL)

GET /home -> page “Vous êtes connecté”

GET /logout -> déconnexion (suppression de session)

7) Mesures de sécurité implémentées
 Mots de passe hashés

Aucun mot de passe en clair dans la base (utilisation de generate_password_hash)

 Requêtes SQL paramétrées

Protection contre l’injection SQL (SELECT ... WHERE username = ?)

 Sessions

Après connexion, stockage de l’utilisateur en session (session["user"])

 Limitation brute-force sur le login

Après plusieurs tentatives, blocage temporaire (anti attaques par force brute)

 Validation minimale des champs

Empêche champs vides, tailles minimales




Projet réalisé par : Rania MOULAI HACENE
Date : 10 Février 2026
