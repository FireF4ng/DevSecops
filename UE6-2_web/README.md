# RawPronote

RawPronote est une application web permettant aux élèves et aux professeurs de gérer leurs emplois du temps, leurs notes et la communication avec l'administration. L'application utilise **Flask** comme framework backend et propose une interface dynamique en **HTML/CSS/JS**.

## 📂 Structure du projet

```
DevSec/
├── index.py                     # Point d'entrée de l'application
├── config.py                    # Configuration de l'application
├── extensions.py                 # Extensions Flask (ex: SQLAlchemy)
├── sonar-project.properties      # Configuration pour SonarQube
│
├── controller/                   # Gestion des routes et des contrôleurs
│   ├── __init__.py
│   ├── admin_controller.py       # Gestion des fonctionnalités admin
│   ├── auth_controller.py        # Gestion de l'authentification
│   ├── general_controller.py     # Gestion des pages utilisateurs
│
├── db/                           # Base de données
│   ├── __init__.py
│   ├── db.py                     # Connexion à la base SQLite
│   ├── database.db                # Fichier de base de données SQLite
│
├── logs/                         # Logs de sécurité et erreurs
│   ├── security.log
│
├── model/                        # Modèles SQLAlchemy
│   ├── __init__.py
│   ├── user_model.py              # Modèles pour utilisateurs, notes, classes...
│
├── tools/                        # Outils supplémentaires
│   ├── __init__.py
│   ├── tools.py
│
├── view/                         # Partie Frontend
│   ├── __init__.py
│   ├── static/
│   │   ├── css/                   # Fichiers CSS
│   │   │   ├── admin.css
│   │   │   ├── login.css
│   │   │   ├── main.css
│   │   ├── images/                # Images du site
│   │   ├── js/                    # Scripts JavaScript
│   │   │   ├── admin.js
│   │   │   ├── header.js
│   │   │   ├── main.js
│   ├── templates/                 # Fichiers HTML
│       ├── (toutes les pages HTML)
│
└── .gitignore                     # Fichiers à ignorer pour Git
```

---

## ⚙️ Installation des dépendances

### 📌 Prérequis

- Python 3.10+
- `pip` installé
- `venv` pour créer un environnement virtuel
- SQLite3 (inclus dans Python)

### 🛠 Installation sous **Windows & Linux**

1. **Cloner le projet**  
   ```sh
   git clone https://github.com/FireF4ng/DevSecops.git
   cd DevSecops
   ```

2. **Créer un environnement virtuel et l'activer**  
   **Windows** :  
   ```sh
   python -m venv venv
   venv\Scripts\activate
   ```
   **Linux / MacOS** :  
   ```sh
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Installer les dépendances**  
   ```sh
   pip install -r requirements.txt
   ```

4. **Initialiser la base de données**  
   ```sh
   python -c "from db.db import init_db; init_db()"
   ```

---

## 🚀 Lancer l'application

Après installation, exécute cette commande :

```sh
python index.py
```

Par défaut, l'application sera accessible sur **http://127.0.0.1:5000/**.  

Si tu veux activer le **mode debug** pour le développement :  

```sh
python index.py --debug
```

---

## 📌 Fonctionnalités

- 🔒 **Authentification** (Élèves, Professeurs, Admins)
- 📅 **Agenda** affichant les cours prévus
- 🎓 **Gestion des notes** pour chaque élève
- 🎒 **Vie Scolaire** : affichage des classes et professeurs principaux
- 📚 **Cahier de texte** : suivi des devoirs
- 📬 **Communication** : système de feedback pour les élèves et professeurs
- 🛠 **Panneau Admin** pour gérer la base de données
- 🔒 **Sécurité** : Hashage des mots de passe et chiffrement des noms/prénoms

---

## ✅ TODOs

🔴 **Bugs à corriger :**
- 📌 Corriger les erreurs HTTP 400 sur certains formulaires
- 🛠 Vérifier l'intégration des tokens CSRF dans les requêtes POST
- 🔍 Déboguer les requêtes fetch pour les boutons "Ajouter" et "Sauvegarder"

🟢 **Améliorations à venir :**
- 🎓 Ajouter la possibilité aux **professeurs d'ajouter des notes**
- 📌 Améliorer l'interface du panneau d'administration
- 📊 Implémenter des statistiques sur les performances des élèves
- 📨 Ajouter un système de **messagerie interne** entre élèves et professeurs

---

Si tu rencontres un problème, ouvre une **issue** sur GitHub ou contacte-moi ! 😊🚀

---

**Tu veux contribuer ?** Forke le repo et propose une **Pull Request** ! 🔥


## 📜 Licence
Projet sous licence **MIT**. Tu es libre de l'utiliser et de le modifier comme tu veux ! 🚀

