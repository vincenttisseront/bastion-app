# Fix UX — sélecteur contextuel « Ajouter un droit »

Affiche un seul champ ressource selon Type (Application / Fichier / Dossier / Rôle).
Cause : `.form-group{display:flex}` annulait l’attribut HTML `hidden`.
