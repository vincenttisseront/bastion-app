# Bascule ActiveSync sur Grommunio — checklist d'exécution

> Version courte et opérationnelle du §16 de
> [`activesync-devices-inventaire-approbation-user.md`](./activesync-devices-inventaire-approbation-user.md).
> À suivre dans l'ordre, terminal ouvert.
> **Toute case rouge ⇒ on n'active pas aujourd'hui.** Rien n'est urgent : le gate est off depuis
> le début, un jour de plus ne coûte rien, une messagerie coupée si.

## Avant de commencer

- [ ] Créneau choisi où **Hervé et Brigitte sont joignables** (tu veux l'apprendre d'eux en
      10 minutes, pas le découvrir demain)
- [ ] Un **téléphone de test non inventorié** sous la main (ou un profil EAS de test)
- [ ] La commande de rollback déjà dans le presse-papier :
      `python -m app.admin.activesync_control_cli grommunio --disable`

## 1. Critère bloquant — `miss_family`

`/admin/logs` → action `activesync.device_unidentified` → activer la colonne `miss_family`,
sur toute la fenêtre depuis le 2026-08-15.

- [ ] **Aucune entrée** ⇒ ✅ idéal, passer à l'étape 2
- [ ] `decoder_failure` présent ⇒ 🛑 **STOP**. Des appareils réels passent aujourd'hui sans être
      identifiés : ils prendront un 403 à la bascule. Récupérer les `query_sample` associés et
      corriger le décodeur MS-ASHTTP avant toute activation.
- [ ] `no_device_sent` présent ⇒ 🛑 **STOP** si c'est un client réel. Identifier **qui**, puis
      décider : le fail-closed le coupera.

## 2. Parc complet

- [ ] L'inventaire contient bien : Hervé, Brigitte, toi
- [ ] Personne n'a de **second téléphone, tablette, ou client lourd** absent de la liste
- [ ] Personne n'a de téléphone **éteint / en congés / peu utilisé** depuis le 2026-08-15
      → un appareil absent de l'inventaire **sera bloqué**

## 3. Deux vérifications de code (PR #146)

Aucun test ne les attrape naturellement, d'où la relecture manuelle :

- [x] Le backfill **n'approuve que les `pending`** — jamais un `blocked`, `blocked_by_admin` ou
      `rejected`. *Sinon un téléphone volé bloqué la veille est réhabilité par la bascule, en
      silence.*
- [x] La confirmation approuve **la liste affichée par la pré-visualisation**, pas le résultat
      d'une nouvelle requête au clic. *Sinon un appareil apparu pendant que tu relis les noms est
      approuvé sans avoir jamais été vu.*

> **Relecture code (2026-08-16, corrigé)** — voir note en bas de ce fichier.

## 4. Pré-visualisation

```
python -m app.admin.activesync_control_cli grommunio --preview
```

> La CLI affiche les lignes `PENDING <DeviceId> …` (liste figée). Pour relire **nom par nom**,
> préférer aussi l'écran `/admin/apps/grommunio/activesync/devices/preview`.

- [ ] Relire la liste **nom par nom**, pas en comptant les lignes
- [ ] Chaque appareil correspond à une personne et à un téléphone que tu peux nommer

## 5. Activation

Via l'écran (recommandé) : le formulaire POST envoie les `pending_device_id` affichés.

Via CLI (même liste figée que le `--preview`) :

```
python -m app.admin.activesync_control_cli grommunio --enable --pending-id ID1 --pending-id ID2
```

- [ ] Confirmer (écran ou CLI avec les ids du preview)
- [ ] Vérifier le log **`BST-AUTH-1003`** (`ACTIVESYNC_DEVICE_CONTROL_ENABLED`) et son décompte
      par source
- [ ] Confirmer la configuration : bon drapeau sur la **bonne application**, nginx rechargé,
      locations ActiveSync bien générées

## 6. Surveillance 30 minutes

- [ ] Les `hits` des appareils approuvés **continuent de progresser**
- [ ] **Aucun** `BST-AUTH-2006` (`activesync.device_denied`) sur un utilisateur légitime
- [ ] 🛑 Au premier utilisateur légitime coupé : `--disable`, sans hésiter et sans diagnostiquer
      d'abord. La protection peut attendre une heure, pas la messagerie de l'entreprise.

## 7. Validation post-bascule — le test qui compte

Ajouter un compte ActiveSync sur le téléphone de test non inventorié :

- [ ] La synchronisation **échoue** (403, et non une demande de mot de passe en boucle)
- [ ] L'appareil apparaît dans `/admin/pending-devices`
- [ ] L'appareil apparaît dans le portail de **son propriétaire** (`/profile`)
- [ ] La **notification SMTP** est bien reçue
- [ ] L'utilisateur approuve depuis `/profile`
- [ ] La synchronisation **reprend** — noter le délai : ______

> Le délai est côté client (retry iOS), pas côté bastion (un `SELECT` par requête, aucun cache).
> S'il dépasse quelques minutes, l'écrire dans le message de confirmation du portail
> (« la synchronisation peut reprendre dans quelques minutes ») plutôt que de laisser
> l'utilisateur conclure à un échec.

## Après la bascule

- [ ] Lot 3 — détection de clone (§14, prompt §14.7 avec les raffinements du §14.2.bis)
- [ ] Audit de l'étanchéité du périmètre grommunio (IMAP, SMTP auth, EWS, MAPI/HTTP, webmail
      direct) — **risque résiduel dominant**, hors repo
- [ ] Mot de passe applicatif dédié à la synchronisation, distinct du mot de passe SSO

---

## Note — relecture code étape 3 (2026-08-16, corrigé)

| Vérification | Résultat | Preuve |
|---|---|---|
| Backfill n'approuve que les `pending` | ✅ OK | `enable_device_control` n'approuve que des lignes encore `pending` + non `blocked_by_admin` |
| Confirmation = liste figée de la prévisualisation | ✅ **corrigé** | Intersection `(liste figée) ∩ (toujours pending, non blocked_by_admin)` au POST. Un pending apparu après → `left_pending`. Un appareil **bloqué entre-temps** → `skipped_not_pending`, **jamais** ré-approuvé. |
