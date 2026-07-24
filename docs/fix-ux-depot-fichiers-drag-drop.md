# Fix UX — dépôt fichiers drag & drop

Parcours unique sur `/admin/files` : zone de dépôt → résolution inline (nouveau / existant) →
`POST /admin/files/deposit` (multipart unique). Droits / bêta restent sur `/admin/files/{id}`.

Endpoints : `POST /admin/files/deposit`, `GET /admin/files/resolve-name?q=…`.
