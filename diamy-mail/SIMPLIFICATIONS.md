# Simplifications assumées de la maquette

Ce fichier distingue « pas encore fait » de « fait faux ». À tenir à jour : c'est ce qui
rend la maquette **honnête** en revue. Règle d'or (guide §12) : si tu modifies la conception,
tu mets à jour l'annexe concernée (version + changelog) — jamais de divergence code/spec.

| Domaine | Simplification actuelle | Raison | Ce que fera la vraie implém | Annexe |
|---------|-------------------------|--------|-----------------------------|--------|
| Crypto | Backend `dev-crypto` (RustCrypto) derrière `diamy-mail-crypto` | Messaging Diamy tout juste en ligne, pas stable | Backend `messaging-crypto` (primitives auditées messaging) + re-provision (pas d'interop) | A02/A18 |
| Signature identité | Ed25519 (stand-in) | Crate ML-DSA jeune | ML-DSA-65 (FIPS 204) | A02/A17 |
| IAM | `DevIamClient` en mémoire, principaux `@w3.tel` amorcés | Env de dev IAM à brancher | Adaptateur vers l'API de l'env de dev IAM, puis prod | A17 |
| Révocation | Non implémentée | Mécanisme non confirmé (A17-TOK-2) | Selon mécanisme IAM confirmé | A17 |
| Stockage | `StoredMessage` en mémoire (démo mxd) | Squelette | Postgres via `sqlx`, schéma A21 | A21/A02 |
| MX entrant | « Réception » simulée dans `diamy-mxd` | Vrai MX en cours (avec Aubin) | Serveur MX SMTP réel | A01 |
| Sync | Reconstruction directe (démo) | Squelette | API sync native, signaux-seuls (A04) | A04 |
| Rendu | Non implémenté (démo affiche le clair) | Squelette | Projection Tiptap à schéma fermé | A08 |
| Agenda / Sortant / Bridge | Absents | Hors périmètre tranche 1 | diamy-cald / A10 complet / diamy-bridged | A12-A15 / A10 / A20 |

## Garde-fous en place
- `dev-crypto` **refuse de démarrer hors `DIAMY_ENV=dev`** (`assert_backend_allowed_for_env`, A18 SEC-FC-1).
- Les données `dev-crypto` **ne sont pas interopérables** avec `messaging-crypto` → re-provision à la bascule, pas de migration.
- La démo `diamy-mxd` **vérifie** qu'aucun clair ne subsiste dans le blob stocké (INV-1).
