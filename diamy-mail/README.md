# Diamy Mail — squelette de maquette

Point de départ **qui compile et tourne** pour monter la maquette Diamy Mail à partir du
corpus de spécifications. À lire avec le *Guide de prise en main* et le *Kit de démarrage*.

⚠️ **Squelette de départ, pas une implémentation validée.** Il illustre la structure et le
chemin vertical ; la référence normative reste le corpus (annexes A00–A29). Tout écart de
conception introduit ici doit être répercuté dans l'annexe propriétaire (guide §12).

## Ce qui est déjà là

- **Workspace Cargo** avec les crates d'A18 et 3 services.
- **`diamy-mail-crypto`** : LA maison de la crypto (INV-5), **une API, deux backends** derrière un *feature flag* :
  - `dev-crypto` (défaut) : AES-256-GCM + ML-KEM-768 + HKDF-SHA256 + Ed25519 (stand-in ML-DSA). Primitives auditées RustCrypto. **Non expédiable**, *fail-closed* hors dev.
  - `messaging-crypto` : la cible (primitives du messaging Diamy), stub à brancher plus tard.
- **`diamy-addr`** : `diamy_addr_canon()` (A24) + type `CanonicalAddress` (type-state).
- **`diamy-mail-iam`** : client de consommation IAM + `DevIamClient` (doublure, principaux `@w3.tel`).
- **`diamy-mail-model`** : types miroir A21 avec classification de chiffrement (CDM-ENC).
- **`diamy-obs`** : logs `tracing` (sans contenu, INV-21) + métriques Prometheus (compteurs `diamy_events_total` + jauges `diamy_gauges`).
- **`diamy-mail-render`** : conversion vers **Tiptap JSON à schéma fermé** (A08) — chemin `text/plain` uniquement pour cette maquette (voir `SIMPLIFICATIONS.md`) ; câblée dans la démo `read_test_mail`, qui n'affiche plus jamais le clair brut (INV-17).
- **`diamy-mail-mime`** : parsing MIME/RFC 5322 (A01-PARSE, step 2) — wrapper autour de `mail-parser` ; sélectionne le corps texte/HTML authentique (jamais les en-têtes, jamais du HTML converti), pièces jointes détectées mais pas conservées tant que l'AV (A01-AV) n'existe pas.
- **`diamy-mxd`** : **démo du chemin vertical** (frontière → parse MIME → stockage chiffré → sync → déchiffrement vérifié), vrai SMTP (STARTTLS) sur `:2525`, persistance Postgres réelle, **file de hold** (A01-HOLD, ferme A17-DIR-5) avec balayage de release périodique, endpoint `/metrics` sur `:9102` (compteurs/jauges réels branchés sur le pipeline).
- **`diamy-maild`** : API de sync HTTPS authentifiée (AppKey Tier 2 + jeton mail-plane) + endpoint `/metrics` (`:9101`) + garde-fou crypto au boot.
- **Dashboard Grafana** (`deploy/grafana/`) : datasource Prometheus + dashboard "Diamy Mail" provisionnés AUTOMATIQUEMENT au démarrage — aucun clic dans l'UI, `docker compose up` suffit (débit SMTP par résultat, profondeur de la file de hold, relâchements/purges, cibles up).
- **`diamy-bridged`** : Bridge IMAP/SMTP local (A20) pour clients tiers (Thunderbird) — loopback uniquement (A20-ARCH-2/NET-1/2/3), lecture IMAP + envoi SMTP (voir `diamy-submitd` juste en dessous ; A20-SMTP-1 : le Bridge délègue TOUJOURS l'émission, il ne relaie jamais lui-même vers Internet).
- **`diamy-submitd`** : `POST /submit` (A10 §2/A20-SMTP-1), tranche démo minimale — authentification à deux facteurs, VRAI dialogue SMTP sortant par destinataire, réinjection dans `diamy-mxd` pour les domaines locaux (boucle fermée de démo). PAS de DKIM/SPF-DKIM-DMARC/rate-limiting/pools d'envoi/copie Envoyés/retry-DSN (voir `SIMPLIFICATIONS.md` pour le détail exact).

## Démarrer

```bash
# 1. Compiler
cargo build

# 2. Tests (round-trip enveloppe, fail-closed sur tag altéré, normalisation d'adresse…)
cargo test

# 3. Démo du chemin vertical
cargo run -p diamy-mxd

# 4. Service métriques (puis ouvrir http://localhost:9101)
cargo run -p diamy-maild

# 5. Observabilité (Postgres + Prometheus + Grafana, dashboard provisionné automatiquement)
docker compose up -d
# -> Grafana sur http://localhost:3001 (admin / devonly_change_me), dashboard "Diamy Mail"
# -> Prometheus sur http://localhost:9091/targets (diamy-maild + diamy-mxd doivent être "up")

# 6. Chemin sortant (A10/A20-SMTP-1) — envoi depuis Thunderbird via le Bridge
cargo run -p diamy-submitd   # POST /submit sur 127.0.0.1:8446 (HTTPS)
cargo run -p diamy-bridged   # IMAP sur 127.0.0.1:1143 + SMTP sur 127.0.0.1:1587 (voir DEMO_GUIDE.md)
```

Le garde-fou *fail-closed* se vérifie ainsi (le backend dev doit refuser un env non-dev) :

```bash
DIAMY_ENV=prod cargo run -p diamy-maild   # doit échouer au démarrage
```

## Prochaines étapes

**À trancher avec Cédric avant de coder autour (pas des chantiers de code) :**
- `MAX_DATA_BYTES` : 10 Mo actuel vs 50 Mo recommandé par A02-QOS-2 — décision produit en attente.

**Résolu (ne plus lister comme ouvert) :**
- **`mint_dev_mail_plane_token` — capacité de fabrication de jeton de session retirée du code** (ex-ESCALADE INV-9/A17-P-1). La fonction qui signait un jeton de session valide à la volée a été ENTIÈREMENT supprimée (avec le feature `dev-token-issuer`) ; les tests et exemples LISENT désormais un jeu de jetons **pré-signés hors du code** (`tests/fixtures/dev_mail_plane_tokens.json`), et plus aucune fonction du repo ne sait en fabriquer. Ce point n'était PAS un vrai conflit de conception : la correction **retire** la violation au lieu de la justifier, donc **Hugo l'a pris en charge directement, sans arbitrage de Cédric**. Garanti par le test anti-régression repo-wide `crates/diamy-mail-iam/tests/no_token_minting_in_repo.rs`. Détail dans `SIMPLIFICATIONS.md`.
- **Divergence A01/A21 sur la file de hold** — *tranchée par Cédric le 2026-07-15* (voir `SIMPLIFICATIONS.md`, ligne "ex-ESCALADE A01/A21"). A01-HOLD-5 ("body plaintext is NOT reconstructed") et l'ancien DDL `hold_queue` d'A21 décrivaient deux designs incompatibles ; Cédric (référent du projet) a validé l'option (a) — **amender A21** (passé en v1.5) pour porter le design **clé seule**, pas A01. Confirmation donnée directement à Hugo (hors dépôt) ; la modification a été écrite par une session Claude Code, la décision arbitrée par Cédric. Implémenté et vérifié de bout en bout.

**Chantiers de code identifiés (aucun ne nécessite d'inventer un comportement non spécifié) :**
1. Le jour où le messaging est stable : implémenter le backend **`messaging-crypto`**
   (labels HKDF + format d'enveloppe exacts) — **rien d'autre ne change** chez les appelants.
2. Une fois l'AV (A01-AV) implémenté : étendre `diamy-mail-mime`/`diamy-mxd` pour conserver les pièces jointes séparément (aujourd'hui détectées mais volontairement pas conservées, voir `SIMPLIFICATIONS.md`).
3. `k_hold` dérivé par un vrai `diamy-secretd` (Level A, A17-ENC-1) au lieu d'un secret d'env de dev, une fois ce service disponible.
4. Observabilité : histogrammes de latence par étape du pipeline (A01 §11), jauge de profondeur de hold PAR TENANT (une jauge globale seulement pour l'instant), compteurs sur l'API de sync de `diamy-maild` (voir `SIMPLIFICATIONS.md`).

*(Déjà fait, à ne pas refaire : les 13 vecteurs A24 sont câblés dans `diamy-addr` ; le stockage Postgres via `sqlx` remplace le `StoredMessage` en mémoire ; le SMTP entrant est réel avec STARTTLS ; la sync est authentifiée ; le rendu Tiptap couvre le chemin text/plain ; le parsing MIME/RFC 5322 (A01-PARSE) sélectionne le vrai corps du message ; la file de hold (A01-HOLD) accepte et relâche automatiquement ; l'AAD de l'enveloppe (A02-CRY-4) est câblée ; le dashboard Grafana est provisionné automatiquement avec des métriques réelles — voir `SIMPLIFICATIONS.md` pour le détail exact de ce qui reste simplifié dans chacun.)*

## Contacts
- DNS / SPF / DKIM / DMARC de `w3.tel` → **Cédric** (référent de stage).
- Serveur MX au bureau → **Aubin**.
