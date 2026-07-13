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
- **`diamy-obs`** : logs `tracing` (sans contenu, INV-21) + métriques Prometheus.
- **`diamy-mxd`** : **démo du chemin vertical** (frontière → stockage chiffré → sync → déchiffrement vérifié).
- **`diamy-maild`** : squelette + endpoint `/metrics` + garde-fou crypto au boot.
- **`diamy-submitd`** : squelette (A10).

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

# 5. Observabilité (Postgres + Prometheus + Grafana)
docker compose up -d
```

Le garde-fou *fail-closed* se vérifie ainsi (le backend dev doit refuser un env non-dev) :

```bash
DIAMY_ENV=prod cargo run -p diamy-maild   # doit échouer au démarrage
```

## Prochaines étapes (ordre suggéré, cf. Kit §7)

1. Câbler les **13 vecteurs A24** dans `diamy-addr` (gate CI).
2. Stockage **Postgres via `sqlx`** (schéma A21) à la place du `StoredMessage` en mémoire.
3. Vrai **MX SMTP** entrant (A01, avec Aubin) en amont de la frontière.
4. **Sync native** (A04) signaux-seuls + client vault (A03/A19) + **rendu Tiptap** (A08).
5. Le jour où le messaging est stable : implémenter le backend **`messaging-crypto`**
   (labels HKDF + format d'enveloppe exacts) — **rien d'autre ne change** chez les appelants.

## Contacts
- DNS / SPF / DKIM / DMARC de `w3.tel` → **Cédric** (référent de stage).
- Serveur MX au bureau → **Aubin**.
