# Diamy Mail — Kit de démarrage de la maquette

**Pour :** Hugo
**Objet :** de zéro à une première tranche verticale qui tourne
**Compagnon de :** *Diamy Mail — Guide de prise en main* (à lire d'abord ; ici on passe à l'action)
**Stack :** Rust · PostgreSQL · Docker · Prometheus/Grafana · Claude (Pro/Max)
**Confidentialité :** document interne – W3TEL / TEQTEL

---

## 0. Comment utiliser ce document

Le *Guide de prise en main* explique le **pourquoi** (modèle zéro-accès, invariants, méthode avec Claude). Ce kit-ci est le **comment démarrer concrètement** : les commandes, l'arborescence, le `docker-compose`, et la première brique à faire tourner.

Ordre conseillé : lis le guide (surtout §3 modèle mental et §5 méthode Claude), puis déroule ce kit de haut en bas. Objectif de la semaine 1 : un squelette qui compile, s'observe, et fait passer **un** message de bout en bout de façon simplifiée.

⚠️ Tout ce qui suit (arborescence, `docker-compose`, `Cargo.toml`, extraits de code) est un **squelette de départ**, pas une implémentation validée. C'est un point de départ à faire évoluer avec Claude en s'appuyant sur les annexes — pas une référence normative. La référence, c'est le corpus.

---

## 1. Prérequis à réunir

### Outils (sur ta machine)

- **Rust** (toolchain stable récente) : `rustup`, `cargo`. Ajoute les composants `clippy` et `rustfmt`.
- **Docker** + **Docker Compose**.
- **Git**.
- Utilitaires cargo qui serviront vite : `cargo install cargo-audit cargo-deny sqlx-cli` (et plus tard `cargo-fuzz`).

### Accès à demander (ne pas rester bloqué dessus, mais les lancer tôt)

| Ressource | Auprès de qui | Pour quoi |
|-----------|---------------|-----------|
| **Environnement de dev IAM + jeu de clés de test** | Cédric / équipe IAM | Identité, résolution des principaux, clés (INV-9, A17). Pas de faux IAM. |
| **Primitives crypto du messaging Diamy** | Cédric / équipe messaging | Cible de `diamy-mail-crypto` (ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF). **Tout juste mises en ligne, pas encore stables → NE PAS attendre.** Tu démarres avec le backend `dev-crypto` (§5) et tu brancheras `messaging-crypto` plus tard. À récupérer à terme : labels HKDF + format d'enveloppe exacts (interop). |
| **Domaine de test `w3.tel`** | déjà acté | Adresses de test, boîtes, alignement SPF/DKIM/DMARC. |
| **Serveur MX au bureau** | **Aubin** | Passerelle entrante réelle (`diamy-mxd`, A01) pour tester le vrai chemin SMTP. |
| **DNS / SPF / DKIM / DMARC de `w3.tel`** | **Cédric** (il a la main) | Tout enregistrement (MX, SPF, clé DKIM, politique DMARC). **Reviens vers lui**, ne configure pas toi-même. |
| **Claude Pro (→ Max)** | déjà en place | Ton copilote d'implémentation. |

---

## 2. Configurer Claude pour ce corpus

Avant d'écrire du code, prépare l'outil (détaillé au §5 du guide).

1. **Crée un projet Claude dédié** et déposes-y le corpus (les 30 annexes).
2. **Mets ces instructions de projet** (elles encodent la constitution) :

   > Tu implémentes Diamy Mail à partir d'un corpus de spécifications normatif. Règles absolues :
   > 1. **N'invente jamais un comportement non spécifié.** Si un cas n'est pas couvert, arrête-toi et signale-le comme un trou de spécification, en proposant des options — ne choisis pas en silence.
   > 2. Respecte les invariants A25 (INV-\*). Si une demande semble exiger d'en casser un, signale-le : c'est la demande qui est fausse.
   > 3. Ne réimplémente jamais la crypto, l'identité, ni la normalisation d'adresses — réutilise les briques désignées.
   > 4. Après chaque génération, liste explicitement : (a) les choix faits qui ne sont PAS dans la spec, (b) les invariants vérifiés, (c) les *forbidden patterns* A18/A19 vérifiés.
   > Contexte à charger pour toute tâche : A25 + A00 + l'annexe concernée + A18 (serveur) ou A19 (client).

3. **Réflexe à chaque tâche** : charge le bon contexte (A25 + A00 + annexe + A18/A19), puis fais la boucle de vérification (guide §5.3).

---

## 3. La cible : carte des composants

```mermaid
flowchart TB
    NET([Internet SMTP]) --> MX

    subgraph SRV["Infrastructure serveur - ne voit jamais le clair au repos"]
        MX[diamy-mxd<br/>passerelle entrante<br/>chiffrement frontiere]
        MAIL[diamy-maild<br/>stockage + sync<br/>annuaire de cles par appareil]
        SUB[diamy-submitd<br/>envoi sortant<br/>DKIM + rate limit]
        CAL[diamy-cald<br/>agenda CalDAV/iTIP]
    end

    MX -->|ciphertext + enveloppes + metadata| MAIL
    MAIL -->|sync WSS/HTTPS<br/>notifs = signaux seuls| VAULT
    SUB -->|DKIM signe| NET
    VAULT -->|envoi chiffre cote client| SUB

    subgraph DEV["Zone appareil - seul endroit ou le clair existe"]
        VAULT[Vault client<br/>SQLite chiffre<br/>dechiffrement + rendu Tiptap<br/>recherche + IA locale]
    end

    IAM[(Diamy IAM<br/>identite, appareils, cles<br/>dependance externe)]
    MX -. lecture annuaire .-> IAM
    MAIL -. verif jetons/entitlements .-> IAM
    VAULT -. session/jetons .-> IAM

    OBS[[diamy-obs<br/>Prometheus / Grafana]]
    MX -.-> OBS
    MAIL -.-> OBS
    SUB -.-> OBS
    CAL -.-> OBS
```

Chaque daemon est un service séparé (A00 §4.1) ; ils partagent des crates communes, jamais du copier-coller.

---

## 4. La cible : le flux vertical à démontrer

C'est *le* chemin que la maquette doit rendre vivant en premier.

```mermaid
sequenceDiagram
    participant Ext as Expediteur Internet
    participant MX as diamy-mxd (frontiere)
    participant DB as Stockage (chiffre)
    participant MAIL as diamy-maild (sync)
    participant V as Vault client (appareil)

    Ext->>MX: 1. Mail entrant (SMTP/TLS)
    Note over MX: 2. Controles securite<br/>3. Chiffrement frontiere (AES-256)<br/>4. Enveloppe par appareil (ML-KEM-768)<br/>5. Destruction du clair (zeroize)
    MX->>DB: 6. Ciphertext + enveloppes + metadata
    MAIL-->>V: 7. Notification = signal seul (pas de contenu)
    V->>MAIL: 8. Le client tire ce qu'il decide
    MAIL->>V: 9. Ciphertext + enveloppe de CET appareil
    Note over V: 10. Dechiffrement local<br/>11. Verif tag/signature AVANT usage<br/>12. Rendu Tiptap (schema ferme)
```

Les numéros correspondent aux invariants : 3-5 → INV-1/3/4 (le serveur ne garde pas de clair), 7 → INV-12 (signaux seuls), 11 → INV-8 (rien de non vérifié n'est rendu), 12 → INV-17 (Tiptap, pas de HTML brut).

---

## 5. Arborescence du workspace Rust

Un **workspace Cargo** unique, une crate par daemon + les crates partagées mandatées par A18-TOP-1.

```
diamy-mail/
├── Cargo.toml                # workspace
├── docker-compose.yml
├── SIMPLIFICATIONS.md        # le journal des raccourcis assumes (voir §8)
├── deploy/
│   ├── prometheus/prometheus.yml
│   └── grafana/…
├── crates/
│   ├── diamy-mail-crypto/    # LA seule maison de la crypto (INV-5) - API stable, 2 backends (voir plus bas)
│   ├── diamy-mail-model/     # types de donnees, miroir de la DDL A21
│   ├── diamy-mail-iam/       # client de consommation IAM (A17)
│   ├── diamy-addr/           # diamy_addr_canon() (A24) - partage octet-pour-octet avec le client
│   └── diamy-obs/            # logs structures + metriques Prometheus + sante A22
└── services/
    ├── diamy-mxd/            # passerelle entrante + chiffrement frontiere (A01)
    ├── diamy-maild/          # stockage + sync + annuaire de cles (A02, A04, A17)
    ├── diamy-submitd/        # envoi sortant (A10)
    └── diamy-cald/           # agenda (A12-A15) - plus tard
```

`Cargo.toml` (workspace) de départ :

```toml
[workspace]
resolver = "2"
members = [
  "crates/diamy-mail-crypto",
  "crates/diamy-mail-model",
  "crates/diamy-mail-iam",
  "crates/diamy-addr",
  "crates/diamy-obs",
  "services/diamy-mxd",
  "services/diamy-maild",
  "services/diamy-submitd",
  # "services/diamy-cald",   # active-le quand tu attaques l'agenda
]

[workspace.dependencies]
tokio      = { version = "1", features = ["full"] }   # runtime async (A18-ASYNC-1)
sqlx       = { version = "0.7", features = ["postgres", "runtime-tokio", "tls-rustls", "uuid", "time"] }
thiserror  = "1"        # erreurs typees (A18-ERR-1)
tracing    = "0.1"      # logs structures SANS contenu (A18-LOG-1)
zeroize    = "1"        # effacement memoire non-elidable (A18-ZERO)
subtle     = "2"        # comparaisons constant-time (A18-ERR-4)
getrandom  = "0.2"      # nonces CSPRNG (A18-CRY-3)
uuid       = { version = "1", features = ["v7"] }      # identifiants UUIDv7 (CDM-ID-1)
# --- backend `dev-crypto` UNIQUEMENT (primitives auditees RustCrypto, JAMAIS en prod) ---
aes-gcm    = "0.10"     # AES-256-GCM
hkdf       = "0.12"     # HKDF-SHA256/512
sha2       = "0.10"
ml-kem     = "0.2"      # ML-KEM-768 (FIPS 203) - stand-in dev, cible = primitive messaging
```

Disciplines A18 à mettre **dès le squelette**, pas « plus tard » :

- `#![forbid(unsafe_code)]` en tête de chaque crate quand c'est possible (A18-CI-2).
- Les types « clair » et « clé » enveloppés dans `Zeroizing`, sans `Debug`/`Clone` qui impriment/copient le contenu (A18-ZERO-1/3).
- Les newtypes de type-state utiles très tôt : `CanonicalAddress` (produit uniquement par `diamy_addr_canon`), `DerivedKey` (produit uniquement par HKDF+label), `VerifiedPlaintext` (obtenu uniquement après vérif du tag GCM). Cf. A18 §9 — ça transforme des invariants en erreurs de compilation.
- CI locale : `cargo clippy -- -D warnings`, `cargo audit`, `cargo deny check`.

### La crate `diamy-mail-crypto` : une API, deux backends

Le messaging Diamy (la source des primitives auditées) vient d'être mis en ligne et n'est pas stable. Pour ne pas être bloqué, **structure la crate en API + backend interchangeable** dès le départ :

- **Une API publique stable** : les opérations (`seal_message`, `wrap_key_for_device`, `unwrap_key`, `open_message`, `derive_key`, `sign_manifest`/`verify_manifest`) et les newtypes (`MessageKey`, `DerivedKey`, `Envelope`, `Ciphertext`, `VerifiedPlaintext`, clés d'appareil ML-KEM / d'identité ML-DSA). **Tout le reste du workspace n'appelle QUE cette API**, jamais une primitive directement (INV-5).
- **Deux backends derrière un *feature flag* Cargo** :
  - `dev-crypto` (par défaut pour la maquette) : primitives auditées RustCrypto (`aes-gcm`, `hkdf`, `ml-kem`). Débloque tout le reste **aujourd'hui**. Format/labels provisoires.
  - `messaging-crypto` (cible) : branchement sur les primitives du messaging Diamy quand elles seront stables. La bascule ne touche **que** cette crate.

```toml
# crates/diamy-mail-crypto/Cargo.toml
[features]
default = ["dev-crypto"]
dev-crypto = ["aes-gcm", "hkdf", "sha2", "ml-kem"]
messaging-crypto = []   # branché plus tard sur la primitive messaging
```

Garde-fous (à coder, pas juste à documenter) :

- **`dev-crypto` ne part jamais en prod** : le build de prod n'active pas ce flag, et le service **refuse de démarrer** *fail-closed* s'il détecte `dev-crypto` hors environnement de dev (esprit A18 SEC-FC-1). Un test vérifie ce refus.
- **Pas d'interop dev ↔ messaging** : les données scellées sous `dev-crypto` ne se déchiffrent pas sous `messaging-crypto` (format différent). À la bascule, on **re-provisionne** les données de test — pas de migration.
- Même avec `dev-crypto`, les **frontières** tiennent : le serveur ne stocke que du chiffré, et `open_message` ne rend un `VerifiedPlaintext` qu'après vérif du tag GCM (INV-1/3/8).

---

## 6. `docker-compose` de développement

But : `docker compose up` te donne Postgres + l'observabilité tout de suite, et un emplacement pour brancher les daemons au fur et à mesure. Postgres/Prometheus/Grafana d'abord (victoire rapide, terrain que tu connais), les daemons ensuite.

```yaml
# docker-compose.yml (dev)
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: diamymail
      POSTGRES_USER: diamy
      POSTGRES_PASSWORD: devonly_change_me
    ports: ["5432:5432"]
    volumes: ["pgdata:/var/lib/postgresql/data"]

  prometheus:
    image: prom/prometheus:latest
    volumes: ["./deploy/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro"]
    ports: ["9090:9090"]

  grafana:
    image: grafana/grafana:latest
    environment:
      GF_SECURITY_ADMIN_PASSWORD: devonly_change_me
    ports: ["3000:3000"]
    depends_on: [prometheus]

  # --- Daemons : a activer un par un ---
  # diamy-maild:
  #   build: { context: ., dockerfile: services/diamy-maild/Dockerfile }
  #   environment:
  #     DATABASE_URL: postgres://diamy:devonly_change_me@postgres:5432/diamymail
  #     IAM_ENDPOINT: <fourni par l'env de dev IAM>
  #     MAIL_JWT_TOKEN: <ref secret, jamais en clair ici>
  #   depends_on: [postgres]
  #   ports: ["8443:8443"]

  # diamy-mxd:
  #   build: { context: ., dockerfile: services/diamy-mxd/Dockerfile }
  #   depends_on: [postgres, diamy-maild]
  #   ports: ["2525:2525"]   # SMTP de test

volumes:
  pgdata:
```

`deploy/prometheus/prometheus.yml` :

```yaml
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: diamy-mail
    static_configs:
      - targets:
          # - "diamy-maild:8443"
          # - "diamy-mxd:9101"
```

Rappels sécurité qui s'appliquent même en dev :
- **Aucun secret en clair** dans le compose ni les variables loguées (A18-SEC-1). Les mots de passe ci-dessus sont des placeholders explicitement `devonly`.
- Chaque service devra exposer `/metrics` (Prometheus) et des **indicateurs de santé distincts** des métriques métier (OBS-1, A22).
- Les logs ne portent **jamais** de contenu, sujet, adresse (au-delà du routage), clé ou jeton (INV-21, A18-LOG-1).

---

## 7. Première tranche verticale (l'objectif de démarrage)

Ne cherche pas à tout construire. Vise **un walking skeleton** : le plus fin chemin qui touche toute la chaîne.

**Objectif :** un message de test est « reçu », chiffré à la frontière, stocké **en chiffré**, tiré par un client, déchiffré et rendu.

Découpage suggéré (chaque étape = un aller-retour avec Claude + boucle de vérif) :

1. **Fondation identité/adresse (A24)** — implémente `diamy_addr_canon()` dans `diamy-addr` et fais passer les **13 vecteurs de test normatifs** d'A24 (dont les cas punycode) en test. C'est ta première preuve que la boucle marche.
2. **Crypto derrière `diamy-mail-crypto` — backend `dev-crypto` (A02)** — définis l'API de la crate, implémente le backend `dev-crypto` (primitives auditées RustCrypto, voir §5), puis un round-trip : chiffrer un message (AES-256-GCM), emballer la clé pour une clé publique d'appareil (ML-KEM-768), déballer, vérifier le tag **avant** de rendre le clair (KAT à l'appui). Tu ne réimplémentes rien à la main et **tu n'attends pas le messaging** — son branchement (`messaging-crypto`) est une étape ultérieure isolée, hors du chemin critique.
3. **Stockage (A21, A02)** — un schéma Postgres minimal : le serveur ne stocke que `ciphertext`, enveloppes par appareil, métadonnées. Aucune colonne lisible côté serveur pour le contenu.
4. **Frontière (A01, `diamy-mxd`)** — un point d'entrée qui prend un message de test, applique 2-3 contrôles, chiffre à la frontière, **détruit le clair** (`zeroize`), écrit en base. (Le vrai MX SMTP avec Aubin vient juste après ; commence par une entrée simplifiée si le MX n'est pas prêt — et note-le dans `SIMPLIFICATIONS.md`.)
5. **Sync + client (A04, A03/A19)** — le client reçoit un **signal**, tire le ciphertext + son enveloppe, déchiffre en local, **vérifie**, et projette en Tiptap. Un client en ligne de commande suffit pour la maquette au départ.

**Critère d'acceptation de la tranche :**
- le message traverse toute la chaîne ;
- à aucun moment le clair n'est écrit côté serveur (vérifie la base et les logs) ;
- les vecteurs A24 et le KAT d'enveloppe passent en CI ;
- aucun *forbidden pattern* A18/A19 présent ;
- `SIMPLIFICATIONS.md` liste honnêtement ce qui est bouchonné.

---

## 8. Le fichier `SIMPLIFICATIONS.md`

Crée-le dès le jour 1 et tiens-le à jour. Il distingue « pas encore fait » de « fait faux », et c'est ce qui rend ta maquette **honnête** en revue. Gabarit :

```markdown
# Simplifications assumées de la maquette

| Domaine | Simplification | Raison | Ce que ferait la vraie implem | Annexe |
|---------|----------------|--------|-------------------------------|--------|
| IAM | Env de dev, pas prod | Prod pas prête | Binding IAM prod | A17 |
| Crypto | Backend `dev-crypto` (RustCrypto), pas le messaging | Messaging tout juste en ligne, non stable | Backend `messaging-crypto` + re-provision (pas d'interop) | A02/A18 |
| Révocation | Non implémentée | Mécanisme non confirmé | Selon A17-TOK-2 confirmé | A17 |
| MX | Entrée SMTP simplifiée | MX bureau en cours | MX réel (avec Aubin) | A01 |
| Agenda | Absent | Hors périmètre tranche 1 | diamy-cald | A12-A15 |
```

Règle d'or associée (guide §12) : **si tu modifies la conception, tu mets à jour l'annexe concernée (version + changelog) — jamais de divergence silencieuse code/spec.**

---

## 9. Definition of Done — fin de semaine 1

- [ ] Rust + Docker installés ; `cargo build` du workspace vide passe.
- [ ] Projet Claude configuré avec les instructions du §2.
- [ ] A25 et A00 lus ; carte des composants + glossaire perso produits et relus.
- [ ] `docker compose up` lève Postgres + Prometheus + Grafana ; un dashboard vide s'affiche.
- [ ] `diamy-addr` : `diamy_addr_canon()` passe les 13 vecteurs A24.
- [ ] Accès demandés (IAM+clés, crypto, MX/Aubin) — lancés, même si pas tous obtenus.
- [ ] `SIMPLIFICATIONS.md` initialisé.
- [ ] Liste des questions ouvertes prête pour Cédric (guide §11).

Si tu atteins ça en une semaine, tu es exactement dans le tempo — comme tu l'as été sur l'API vocale.

---

## 10. Qui contacter, pour quoi

- **DNS / SPF / DKIM / DMARC de `w3.tel`** → **Cédric** (il a la main ; ne configure pas toi-même).
- **Serveur MX au bureau** → **Aubin**.
- **Périmètre, priorités, arbitrages de conception, revue** → **Cédric** (ton référent de stage).
- **Accès IAM dev + jeu de clés, accès crate crypto** → **Cédric / équipes IAM & messaging**.

Et le réflexe de fond, encore et toujours : **face à un cas non prévu, on demande et on signale — on n'invente pas.**

---

*Bon démarrage, Hugo. Commence petit et vertical, garde le serveur aveugle au contenu, vérifie chaque génération, et tiens le corpus à jour. Le reste, c'est de l'itération.*
