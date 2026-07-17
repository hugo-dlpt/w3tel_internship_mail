# Guide de démo Diamy Mail — checklist pas-à-pas

Ce document est une « ligne de course » pour lancer la démo complète (réception SMTP →
chiffrement → stockage → bridge IMAP → Thunderbird) sans avoir à comprendre le code. Suis les
étapes DANS L'ORDRE, en copiant-collant les commandes telles quelles.

Toutes les commandes `cd` ci-dessous partent du dossier du projet. Remplace le chemin si besoin :

```bash
cd "/Users/devteqtel/Desktop/STAGE DELEPORTE/PROJET_2/diamy-mail"
```

---

## 1. Nettoyage complet (optionnel, recommandé avant une vraie démo)

**Optionnel si tu continues une session déjà en cours** (les services tournent déjà, tu as déjà
des mails de test dedans, tout fonctionne) → passe directement à l'étape 2 (ou même à l'étape 5
si tout tourne déjà).

**Recommandé avant une présentation** pour repartir sur une base garantie propre et éviter les
surprises (anciens mails de test qui traînent, clés d'appareil désynchronisées).

```bash
cd "/Users/devteqtel/Desktop/STAGE DELEPORTE/PROJET_2/diamy-mail"

# 1. Arrêter tous les services applicatifs (à faire dans chaque terminal où ils tournent) :
#    Ctrl+C dans les terminaux diamy-maild / diamy-mxd / diamy-bridged.
#    Si tu ne sais plus où ils tournent, cette commande les arrête tous d'un coup :
pkill -f "target/debug/diamy-maild"
pkill -f "target/debug/diamy-mxd"
pkill -f "target/debug/diamy-bridged"
pkill -f "target/debug/diamy-submitd"

# 2. Arrêter Postgres/Prometheus/Grafana ET détruire le volume de données Postgres
#    (-v = supprime aussi les données, c'est le "vrai" reset) :
docker compose down -v

# 3. Supprimer les blobs de messages déjà chiffrés sur disque (sinon des messages fantômes
#    peuvent traîner dans le catalogue une fois Postgres relancé) :
rm -rf ./blob_store
rm -rf ./services/diamy-mxd/blob_store
rm -rf ./services/diamy-maild/blob_store

# 4. Supprimer les anciennes clés d'appareil de dev (le Bridge devra être ré-enrôlé, voir §3) :
rm -rf ./dev_secrets
```

> Rien à recréer à la main : les dossiers `blob_store` et `dev_secrets` sont recréés
> automatiquement au prochain démarrage des services / au prochain enrôlement.

---

## 2. Démarrage — dans l'ordre exact, terminal par terminal

Ouvre 5 terminaux. Dans chacun, place-toi d'abord dans le dossier du projet :

```bash
cd "/Users/devteqtel/Desktop/STAGE DELEPORTE/PROJET_2/diamy-mail"
```

### Terminal 1 — Docker (Postgres, Prometheus, Grafana)

```bash
docker compose up -d
docker compose ps
```

✅ **C'est bon si** `docker compose ps` affiche les 3 services (`postgres`, `prometheus`,
`grafana`) avec le statut `Up`/`running`. Ce terminal ne reste pas occupé (les conteneurs
tournent en arrière-plan) — tu peux t'en resservir pour autre chose ensuite.

### Terminal 2 — diamy-maild (API de sync)

```bash
RUST_LOG=diamy_maild=debug cargo run -p diamy-maild
```

✅ **C'est bon quand tu vois cette ligne** (peut prendre 1-2 min la première fois, le temps de
compiler) :
```
== diamy-maild : API de sync (lecture seule, HTTPS, 127.0.0.1 uniquement, authentifiée) sur 127.0.0.1:8443 ==
```
Laisse ce terminal ouvert, ne ferme pas.

### Terminal 3 — diamy-mxd (réception SMTP + chiffrement)

```bash
cargo run -p diamy-mxd
```

✅ **C'est bon quand tu vois** :
```
== diamy-mxd : SMTP sur 0.0.0.0:2525 — STARTTLS dispo (essaie : swaks --to hugo@w3.tel --server 127.0.0.1:2525 -tls) ==
== diamy-mxd : /metrics sur 0.0.0.0:9102 ==
```
Laisse ce terminal ouvert.

### Terminal 4 — diamy-submitd (envoi sortant, A10/A20-SMTP-1)

```bash
RUST_LOG=diamy_submitd=debug cargo run -p diamy-submitd
```

✅ **C'est bon quand tu vois** :
```
== diamy-submitd : POST /submit sur 127.0.0.1:8446 (HTTPS, authentifié, tranche démo — pas de DKIM/SPF/rate-limit) ==
```
Laisse ce terminal ouvert. **Sans ce service, l'envoi depuis Thunderbird échouera** (le Bridge
délègue systématiquement l'émission à `diamy-submitd`, A20-SMTP-1 — il ne parle jamais SMTP
sortant lui-même).

### Terminal 5 — diamy-bridged (pont IMAP + SMTP local pour Thunderbird)

```bash
RUST_LOG=diamy_bridged=debug cargo run -p diamy-bridged
```

✅ **C'est bon quand tu vois** :
```
== diamy-bridged : IMAP sur 127.0.0.1:1143 (loopback uniquement, A20-ARCH-2) ==
   Compte de démo : utilisateur="hugo@w3.tel" — voir DIAMY_BRIDGED_IMAP_USER/DIAMY_BRIDGED_IMAP_PASSWORD
== diamy-bridged : SMTP sur 127.0.0.1:1587 (loopback uniquement, A20-SMTP-1) ==
```
Laisse ce terminal ouvert.

> Tu peux lancer une SECONDE instance de `diamy-bridged` (un second compte de démo, ex.
> `cedric@w3.tel`, pour montrer un échange entre deux comptes) — voir le **§6 Scénario avancé**,
> après avoir terminé le scénario à un seul compte ci-dessous (§3 à §5bis).

### ⚠️ Warning à ignorer, ça n'annonce rien de grave

Sur `diamy-maild` et `diamy-mxd`, tu peux voir ce message au démarrage :
```
warning: the following packages contain code that will be rejected by a future version of Rust: sqlx-postgres v0.7.4
```
**C'est sans danger** — ce n'est pas une erreur, juste un avertissement de compatibilité future
de la bibliothèque Postgres. Ignore-le et continue.

---

## 3. Enrôlement du Bridge (uniquement après un nettoyage complet, étape 1)

Si tu viens de faire le nettoyage complet (ou si c'est la toute première fois), le Bridge a
besoin de sa propre clé d'appareil. Dans n'importe quel terminal libre :

```bash
cd "/Users/devteqtel/Desktop/STAGE DELEPORTE/PROJET_2/diamy-mail"
cargo run --example enroll_bridge_device -p diamy-mail-storage -- hugo@w3.tel
```

✅ **C'est bon quand tu vois** :
```
Appareil BRIDGE enrôlé pour hugo@w3.tel (principal ...), device_id=...
Clé privée du Bridge (...) persistée dans ./dev_secrets/hugo_w3_tel.bridge.devicekey (...)
```

> Si tu n'as PAS fait le nettoyage complet et que cette clé existe déjà, tu peux sauter cette
> étape (le Bridge lit la clé existante au démarrage).

---

## 4. Envoyer un mail de test

Commande fiable et déjà validée — expéditeur `cedric@w3.tel` (un compte de démo déjà provisionné,
fonctionne à coup sûr) :

```bash
swaks --to hugo@w3.tel \
      --from cedric@w3.tel \
      --server 127.0.0.1:2525 \
      -tls \
      --header "Subject: [SUJET ICI]" \
      --body "[CORPS DU MESSAGE ICI]"
```

Remplace juste `[SUJET ICI]` et `[CORPS DU MESSAGE ICI]` — ne touche à rien d'autre dans la
commande.

✅ **C'est bon quand tu vois, tout en bas** :
```
<~  250 message accepte
 ~> QUIT
<~  221 au revoir
```

---

## 5. Voir le mail dans Thunderbird

**Après CHAQUE envoi de mail**, clique sur **« Récupérer les messages »** dans Thunderbird — il
n'y a pas de notification automatique en V1, le client doit interroger le serveur activement.

**Bonne nouvelle** : depuis le dernier correctif, **un simple clic sur « Récupérer les
messages » suffit désormais**, même sur une connexion IMAP déjà ouverte depuis un moment — pas
besoin de déconnecter/reconnecter le compte à chaque fois. (Tu ne dois déconnecter/reconnecter
que si tu viens de **relancer le processus `diamy-bridged`** lui-même — dans ce cas la vieille
connexion est coupée, et un premier clic peut ne rien faire : refais-en un second si besoin.)

### Paramètres du compte Thunderbird (à ne saisir qu'une fois — ou après un nettoyage complet)

| Paramètre | Valeur |
|---|---|
| Serveur entrant | `127.0.0.1` |
| Port | `1143` |
| Sécurité de la connexion | **Aucune** |
| Méthode d'authentification | **Mot de passe, non sécurisé** |
| Nom d'utilisateur | `hugo@w3.tel` |
| Mot de passe | `devonly_change_me_bridge_password` |

---

## 5bis. Envoyer un mail DEPUIS Thunderbird (chemin sortant, A10/A20-SMTP-1)

### Paramètres du serveur SORTANT (SMTP) — à ajouter au même compte

Dans Thunderbird : **Paramètres des comptes → Serveur sortant (SMTP) → Ajouter** (ou modifier
l'entrée existante si Thunderbird en a créé une automatiquement) :

| Paramètre | Valeur |
|---|---|
| Nom du serveur | `127.0.0.1` |
| Port | `1587` |
| Sécurité de la connexion | **Aucune** |
| Méthode d'authentification | **Mot de passe, non sécurisé** |
| Nom d'utilisateur | `hugo@w3.tel` |
| Mot de passe | `devonly_change_me_bridge_password` |

Ce sont EXACTEMENT les mêmes identifiants que le serveur entrant (§5) — un seul compte de démo
préconfiguré sert pour IMAP et SMTP (simplification assumée, voir `SIMPLIFICATIONS.md`).

### Test en boucle fermée : envoie-toi un mail à toi-même

Terminal 4 (`diamy-submitd`) et Terminal 5 (`diamy-bridged`) doivent tourner. Dans Thunderbird,
compose un nouveau message :
- **À** : `cedric@w3.tel` (ou `hugo@w3.tel` toi-même) — un domaine `@w3.tel` est traité comme
  "local" par `diamy-submitd` (`DIAMY_SUBMITD_LOCAL_DOMAINS`) et réinjecté directement dans
  `diamy-mxd`, sans sortir sur Internet : la démo fonctionne même sans connexion réseau externe.
- Sujet/corps : ce que tu veux.
- Clique **Envoyer**.

✅ **C'est bon si** l'envoi ne remonte AUCUNE erreur dans Thunderbird, et si tu vois dans le
terminal `diamy-bridged` (avec `RUST_LOG=diamy_bridged=debug`) une ligne du style :
```
soumission SMTP recue, transmission a diamy-submitd (A10, pas de relais direct)
```
puis dans le terminal `diamy-submitd` une ligne confirmant le relais accepté. Ensuite, **clique
sur « Récupérer les messages »** (§5) sur le compte destinataire pour voir le mail arriver —
même mécanisme de réception que pour un mail envoyé par `swaks` (§4).

> Le mail envoyé depuis Thunderbird n'apparaît PAS dans un dossier « Envoyés » : cette V1 ne
> construit pas la copie « Envoyés » chiffrée côté client (A02 §5.2) — voir `SIMPLIFICATIONS.md`.
> Seule l'émission a lieu.

**Envie de montrer un échange entre DEUX personnes distinctes plutôt qu'un aller-retour avec
toi-même ?** → passe au **§6. Scénario avancé : échange entre deux comptes (hugo ↔ cedric)**
ci-dessous.

---

## 6. Scénario avancé : échange entre deux comptes (hugo ↔ cedric)

Ce scénario ajoute un **second compte de démo** (`cedric@w3.tel`) avec sa **propre instance**
`diamy-bridged`, pour montrer un VRAI échange entre deux personnes dans Thunderbird — hugo envoie,
cedric reçoit — plutôt qu'un aller-retour sur un seul compte (§5bis).

### Le principe (à comprendre avant de taper les commandes)

**Un Bridge = un appareil = un utilisateur.** Ce n'est jamais un Bridge « multi-comptes » qu'on
configurerait pour accepter plusieurs utilisateurs à la fois — chaque instance `diamy-bridged` est
son PROPRE appareil enrôlé, avec ses PROPRES clés de chiffrement, exactement comme si c'était un
téléphone ou un ordinateur différent (A20-CRED-4b). C'est pour ça qu'on ne peut pas juste
« ajouter un second compte » à l'instance de hugo déjà lancée : il faut une SECONDE instance
séparée, celle de cedric, avec son propre enrôlement, ses propres ports d'écoute, et son propre
processus. Les deux instances parlent au MÊME `diamy-maild`/`diamy-mxd`/`diamy-submitd` — c'est le
serveur qui est partagé, jamais le Bridge lui-même.

### Prérequis

Les **Terminaux 1 à 5 du §2** doivent déjà tourner (Docker, `diamy-maild`, `diamy-mxd`,
`diamy-submitd`, et l'instance `diamy-bridged` de hugo) — ce scénario ne les répète pas, il
AJOUTE une sixième pièce à côté. Si tu peux déjà envoyer un mail à hugo et le voir dans
Thunderbird (§4-§5), tu es prêt.

### Étape A — Enrôler l'appareil Bridge de cedric (une seule fois)

Comme au §3, mais avec l'adresse de cedric. Dans n'importe quel terminal libre :

```bash
cd "/Users/devteqtel/Desktop/STAGE DELEPORTE/PROJET_2/diamy-mail"
cargo run --example enroll_bridge_device -p diamy-mail-storage -- cedric@w3.tel
```

✅ **C'est bon quand tu vois** :
```
Appareil BRIDGE enrôlé pour cedric@w3.tel (principal ...), device_id=...
Clé privée du Bridge (...) persistée dans ./dev_secrets/cedric_w3_tel.bridge.devicekey (...)
```

> Si cette clé existe déjà (tu as déjà fait ce scénario avant, sans nettoyage complet depuis), tu
> peux sauter cette étape — le Bridge lit la clé existante au démarrage.

### Étape B — Terminal 6 : la seconde instance `diamy-bridged` (cedric)

Le **Terminal 5** reste celui de hugo, **inchangé, ne le touche pas**. Ouvre un **SIXIÈME**
terminal, place-toi dans le dossier du projet, puis lance :

```bash
cd "/Users/devteqtel/Desktop/STAGE DELEPORTE/PROJET_2/diamy-mail"
DIAMY_BRIDGED_IMAP_USER=cedric@w3.tel \
DIAMY_BRIDGED_IMAP_PASSWORD=devonly_change_me_bridge_password \
DIAMY_BRIDGED_IMAP_PORT=1144 \
DIAMY_BRIDGED_SMTP_PORT=1588 \
RUST_LOG=diamy_bridged=debug cargo run -p diamy-bridged
```

✅ **C'est bon quand tu vois** :
```
== diamy-bridged : IMAP sur 127.0.0.1:1144 (loopback uniquement, A20-ARCH-2) ==
   Compte de démo : utilisateur="cedric@w3.tel" — voir DIAMY_BRIDGED_IMAP_USER/DIAMY_BRIDGED_IMAP_PASSWORD
== diamy-bridged : SMTP sur 127.0.0.1:1588 (loopback uniquement, A20-SMTP-1) ==
```
Laisse ce terminal ouvert (comme les 5 précédents).

> Les ports 1144/1588 sont un choix arbitraire (n'importe quel port libre convient) — ce qui
> compte, c'est qu'ils soient DIFFÉRENTS de ceux de hugo (1143/1587, Terminal 5). L'IP reste
> TOUJOURS `127.0.0.1` quel que soit le port choisi (A20-ARCH-2/NET-1, non négociable) — ces
> variables ne relâchent jamais la contrainte loopback-only, elles ne font que choisir LEQUEL
> port loopback est utilisé.

### Étape C — Ajouter le compte de cedric dans Thunderbird

Ajoute un DEUXIÈME compte dans Thunderbird (**Paramètres des comptes → Actions du compte →
Ajouter un compte Courrier**), avec ces paramètres — même forme que ceux de hugo (§5/§5bis), mais
pointant vers le Terminal 6 (ports 1144/1588) :

**Serveur entrant (IMAP)**

| Paramètre | Valeur |
|---|---|
| Serveur entrant | `127.0.0.1` |
| Port | `1144` |
| Sécurité de la connexion | **Aucune** |
| Méthode d'authentification | **Mot de passe, non sécurisé** |
| Nom d'utilisateur | `cedric@w3.tel` |
| Mot de passe | `devonly_change_me_bridge_password` |

**Serveur sortant (SMTP)**

| Paramètre | Valeur |
|---|---|
| Nom du serveur | `127.0.0.1` |
| Port | `1588` |
| Sécurité de la connexion | **Aucune** |
| Méthode d'authentification | **Mot de passe, non sécurisé** |
| Nom d'utilisateur | `cedric@w3.tel` |
| Mot de passe | `devonly_change_me_bridge_password` |

Tu as maintenant DEUX comptes dans Thunderbird : celui de hugo (port 1143/1587) et celui de
cedric (port 1144/1588), chacun parlant à SA PROPRE instance Bridge.

### Étape D — Scénario de test recommandé : hugo envoie, cedric reçoit

1. Dans le compte **hugo** de Thunderbird, compose un nouveau message :
   - **À** : `cedric@w3.tel`
   - Sujet/corps : ce que tu veux.
   - Clique **Envoyer**.
2. ✅ **C'est bon si** l'envoi ne remonte aucune erreur (même vérification qu'au §5bis).
3. Dans le compte **cedric** de Thunderbird, clique **« Récupérer les messages »** — le mail
   envoyé par hugo doit apparaître dans la boîte de cedric.
4. Pour montrer que l'état lu/supprimé est bien réel (A04 §3/§5.3, pas un stand-in), **sur le
   compte cedric** :
   - Ouvre le mail reçu de hugo pour le marquer **lu** (`\Seen`) — clique **« Récupérer les
     messages »** une seconde fois (nouvelle interrogation réseau du serveur, pas un simple
     rafraîchissement d'affichage local) : le mail reste marqué lu, preuve que l'état est bien
     enregistré côté serveur, pas seulement dans la fenêtre Thunderbird ouverte.
   - Supprime le mail (touche Suppr, ou clic droit → Supprimer), puis vide la Corbeille (ou
     laisse Thunderbird envoyer `EXPUNGE`) : re-clique **« Récupérer les messages »** — le mail a
     bien disparu, et ceci n'affecte en rien la boîte de hugo (compte, principal, et instance
     Bridge totalement distincts — voir le principe ci-dessus).

---

## 7. Dépannage rapide

**« Address already in use » au démarrage d'un service (port déjà occupé)**
Une instance précédente tourne encore sur ce port. Trouve-la et arrête-la (remplace `PORT` par
`2525` pour mxd, `8443` pour maild, `1143` pour l'IMAP du bridged, `1587` pour le SMTP du
bridged, `8446` pour submitd) :
```bash
lsof -i :PORT
kill <PID_affiché>
```
Puis relance normalement (étape 2).

**Postgres ne démarre pas / erreur au démarrage du conteneur**
Vérifie les logs :
```bash
docker compose logs postgres
```
Si erreur de verrou (`bogus data in lock file`) ou tout autre souci de démarrage, le plus sûr
est de refaire le nettoyage complet de l'étape 1 (`docker compose down -v` puis `docker compose
up -d`). Ce n'est PAS un conflit avec un Postgres natif déjà installé sur la machine : Postgres
tourne ici sur le port **5433** (pas 5432) précisément pour éviter ce conflit.

**Le mail n'apparaît pas dans Thunderbird**
1. As-tu cliqué sur « Récupérer les messages » APRÈS l'envoi (voir étape 5) ? C'est la cause la
   plus fréquente.
2. Le mail est-il bien parti (`250 message accepte` à la fin de la commande swaks, étape 4 — ou
   pas d'erreur d'envoi dans Thunderbird pour un envoi depuis le client, étape 5bis) ?
3. Les 4 services (`diamy-maild`, `diamy-mxd`, `diamy-submitd`, `diamy-bridged`) tournent-ils
   toujours (les 4 terminaux sont bien restés ouverts) ?

**Erreur d'envoi dans Thunderbird ("impossible d'envoyer le message")**
1. Le terminal `diamy-submitd` (Terminal 4) tourne-t-il ? Sans lui, le Bridge ne peut relayer
   aucun envoi (A20-SMTP-1 : il ne relaie jamais lui-même).
2. Le destinataire est-il bien un domaine connu (`@w3.tel`) ou une adresse jamais enrôlée
   (`aubin@w3.tel` est volontairement réservé "sans appareil" dans toute la suite de tests) ?

**`cargo run` recompile à chaque fois / c'est long**
Normal la première fois après un changement de code ou un `docker compose down -v` +
redémarrage. Les lancements suivants sont quasi instantanés.

**« Address already in use » au lancement du Terminal 6 (seconde instance Bridge, §6)**
Tu as oublié de changer `DIAMY_BRIDGED_IMAP_PORT`/`DIAMY_BRIDGED_SMTP_PORT` — l'instance de
cedric essaie alors de se lancer sur les MÊMES ports que celle de hugo (1143/1587, Terminal 5),
déjà occupés. Vérifie que la commande du §6 Étape B porte bien les 4 variables d'environnement
(`DIAMY_BRIDGED_IMAP_USER`, `_PASSWORD`, `_PORT`, `DIAMY_BRIDGED_SMTP_PORT`) — pas seulement
l'utilisateur.

**Le compte cedric dans Thunderbird ne se connecte pas, ou semble être le compte de hugo**
Vérifie les ports saisis dans les paramètres du compte cedric (§6 Étape C) : `1144`/`1588`, PAS
`1143`/`1587` (ceux de hugo). Si les deux comptes Thunderbird pointent par erreur vers les MÊMES
ports, le second compte parle en fait à l'instance Bridge de hugo — tu verrais alors les mails
de hugo apparaître dans le compte censé être celui de cedric (ou une erreur d'identifiants,
puisque le nom d'utilisateur/mot de passe attendus par l'instance de hugo sont ceux de hugo).

---

## 8. Arrêt propre en fin de démo

1. Dans chaque terminal où un service `cargo run` tourne (maild, mxd, submitd, bridged de hugo
   — et, si tu as suivi le §6, bridged de cedric au Terminal 6) : `Ctrl+C`.
2. Puis, dans un terminal quelconque :
```bash
cd "/Users/devteqtel/Desktop/STAGE DELEPORTE/PROJET_2/diamy-mail"
docker compose down
```
   (SANS `-v` ici, pour garder les données si tu veux reprendre la démo plus tard sans tout
   ré-enrôler — utilise `docker compose down -v` uniquement si tu veux un vrai reset, voir §1.)
