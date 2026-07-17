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

Ouvre 4 terminaux. Dans chacun, place-toi d'abord dans le dossier du projet :

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

### Terminal 4 — diamy-bridged (pont IMAP local pour Thunderbird)

```bash
RUST_LOG=diamy_bridged=debug cargo run -p diamy-bridged
```

✅ **C'est bon quand tu vois** :
```
== diamy-bridged : IMAP sur 127.0.0.1:1143 (loopback uniquement, A20-ARCH-2) ==
   Compte de démo : utilisateur="hugo@w3.tel" — voir DIAMY_BRIDGED_IMAP_USER/DIAMY_BRIDGED_IMAP_PASSWORD
```
Laisse ce terminal ouvert.

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

## 6. Dépannage rapide

**« Address already in use » au démarrage d'un service (port déjà occupé)**
Une instance précédente tourne encore sur ce port. Trouve-la et arrête-la (remplace `PORT` par
`2525` pour mxd, `8443` pour maild, `1143` pour bridged) :
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
2. Le mail est-il bien parti (`250 message accepte` à la fin de la commande swaks, étape 4) ?
3. Les 3 services (`diamy-maild`, `diamy-mxd`, `diamy-bridged`) tournent-ils toujours (les 3
   terminaux sont bien restés ouverts) ?

**`cargo run` recompile à chaque fois / c'est long**
Normal la première fois après un changement de code ou un `docker compose down -v` +
redémarrage. Les lancements suivants sont quasi instantanés.

---

## 7. Arrêt propre en fin de démo

1. Dans chaque terminal où un service `cargo run` tourne (maild, mxd, bridged) : `Ctrl+C`.
2. Puis, dans un terminal quelconque :
```bash
cd "/Users/devteqtel/Desktop/STAGE DELEPORTE/PROJET_2/diamy-mail"
docker compose down
```
   (SANS `-v` ici, pour garder les données si tu veux reprendre la démo plus tard sans tout
   ré-enrôler — utilise `docker compose down -v` uniquement si tu veux un vrai reset, voir §1.)
