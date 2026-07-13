# Diamy Mail — Guide de prise en main

**Objet :** monter la maquette de Diamy Mail à partir du corpus de spécifications
**Pour :** Hugo (reprise du projet)
**De :** Cédric BORNECQUE
**Outil principal :** Claude (Pro/Max) piloté sur le corpus
**Confidentialité :** document interne – W3TEL / TEQTEL

---

## 0. À lire en premier (2 minutes)

Bienvenue sur Diamy Mail, Hugo. Tu as fait du très bon travail sur l'API vocale en une semaine ; ce projet-ci est d'une autre nature, et c'est voulu que je te le confie maintenant.

Trois choses à intégrer avant tout le reste :

1. **Ta mission n'est pas d'inventer un produit, c'est de matérialiser une spécification qui existe déjà.** Le corpus (30 documents) décrit Diamy Mail dans le détail. Ton livrable est une **maquette** : un squelette qui tourne et qui *démontre* l'architecture, pas le produit final de production.

2. **Diamy Mail n'est pas « une messagerie de plus ».** C'est une messagerie **à zéro-accès** : les serveurs ne doivent jamais pouvoir lire le contenu des mails. Cette contrainte gouverne *toutes* les décisions techniques. Si à un moment tu te retrouves à faire lire le contenu par le serveur « juste pour la démo », tu as construit la mauvaise chose. On y revient au §3.

3. **Le corpus est écrit pour être implémenté avec une IA de code.** C'est exactement ton cas d'usage. Mais il y a une discipline précise à respecter avec Claude, sinon il va « boucher les trous » en inventant — ce qui est le pire résultat possible ici. On y revient au §5.

Prends le temps des §3 et §5 : ce sont eux qui font la différence entre une maquette juste et une maquette qui a l'air de marcher mais trahit l'architecture.

---

## 1. Diamy Mail en une page

Diamy Mail est une **plateforme mail + agenda sécurisée, B2B** (chaque utilisateur appartient à une organisation « tenant »). Elle se compose de :

- une **passerelle entrante (MX)** qui chiffre le courrier « à la frontière », dès la réception SMTP, avant tout stockage ;
- un **stockage chiffré par appareil** (modèle « enveloppe ») : le serveur ne stocke que du chiffré ;
- un **client « vault » local-first** (desktop/mobile) qui fonctionne hors-ligne, avec sa base SQLite chiffrée et sa recherche locale ;
- un **chemin d'envoi sortant** avec limitation de débit par expéditeur, signature DKIM et gestion de réputation d'IP ;
- un **moteur d'analyse de confiance** (origine du message, liens, pièces jointes) qui produit un score explicable ;
- un **rendu par schéma fermé Tiptap-JSON** à la place du rendu HTML brut (sécurité d'affichage) ;
- un **sous-système agenda** (CalDAV / iTIP / iMIP, récurrences RFC 5545, fuseaux horaires, disponibilité) ;
- une intégration avec **Diamy IAM** pour l'identité, les appareils et les clés (à réutiliser, **pas** à réimplémenter).

Les composants serveur sont des services séparés : `diamy-mxd` (entrant), `diamy-maild` (stockage/sync), `diamy-submitd` (sortant), `diamy-cald` (agenda), plus le `diamy-bridged` (façade IMAP/SMTP locale pour Thunderbird/Outlook).

Diamy Mail **réutilise** des briques Diamy existantes (IAM, primitives cryptographiques du messaging). Ce n'est pas un produit isolé : c'est une pièce d'un écosystème.

---

## 2. Ce qu'est — et n'est pas — « la maquette »

On te demande une **maquette**, terme à cadrer précisément (à confirmer avec Cédric, voir §11) :

**La maquette DOIT :**
- tourner (conteneurs déployables, `docker compose up` et ça vit) ;
- démontrer le **chemin vertical** de bout en bout sur un cas simple : un mail entre → il est chiffré à la frontière → stocké en chiffré → synchronisé vers un client → déchiffré et rendu via Tiptap sur l'appareil ;
- respecter **structurellement** les invariants d'architecture (le serveur ne voit pas le contenu en clair), même si certains détails sont simplifiés ;
- être observable dès le départ (métriques Prometheus, dashboards Grafana) — c'est ton point fort, sers-t'en tôt.

**La maquette PEUT (simplifications assumées, à documenter) :**
- bouchonner des dépendances externes réellement indisponibles — **à condition de garder les frontières au bon endroit**. Attention : **l'IAM n'est pas à bouchonner**. Il n'est pas encore en production, mais il fournit un **environnement de dev avec un jeu de clés de test** : on s'appuie dessus (voir §6 et §7), pas sur un faux IAM ;
- ne couvrir qu'un sous-ensemble des annexes (par ex. laisser l'agenda pour plus tard) ;
- ne pas viser la performance ni la résistance à la charge.

**La maquette NE DOIT PAS :**
- relâcher un invariant « pour aller plus vite » (par ex. stocker du clair côté serveur, même temporairement, hors des exceptions déclarées) — ça vide le projet de son sens ;
- réimplémenter la crypto, l'identité, ou la normalisation d'adresses (voir §3 et §5) ;
- partir en production. C'est une maquette.

Règle simple : **on peut simplifier la force, jamais les frontières.** Utiliser des clés de dev plus faibles, oui ; laisser le serveur lire le contenu, non.

---

## 3. Le modèle mental non-négociable

C'est le cœur. Si tu ne retiens qu'une section, c'est celle-ci.

### 3.1 Trois zones, et une seule où le clair a le droit d'exister

1. **Zone appareil** — le clair est autorisé **ici et nulle part ailleurs** : c'est le seul endroit où le contenu déchiffré, les pièces jointes et le rendu existent.
2. **Zone frontière (MX entrant, RAM transitoire)** — le clair existe brièvement pour le courrier Internet entrant pendant la réception SMTP et les contrôles de sécurité, puis **doit être détruit** immédiatement après le chiffrement frontière. Aucun clair persistant.
3. **Infrastructure de chiffré** — tout le stockage (blobs, catalogue, sauvegardes, object storage) ne contient que du chiffré. Les serveurs ne détiennent **aucune** clé privée ni clé de déchiffrement de message.

### 3.2 Serveur « honnête mais curieux »

On modélise le serveur comme *honest-but-curious* : on suppose qu'un attaquant peut lire tout le stockage, et l'architecture doit garantir qu'il n'en tire **aucun** contenu en clair. Autrement dit : la confidentialité ne repose jamais sur la confiance dans le serveur.

### 3.3 Les invariants (extraits d'A25 — la « constitution »)

Le document **A25** liste les invariants du corpus. Ce sont des propriétés qui tiennent **partout** ; en violer un est un défaut d'architecture, pas un bug local. Les plus structurants pour la maquette :

- **INV-1** : le serveur ne peut pas déchiffrer le contenu des boîtes synchronisées. Il stocke du chiffré + des enveloppes par appareil qu'il ne peut pas ouvrir.
- **INV-3** : le clair n'existe que dans des **exceptions déclarées et bornées** (frontière entrante, file d'attente `k_hold`, sandbox pièce jointe, fenêtre d'émission sortante, matériel webmail, iMIP vers invité externe, projection libre/occupé, Bridge local). Rien en dehors de cette liste n'expose de clair.
- **INV-4** : les clés privées ne quittent jamais le coffre sécurisé de l'OS (natif).
- **INV-5** : la crypto n'est **jamais** réimplémentée — on réutilise les primitives Diamy auditées (ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF).
- **INV-9 / INV-10** : l'identité passe **toujours** par Diamy IAM ; les adresses sont canonicalisées par **une seule** fonction partagée avant tout lookup/hash/comparaison.
- **INV-12** : le serveur ne pousse jamais de contenu ; les notifications sont des **signaux seulement**, le client tire ce qu'il décide.
- **INV-16** : **fail-closed** sur toute erreur de sécurité (déchiffrement, vérif, auth, clé) — on rejette/temporise/met en file, on ne poursuit jamais avec des données non vérifiées.
- **INV-17** : rendu Tiptap à schéma fermé par défaut ; HTML brut uniquement dans une sandbox isolée, jamais en repli.

Tu n'as pas besoin de tous les mémoriser aujourd'hui. Tu dois savoir qu'ils existent, où ils sont (A25 §2), et que **le code que tu génères avec Claude doit être vérifié contre eux** (§5).

---

## 4. Comment le corpus est organisé

Le corpus = 1 document maître + des annexes. Chaque annexe hérite des règles transverses du maître.

- **A00 — Architecture maîtresse** : le périmètre, la carte des composants, les règles transverses (données, API, sécurité), le plan du corpus. C'est le cadre.
- **A25 — Invariants & constitution** : le document racine, à lire **en premier**. Les invariants (INV-\*) et les règles ordonnées que suit l'implémenteur quand la spec ne dit pas quoi faire.
- **A01–A24** : les annexes « feature » (passerelle, stockage, sync, recherche, confiance, rendu, sortant, onboarding, agenda, IAM, DDL, santé…).
- **A18 / A19** : la discipline d'implémentation, respectivement **serveur (Rust)** et **client (SDK)**.
- **A21 / A22** : le schéma physique (DDL, source de vérité) et les seuils de santé.
- **A26–A29** : extensions (multi-comptes, ressources partagées, présence, UX de confiance).

### Ordre de lecture (pour comprendre)

**A25 → A00 → l'annexe (ou les annexes) de la tâche → A18/A19 → A21/A22 au besoin.**
A25 et A00 posent le cadre qu'aucune annexe ne peut violer ; l'annexe feature pose la tâche ; A18/A19 disent comment construire ; A21/A22 donnent la réalité physique/opérationnelle.

### Ordre de production (pour construire)

Cédric recommande (dans A00) : **A24 → A17 → A02 → A01 → A03 → A04 → A05 → A08 → A06 → A07 → A09 → A10 → A11 → A23 → A16 → A21 → A22 → A18 → A19 → A12 → A13 → A14 → A15 → A20.**
Logique : la normalisation d'identité/adresse d'abord (A24, c'est la clé de jointure dont tout dépend), puis identité/stockage/passerelle (la fondation), puis le sortant/onboarding, et l'agenda en dernier (le plus risqué côté interopérabilité tierce).

Pour une **maquette**, tu ne suivras pas tout cet ordre : tu viseras d'abord un chemin vertical fin (§7).

> **Important :** l'état d'avancement réel du corpus, ce qui reste ouvert, et une **règle impérative** sur la mise à jour des specs quand tu modifies la conception sont au **§12**. Lis-le avant d'écrire du code.

---

## 5. Travailler avec Claude sur ce corpus — la méthode

C'est le point le plus important après le §3. Le corpus est conçu pour l'implémentation assistée par IA, mais avec une règle de fer.

### 5.1 La règle d'or : ne jamais inventer un cas non spécifié

La **règle 2 de la constitution (A25 §3)** dit textuellement : *si un cas n'est pas couvert, ne l'invente pas — arrête-toi et signale-le comme un trou de spécification.* C'est « la règle la plus importante pour l'implémentation IA ».

Concrètement, quand tu pilotes Claude :

- Mets cette règle **dans ton prompt système / tes instructions de projet** : « Si la spécification ne couvre pas un cas, ne l'invente pas : signale-le explicitement comme un gap à trancher, et propose des options plutôt que d'en choisir une en silence. »
- Quand Claude produit du code, **demande-lui systématiquement** : « Quels choix as-tu faits qui ne sont PAS dans la spec ? » Ces choix-là sont tes points de vigilance.
- Un comportement inventé, c'est comme ça qu'un cas non spécifié devient un bug. Mieux vaut une question ouverte qu'une réponse fausse silencieuse.

### 5.2 Charge le bon contexte

Avant de faire produire du code sur une brique, donne à Claude : **A25 + A00 + l'annexe concernée + A18 (serveur) ou A19 (client)**. Ne le lance pas sur une annexe seule : il lui manquerait le cadre et les invariants.

### 5.3 La boucle de vérification (obligatoire)

Après chaque génération, fais passer le code contre **deux listes** :

1. la section **« Common AI Implementation Errors »** de l'annexe touchée (« est-ce que la logique *de cette feature* est correcte ? ») ;
2. la liste **« Forbidden Patterns » d'A18 §13 (serveur) ou A19 §11 (client)** (« est-ce que la *discipline* de sécurité a été suivie partout ? »).

A18 est explicitement pensée comme **la porte de revue unique** : un changement n'est prêt que quand il passe la watch-list de son annexe **et** les forbidden-patterns d'A18/A19.

### 5.4 Le top des erreurs IA à traquer (extrait)

Ces pièges reviennent tout le temps ; garde-les sous les yeux :

- hacher la **chaîne** d'un UUID au lieu de sa forme binaire 16 octets ;
- utiliser un secret brut **directement** comme clé au lieu de dériver via HKDF avec un label explicite ;
- rendre du **HTML brut** au lieu de passer par le schéma fermé Tiptap ;
- **stocker du clair** à une couche persistante (logs, caches, fichiers temp, backups compris) ;
- traiter une **archive protégée par mot de passe** comme « vide/propre » parce qu'on n'a pas pu l'ouvrir, au lieu de « risque maximal » ;
- pousser du **contenu dans les notifications** au lieu de signaux seulement ;
- autoriser un **envoi sortant avant** l'alignement SPF/DKIM/DMARC ;
- **réimplémenter** l'identité/la session/les clés déjà possédées par IAM ;
- utiliser **deux implémentations différentes** de normalisation d'adresse (identité vs Blind Index) → recherche/routage qui ratent silencieusement ;
- côté requêtes : oublier que **chaque appel client porte deux credentials indépendants** (l'AppKey Tier 2 « quelle application » + le jeton mail-plane « quel utilisateur »), validés dans un ordre fixe par un middleware partagé — pas des checks inline par endpoint.

### 5.5 Encoder les invariants dans les types

Quand c'est possible (surtout côté Rust), fais transformer un invariant en **erreur de compilation** plutôt qu'en bug runtime : un type `VerifiedPlaintext` qu'on n'obtient que d'un déchiffrement dont le tag GCM a été vérifié ; un `DerivedKey` qu'on n'obtient que de HKDF-avec-label ; une `CanonicalAddress` produite uniquement par la fonction de normalisation. C'est la recommandation A18 §9, et c'est ce qui neutralise des classes entières d'erreurs.

---

## 6. La stack et l'environnement de travail (décidés)

**Décision actée par Cédric : l'implémentation est en Rust, conformément à A18.** Pas de prototype Node jetable — on construit directement sur la stack cible.

Ce que dit le corpus :

- **Serveur (A18)** : **Rust**. Services séparés (`diamy-mxd`, `diamy-maild`, `diamy-submitd`, `diamy-cald`), runtime `tokio`, PostgreSQL via `sqlx`, crypto isolée dans une crate `diamy-mail-crypto`, zeroization mémoire, etc. Le choix de Rust est motivé par la sécurité mémoire (manipulation de clair/de clés) et l'alignement avec le reste du stack Diamy.
- **Client (A19)** : un **cœur SDK partagé** (recommandé : Rust compilé en WASM/natif) enveloppé de couches plateforme (desktop Electron/natif, mobile, webmail thin client). L'idée : les fonctions sensibles à la dérive (normalisation d'adresse, dérivation de tokens Blind-Index, résolution de conflits) doivent être **le même code** côté serveur et client.

C'est donc du Rust. C'est le terrain le plus neuf pour toi (le cœur crypto surtout) : avances-y en binôme serré avec Claude et appuie-toi fort sur la boucle de vérification (§5.3) et sur le type-state (§5.5), qui transforment beaucoup d'erreurs en erreurs de compilation. Les **frontières et invariants** (§3) ne dépendent de toute façon pas du langage : ils restent la boussole.

**Sur l'IAM (décidé aussi) :** l'IAM n'est pas encore en production, mais il peut te générer un **environnement de dev avec un jeu de clés de test**. Tu t'appuies dessus plutôt que de fabriquer un faux IAM — c'est ce que veut l'architecture (INV-9 : pas de registre d'utilisateurs parallèle ; A17-P-4 : binding IAM réel exigé au démarrage). Un point à garder en tête : le corpus signale un point ouvert HIGH côté IAM — le **mécanisme exact de révocation de jetons n'est pas confirmé** (A17-TOK-2). Sans impact pour la maquette, mais ne code pas la révocation contre l'hypothèse « epoch bump » : signale-le comme un point à confirmer avec l'équipe IAM.

**Sur la crypto (décidé — important) :** la crypto de Diamy Mail réutilise les primitives du **messaging Diamy**, qui viennent **tout juste d'être mises en ligne** et ne sont pas encore stabilisées. **Tu ne dois pas être bloqué par ça.** La règle : **toute** la crypto vit derrière la frontière d'**une seule crate, `diamy-mail-crypto`** (INV-5, A18-TOP-1) — le reste du code ne connaît que son API, jamais les primitives. Tu définis cette API tout de suite (sceller un message, envelopper/désenvelopper une clé par appareil, dériver via HKDF, signer/vérifier) et tu la fournis avec **deux backends interchangeables** derrière un *feature flag* Cargo :

- `dev-crypto` (celui que tu utilises maintenant) : des primitives **auditées** de crates Rust reconnues (`aes-gcm`, `hkdf`, `ml-kem` de RustCrypto) — pas du hand-rolled, mais **pas** le socle messaging et **pas** le format d'interop définitif. Il te débloque pour construire tout le reste.
- `messaging-crypto` (la cible) : le branchement sur les primitives auditées du messaging Diamy, une fois stables. Le jour de la bascule, **seul le backend change** — les appelants (stockage, frontière, sync, client) ne bougent pas.

Deux garde-fous non négociables : (1) le backend `dev-crypto` ne doit **jamais** pouvoir partir en prod — build de prod sans ce flag, et **refus de démarrage** *fail-closed* s'il est actif hors dev (esprit A18 SEC-FC) ; (2) les données créées sous `dev-crypto` ne sont **pas** interopérables avec `messaging-crypto` (format/labels différents) — à la bascule on **re-provisionne**, on ne migre pas (données de test jetables, c'est acceptable). Note-le dans `SIMPLIFICATIONS.md`.

Ce qui compte : la **force** de la crypto est temporaire, mais les **frontières** ne bougent pas — le serveur reste aveugle au contenu, on vérifie toujours le tag avant d'utiliser le clair (INV-1/3/8), même avec le backend de dev.

### Domaine et environnement de test

- **Domaine de test : `w3.tel`.** C'est le domaine sur lequel tu travailles : adresses de test, provisioning des boîtes, alignement SPF/DKIM/DMARC. Toute la maquette tourne sous ce domaine.
- **Serveur MX :** tu peux en monter un **au bureau, avec l'aide d'Aubin**. C'est ta passerelle entrante (`diamy-mxd`, annexe A01) pour exercer le vrai chemin de réception SMTP, pas seulement une simulation.
- **DNS / SPF / DKIM / DMARC :** c'est **Cédric qui a la main** sur la configuration DNS de `w3.tel`. **Reviens vers lui** dès que tu as besoin d'un enregistrement (MX, SPF, clé DKIM, politique DMARC) — ne tente pas de le configurer toi-même. Le côté produit de cet onboarding (provisioning guidé SPF/DKIM/DMARC, vérification DNS, activation *fail-closed*) est spécifié en A11 ; côté opérationnel pour la maquette, tu passes par Cédric.

Rappel utile : un tenant ne peut pas envoyer tant que SPF/DKIM/DMARC ne sont pas vérifiés alignés (SEC-OUT-2, onboarding *fail-closed*). C'est donc un vrai prérequis, pas un détail — d'où le passage obligé par Cédric pour le DNS.

---

## 7. Plan de maquette proposé (à valider)

Plutôt que de suivre l'ordre de production complet, vise un **squelette vertical** puis élargis. Chaque étape joue aussi sur tes points forts.

**Étape 0 — Cadre & environnement (jours 1-2)**
Lire A25 puis A00. Monter le repo, le `docker compose` des services vides, l'ossature d'observabilité (Prometheus + Grafana — terrain connu pour toi). Faire produire par Claude, à partir du corpus, une **carte des composants** et un **glossaire** pour toi-même, et les faire relire.

**Étape 1 — Identité & adresses (A24, A17)**
La fonction de canonicalisation d'adresse partagée (`diamy_addr_canon`) et le contrat IAM. C'est la fondation ; A24 fournit même 13 vecteurs de test normatifs (dont des cas punycode) à faire passer en CI. Ici tu branches l'**environnement de dev IAM avec le jeu de clés de test** (décidé, §6) : tu résous les principaux via IAM, tu ne réimplémentes ni l'identité ni le hachage `primary_email_hash` (tu appelles le contrat IAM).

**Étape 2 — Frontière crypto & stockage (A02, A21) — sans dépendre du messaging**
Définis d'abord l'**API de `diamy-mail-crypto`** et son backend `dev-crypto` (voir §6) : c'est ce qui te permet d'avancer **sans attendre** que le messaging soit stable. Puis le modèle « enveloppe » : un message chiffré une fois (AES-256-GCM), la clé enveloppée une fois par appareil (ML-KEM-768), le tag vérifié **avant** tout usage. Le serveur ne stocke que du chiffré ; A21 (DDL) est la source de vérité du schéma. Le branchement du vrai backend `messaging-crypto` est une étape **ultérieure et isolée**, hors du chemin critique de la maquette.

**Étape 3 — Frontière entrante (A01)**
Réception SMTP → contrôles → chiffrement frontière → destruction du clair. Le point le plus « sécurité mémoire » ; c'est là que la fidélité aux invariants compte le plus.

**Étape 4 — Sync & client (A04, A03, A19)**
API de sync native (pas IMAP), notifications signaux-seulement (tes webhooks te serviront ici, mais rappel : signal, pas contenu), client vault qui tire, déchiffre, et **rend via Tiptap**.

**Étape 5 — Recherche & IA locale (A05)**
Extraction de mots-clés **on-device** — tu as déjà fait de l'Ollama, c'est exactement l'esprit : l'IA tourne en local, seuls des mots-clés dérivés peuvent éventuellement quitter l'appareil (et seulement en mode webmail).

À ce stade tu as une maquette qui démontre l'architecture de bout en bout. L'agenda (A12–A15), le sortant complet (A10/A11/A23), la classification (A16), le Bridge (A20) viennent après, selon le périmètre validé.

**Où tes acquis accélèrent :** observabilité A22 (Prometheus/Grafana), déploiement Docker des daemons, IA locale A05 (Ollama), notifications A04 (webhooks), SDK client A19 (front/TS). Le cœur crypto Rust (A02/A18) est le terrain le plus neuf pour toi **et il dépend du messaging tout juste mis en ligne** — c'est justement pour ça qu'il est isolé derrière la crate `diamy-mail-crypto` avec un backend `dev-crypto` (§6) : tu ne l'attends pas pour avancer, tu brancheras le vrai backend plus tard. Avances-y en binôme avec Claude et en t'appuyant fort sur la boucle de vérification (§5.3).

---

## 8. « Maquette terminée » — critères

Tu peux considérer une étape comme faite quand :

- le chemin vertical de l'étape tourne dans les conteneurs ;
- **aucun** forbidden-pattern d'A18/A19 n'est présent (revue passée) ;
- les vecteurs de test normatifs de l'annexe passent (là où il y en a : A24, KAT d'enveloppe…) ;
- **aucun invariant n'est violé structurellement** — en particulier : rien ne stocke de clair côté serveur hors exception déclarée ;
- les simplifications assumées sont **écrites** quelque part (un `SIMPLIFICATIONS.md` : « IAM en environnement de dev, pas prod », « primitives crypto de dev », « pas d'agenda », « révocation non implémentée — mécanisme IAM à confirmer »), pour que la revue avec Cédric distingue « pas fait » de « fait faux ».

Ce dernier point est capital : une maquette honnête dit clairement ce qu'elle *ne* fait *pas*.

---

## 9. Glossaire minimal

- **Tenant** : une organisation cliente. Diamy Mail est B2B ; tout utilisateur appartient à un tenant (= un tenant Diamy IAM).
- **Frontier encryption (chiffrement frontière)** : chiffrement appliqué par la passerelle entrante juste après réception SMTP, avant tout stockage. Le clair n'existe que transitoirement en RAM.
- **Envelope (enveloppe)** : une clé AES de message emballée pour la clé publique d'un appareil précis. Un message est chiffré une fois ; la clé est emballée une fois par appareil.
- **Device (appareil)** : une instance client autorisée (PC, tel, tablette) avec sa propre paire de clés. Les clés privées ne quittent jamais le coffre sécurisé de l'OS.
- **Vault client** : le client local-first (catalogue SQLite chiffré + blobs chiffrés + index de recherche local).
- **Blind Index** : un index unidirectionnel à clé (HMAC) permettant une recherche d'égalité côté serveur sans révéler le clair. Utilisé **uniquement** si le webmail est activé.
- **Trust score** : valeur de confiance calculée et explicable attachée à un message/lien/pièce jointe.
- **Tiptap document** : représentation JSON structurée à schéma fermé du contenu (modèle ProseMirror), qui remplace le HTML brut pour le rendu par défaut.
- **Webmail mode** : capacité **opt-in** où le contenu passe par un navigateur avec recherche Blind-Index côté serveur, au lieu d'un stockage local uniquement. Posture de sécurité assumée plus faible.
- **AppKey (Tier 2)** : credential propre à l'application cliente (« quelle app appelle »), distinct du jeton mail-plane (« quel utilisateur »). À ne pas confondre avec l'AppKey Tier 1 côté IAM que le backend utilise pour appeler IAM (le client ne la voit jamais).
- **Honest-but-curious** : modèle de menace où le serveur est supposé pouvoir tout observer sans qu'on puisse en tirer du clair.

---

## 10. Checklist de la première semaine

- [ ] Lire A25 en entier, puis A00. Noter ce qui n'est pas clair.
- [ ] Survoler la table du corpus (A00 §12) pour situer chaque annexe.
- [ ] Configurer Claude (projet dédié + instruction « ne jamais inventer un cas non spécifié, signaler le gap »).
- [ ] Faire produire par Claude une carte des composants + un glossaire perso, les relire contre A00.
- [ ] Monter le repo + `docker compose` squelette + Prometheus/Grafana.
- [ ] Lister les **questions ouvertes** pour Cédric (voir §11) et les poser **avant** d'écrire du code métier.
- [ ] Ne rien coder sur une brique sans avoir chargé A25 + A00 + l'annexe + A18/A19.

---

## 11. Décisions prises et questions restantes

### Déjà tranché par Cédric

- **Stack : Rust** (fidèle à A18), pas de prototype Node jetable. (§6)
- **IAM : environnement de dev avec jeu de clés de test.** Pas de faux IAM ; on s'appuie sur l'IAM réel provisionné en dev. (§6)
- **Crypto : backend `dev-crypto` derrière `diamy-mail-crypto`, messaging branché plus tard.** Le messaging Diamy vient d'être mis en ligne ; tu n'attends pas qu'il soit stable — tu codes contre l'API de la crate avec un backend de dev audité (non expédiable) et tu basculeras sur `messaging-crypto` ensuite. (§6)
- **Environnement de test :** domaine **`w3.tel`** ; **serveur MX** à monter au bureau avec **Aubin** ; **DNS/SPF/DKIM/DMARC** gérés par **Cédric** — reviens vers lui pour ça. (§6)
- **Référent de stage : Cédric.** C'est vers lui que tu remontes tes questions, les arbitrages de conception et les revues.

### À confirmer avec Cédric avant de coder le métier

Ces points orientent la maquette ; ne les devine pas.

1. **Crypto — quand et comment brancher le messaging** (non bloquant pour démarrer) : le backend `dev-crypto` te débloque maintenant ; reste à caler avec Cédric le moment de bascule vers `messaging-crypto`, et à récupérer les **labels HKDF et le format d'enveloppe exacts** du messaging pour l'interop (A02-CRY, A19-PAR).
2. **Périmètre de la maquette** : jusqu'où va-t-on ? (chemin vertical mail seul ? agenda inclus ? Bridge ?)
3. **Cible de déploiement** : la maquette tourne juste en local (`docker compose`), ou sur un environnement précis ?
4. **Révocation IAM (point ouvert HIGH)** : le mécanisme exact n'est pas confirmé (A17-TOK-2). À clarifier avec l'équipe IAM avant d'implémenter la révocation ; à ne pas coder au jugé d'ici là.

Poser ces questions tôt, c'est exactement le bon réflexe (c'est même la règle 2 de la constitution appliquée à toi-même : face à un trou, on demande, on n'invente pas).

---

## 12. État d'avancement des spécifications (et règle impérative)

### Où en est le corpus

Le corpus est **complet au stade de brouillon interne**, mais **il n'y a pas encore de code**.

- Les **30 documents existent** (statut « Internal Draft », versions v1.x) : le document maître A00 est en v1.14, la constitution A25 en v1.3, les annexes couvrent tout le périmètre (passerelle, stockage, sync, recherche, confiance, rendu, sortant, onboarding, agenda, IAM, DDL, santé, multi-comptes, ressources partagées, présence, UX).
- Les **six décisions de conception ouvertes** recensées dans A00 §14 sont **toutes closes** par leurs annexes. L'architecture est cohérente et arrêtée sur l'essentiel — ce n'est pas un brouillon flou, c'est une spécification stabilisée.
- Ce qui reste **explicitement ouvert ou différé** (à connaître) :
  - **Mécanisme de révocation de jetons — HIGH, ouvert** (A17-TOK-2 / A25 §6) : l'hypothèse « epoch bump » héritée du messaging n'est pas confirmée contre l'IAM réel (un modèle JTI-cache, à borne plus lâche, est possible). Bloquant pour toute promesse de révocation < 15 s ; à confirmer avec l'équipe IAM. **Ne l'implémente pas au jugé.**
  - **Crypto messaging tout juste en ligne, non stabilisée** : l'intégration du vrai backend crypto est **différée et isolée** derrière `diamy-mail-crypto` (backend `dev-crypto` en attendant, §6). Non bloquant pour la maquette ; la bascule vers `messaging-crypto` se fera sans toucher aux appelants.
  - Outillage différé, **non bloquant** pour la maquette : jeu de diagrammes d'architecture, linter de cohérence inter-annexes (vérifier qu'aucune annexe ne viole un INV-\*), génération de code/contrats depuis les annexes.

Tu produis donc la **première** implémentation. C'est une responsabilité (rien à copier) autant qu'une liberté (aucune dette de code existante).

### Règle impérative : la spec est la source de vérité — tiens-la à jour

Le corpus n'est pas une documentation écrite après coup : c'est la **source de vérité** dont Claude et toi partez pour implémenter. Il en découle une règle non négociable :

> **Si l'implémentation t'amène à modifier la conception — ou révèle un cas non prévu — tu DOIS mettre à jour la spécification, avant ou avec le code. Jamais de divergence silencieuse entre le code et les annexes.**

Concrètement, à chaque changement de conception :

1. **Modifie l'annexe propriétaire** de la règle (une règle = une annexe, A25) — là, pas ailleurs, pour ne pas créer de doublon qui divergera.
2. **Bump la version** de l'annexe et ajoute une **entrée de changelog** (date, auteur, ce qui change et pourquoi). C'est la discipline de tout le corpus : regarde l'en-tête de n'importe quelle annexe, elles fonctionnent toutes comme ça.
3. **Vérifie qu'aucun invariant INV-\* (A25 §2) n'est violé.** Si une feature semble exiger d'en casser un, c'est la feature qui est mauvaise : escalade vers Cédric, ne casse pas l'invariant (constitution règle 4).
4. Si un cas **n'est pas** couvert : ne l'invente pas dans le code. Signale le trou (candidat « Open Decision » / « Deferred Item »), tranche-le avec Cédric, **écris la décision dans l'annexe, puis** implémente (constitution règle 2).

En clair : le code suit la spec ; et quand le code doit s'en écarter, c'est la spec qu'on corrige d'abord. Une maquette qui diverge de ses specs sans les mettre à jour vaut *moins* que pas de maquette — parce qu'elle rend le corpus faux, et le corpus est ce qui a le plus de valeur ici.

---

*Bonne prise en main. Le corpus a l'air massif, mais il est cohérent et pensé pour être suivi pas à pas. Avance par petits chemins verticaux, vérifie chaque génération contre les invariants, et signale tout ce qui manque plutôt que de le combler au jugé.*
