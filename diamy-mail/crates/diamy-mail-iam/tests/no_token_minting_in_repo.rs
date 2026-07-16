//! Preuve anti-régression (INV-9 / A17-P-1) : AUCUNE fonction du repo ne doit savoir
//! FABRIQUER un jeton de session (mail-plane) valide. « Diamy Mail MUST NOT mint identity or
//! session tokens » — seul IAM est autorité d'émission. C'est la CAPACITÉ elle-même qu'on
//! interdit, pas seulement son usage en prod : ce test scanne donc TOUT le repo (crates ET
//! services ET exemples), pas un seul binaire (à la différence de
//! `services/diamy-maild/tests/no_keygen_in_binary.rs`, qui garde le seul `main.rs`).
//!
//! Marqueurs interdits, choisis pour être précis (zéro faux positif) et au niveau de la
//! CAPACITÉ, pas d'un simple nom :
//!   - `EncodingKey` : la clé de SIGNATURE de `jsonwebtoken`. La VÉRIFICATION n'utilise jamais
//!     que `DecodingKey` ; on ne peut pas produire un JWT signé sans `EncodingKey`. Sa présence
//!     où que ce soit = quelqu'un peut signer un jeton. C'est exactement la capacité bannie.
//!   - `jsonwebtoken::encode` : l'appel d'encodage/signature JWT (redondant avec le précédent —
//!     on ne peut pas `encode` un jeton signé sans `EncodingKey` — mais explicite).
//!   - `mint_dev_mail_plane_token` : le nom EXACT de la fonction retirée, pour attraper toute
//!     réapparition littérale (copie/restauration).
//!
//! Les jetons de test valides vivent désormais, PRÉ-SIGNÉS une fois hors du code, dans
//! `tests/fixtures/dev_mail_plane_tokens.json` (données, pas du code) ; tests et exemples les
//! LISENT. Ce fichier de test contient les marqueurs interdits en tant que littéraux : il
//! s'exclut lui-même du scan (comme `no_keygen_in_binary.rs`) pour éviter l'auto-référence.

use std::fs;
use std::path::{Path, PathBuf};

/// Marqueurs de la CAPACITÉ de signer/émettre un jeton de session — voir l'en-tête de module.
const FORBIDDEN_TOKEN_MINTING: &[&str] = &[
    "EncodingKey",
    "jsonwebtoken::encode",
    "mint_dev_mail_plane_token",
];

/// Racine du workspace : `.../diamy-mail` (deux niveaux au-dessus de ce crate,
/// `crates/diamy-mail-iam`). Résolu à la compilation via `CARGO_MANIFEST_DIR`.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("racine du workspace deux niveaux au-dessus de crates/diamy-mail-iam")
        .to_path_buf()
}

/// Collecte récursivement tous les fichiers `.rs` sous `dir`, en ignorant `target/`, `.git/`
/// et tout répertoire caché (ni source, ni versionné utilement).
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name == ".git" || name.starts_with('.') {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_function_in_repo_can_mint_a_session_token() {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_rs_files(&root, &mut files);

    // Garde-fou : le scan doit réellement voir des sources (sinon il « passe » à vide).
    assert!(
        files.len() > 5,
        "scan anti-régression vide ({} fichiers .rs sous {}) — le chemin de la racine du \
         workspace est probablement faux, le test ne prouverait rien",
        files.len(),
        root.display()
    );

    let mut violations = Vec::new();
    for path in &files {
        // Ce fichier de test contient les marqueurs interdits en littéraux : on l'exclut
        // (auto-référence), comme `no_keygen_in_binary.rs` ne scanne que `main.rs`.
        if path.file_name().and_then(|n| n.to_str()) == Some("no_token_minting_in_repo.rs") {
            continue;
        }
        let source = fs::read_to_string(path).unwrap_or_default();
        for needle in FORBIDDEN_TOKEN_MINTING {
            if source.contains(needle) {
                let rel = path.strip_prefix(&root).unwrap_or(path);
                violations.push(format!("  - `{needle}` dans {}", rel.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "INV-9 / A17-P-1 : une capacité de FABRICATION de jeton de session a réapparu dans le \
         repo. « Diamy Mail MUST NOT mint identity or session tokens » — seul IAM émet des \
         jetons ; le code ne doit jamais SAVOIR en signer un. Utilise un jeton pré-signé de \
         `tests/fixtures/dev_mail_plane_tokens.json` (à LIRE, jamais à fabriquer).\n{}",
        violations.join("\n")
    );
}
