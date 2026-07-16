//! Sink d'audit **distinct** du log applicatif (INV-20, A18-LOG-3, A00 §11 OBS-3).
//!
//! Toute action privilégiée/irréversible (publication d'annuaire de clés, purge de file de
//! hold, plus tard : purges dures, changements d'allocation, activation d'envoi...) y écrit
//! `actor` + `before`/`after` + `timestamp`. Ce n'est PAS un `tracing::info` générique noyé
//! dans le log applicatif : c'est un flux dédié —
//!   1. un fichier JSON-lines séparé (`DIAMY_AUDIT_LOG`, défaut `./audit_log/audit.jsonl`),
//!      la source d'audit autoritative ;
//!   2. un canal `tracing` sur une **cible réservée** `diamy_audit` (jamais la cible par
//!      défaut), pour un routage/collecte séparé sans dépendre du fichier.
//!
//! Simplification assumée (voir `SIMPLIFICATIONS.md`) : la tamper-evidence (chaînage par
//! hash / signature de chaque entrée, A18-LOG-3 « tamper-evident where feasible ») n'est PAS
//! encore là — un vrai déploiement chaînerait les entrées ou les signerait. Le contrat
//! (sink distinct + actor/before/after/timestamp) est, lui, en place.

use std::io::Write;
use std::sync::Mutex;

/// Sérialise les écritures concurrentes vers le fichier d'audit (append atomique par ligne).
static AUDIT_FILE_LOCK: Mutex<()> = Mutex::new(());

/// Enregistre un évènement d'audit (INV-20). `before`/`after` NE DOIVENT porter que des
/// métadonnées/identifiants/empreintes — jamais de contenu, de clé privée ni de jeton
/// (INV-21 s'applique aussi à ce sink : une clé PUBLIQUE peut y figurer sous forme
/// d'empreinte, jamais une clé privée ni du clair).
pub fn record(actor: &str, action: &str, before: serde_json::Value, after: serde_json::Value) {
    let ts_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let entry = serde_json::json!({
        "ts_unix_ms": ts_unix_ms,
        "actor": actor,
        "action": action,
        "before": before,
        "after": after,
    });

    // Sink autoritatif : fichier JSON-lines dédié, distinct du log applicatif.
    let path = std::env::var("DIAMY_AUDIT_LOG")
        .unwrap_or_else(|_| "./audit_log/audit.jsonl".to_string());
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    {
        let _guard = AUDIT_FILE_LOCK.lock();
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "{entry}");
        }
    }

    // Sink secondaire : canal `tracing` sur une cible RÉSERVÉE (jamais la cible par défaut).
    tracing::info!(target: "diamy_audit", %actor, %action, ts_unix_ms, "évènement d'audit (INV-20)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_appends_a_json_line_with_actor_action_and_timestamp() {
        // Fichier d'audit isolé pour ce test (jamais le défaut partagé).
        let dir = std::env::temp_dir().join(format!("diamy_audit_test_{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        std::env::set_var("DIAMY_AUDIT_LOG", &path);

        record(
            "device:abc",
            "keydir.publish_device_bundle",
            serde_json::json!({ "existed": false }),
            serde_json::json!({ "device_id": "d1", "validity_state": "active" }),
        );

        let content = std::fs::read_to_string(&path).expect("le fichier d'audit doit exister");
        let line = content.lines().next_back().expect("au moins une ligne");
        let parsed: serde_json::Value = serde_json::from_str(line).expect("JSON valide");
        assert_eq!(parsed["actor"], "device:abc");
        assert_eq!(parsed["action"], "keydir.publish_device_bundle");
        assert!(parsed["ts_unix_ms"].as_i64().unwrap() > 0);
        assert_eq!(parsed["before"]["existed"], false);
        assert_eq!(parsed["after"]["validity_state"], "active");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
