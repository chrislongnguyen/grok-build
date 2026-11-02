use std::path::Path;

use agent_client_protocol as acp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::prompter::PromptOutcome;
use super::types::AccessKind;

pub const META_KEY: &str = "x.ai/permissionReview";

pub(crate) fn review_eligible(
    native_decision: &super::types::Decision,
    auto_mode: bool,
    classifier_block: bool,
    mandatory_prompt: bool,
    security_findings: &[String],
) -> bool {
    matches!(native_decision, super::types::Decision::Allow)
        && auto_mode
        && classifier_block
        && !mandatory_prompt
        && !security_findings.iter().any(|finding| {
            matches!(
                finding.as_str(),
                "opaque_shell" | "env_injection" | "exec_or_ambient_git" | "special_exec_surface"
            )
        })
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Eligibility {
    ClassifierHold { reason: String },
    HumanRequired { reason: String },
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingReview {
    pub version: u8,
    pub session_id: String,
    pub tool_call_id: String,
    pub nonce: String,
    pub policy_generation: String,
    pub action_digest: String,
    pub eligibility: Eligibility,
    pub security_findings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputBinding {
    pub path: std::path::PathBuf,
    pub sha256: String,
}

pub async fn inputs_match(bindings: Vec<InputBinding>) -> bool {
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut seen = std::collections::HashSet::new();
        if bindings.len() > 128 {
            return false;
        }
        let mut total = 0_u64;
        bindings.iter().all(|binding| {
            if !binding.path.is_absolute()
                || !seen.insert(binding.path.clone())
                || binding.sha256.len() != 64
                || !binding
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return false;
            }
            if std::fs::canonicalize(&binding.path).ok().as_ref() != Some(&binding.path) {
                return false;
            }
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
            }
            let Ok(file) = options.open(&binding.path) else {
                return false;
            };
            let Ok(metadata) = file.metadata() else {
                return false;
            };
            const LIMIT: u64 = 512 * 1024 * 1024;
            if !metadata.is_file() || metadata.len() > LIMIT {
                return false;
            }
            let mut hash = Sha256::new();
            let mut reader = file.take(LIMIT + 1);
            let mut buffer = [0_u8; 65536];
            let mut count = 0_u64;
            loop {
                let Ok(n) = reader.read(&mut buffer) else {
                    return false;
                };
                if n == 0 {
                    break;
                }
                count += n as u64;
                total += n as u64;
                if count > LIMIT || total > LIMIT {
                    return false;
                }
                hash.update(&buffer[..n]);
            }
            format!("{:x}", hash.finalize()) == binding.sha256
        })
    })
    .await
    .unwrap_or(false)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoreSnapshot(Vec<(std::path::PathBuf, Option<String>)>);

impl StoreSnapshot {
    pub(crate) async fn capture(paths: Vec<std::path::PathBuf>) -> Option<Self> {
        tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut entries = Vec::new();
            for path in paths {
                let mut options = std::fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
                }
                let digest = match options.open(&path) {
                    Ok(file) => {
                        if !file.metadata().ok()?.is_file() {
                            return None;
                        }
                        let mut bytes = Vec::new();
                        file.take(4 * 1024 * 1024 + 1)
                            .read_to_end(&mut bytes)
                            .ok()?;
                        if bytes.len() > 4 * 1024 * 1024 {
                            return None;
                        }
                        Some(format!("{:x}", Sha256::digest(&bytes)))
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(_) => return None,
                };
                entries.push((path, digest));
            }
            Some(Self(entries))
        })
        .await
        .ok()
        .flatten()
    }

    pub(crate) async fn unchanged(&self) -> bool {
        Self::capture(self.0.iter().map(|(path, _)| path.clone()).collect())
            .await
            .as_ref()
            == Some(self)
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionGuard {
    store_snapshot: StoreSnapshot,
    bindings: Vec<InputBinding>,
    generation: u64,
    current_generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl ExecutionGuard {
    pub(crate) fn new(
        store_snapshot: StoreSnapshot,
        bindings: Vec<InputBinding>,
        generation: u64,
        current_generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self {
            store_snapshot,
            bindings,
            generation,
            current_generation,
        }
    }

    pub async fn validate(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.current_generation.load(Ordering::SeqCst) == self.generation
            && inputs_match(self.bindings.clone()).await
            && self.store_snapshot.unchanged().await
            && self.current_generation.load(Ordering::SeqCst) == self.generation
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewAnswer {
    version: u8,
    nonce: String,
    policy_generation: String,
    action_digest: String,
    decision: String,
    #[serde(default)]
    feedback: Option<String>,
    #[serde(default)]
    input_bindings: Vec<InputBinding>,
}

impl PendingReview {
    pub fn new(
        session_id: String,
        update: &acp::ToolCallUpdate,
        access: &AccessKind,
        cwd: &Path,
        generation: u64,
        eligibility: Eligibility,
        security_findings: Vec<String>,
    ) -> Self {
        // The digest binds the request, not files read by a future shell process.
        let action = serde_json::json!({
            "access": format!("{access:?}"),
            "cwd": cwd,
            "toolCall": update,
            "securityFindings": security_findings,
        });
        Self {
            version: 1,
            session_id,
            tool_call_id: update.tool_call_id.to_string(),
            nonce: uuid::Uuid::new_v4().to_string(),
            policy_generation: generation.to_string(),
            action_digest: format!("{:x}", Sha256::digest(action.to_string().as_bytes())),
            eligibility,
            security_findings,
        }
    }

    pub fn answer(
        &self,
        value: &serde_json::Value,
        option: Option<&acp::PermissionOption>,
    ) -> PromptOutcome {
        let invalid = || {
            PromptOutcome::ReviewerRejected(
                "Permission review was invalid or stale; the action was not executed.".into(),
            )
        };
        let Ok(answer) = serde_json::from_value::<ReviewAnswer>(value.clone()) else {
            return invalid();
        };
        if answer.version != self.version
            || answer.nonce != self.nonce
            || answer.policy_generation != self.policy_generation
            || answer.action_digest != self.action_digest
            || !matches!(self.eligibility, Eligibility::ClassifierHold { .. })
        {
            return invalid();
        }
        let Some(option) = option else {
            return invalid();
        };
        match (
            answer.decision.as_str(),
            option.kind,
            option.option_id.0.as_ref(),
        ) {
            ("allow_once", acp::PermissionOptionKind::AllowOnce, "allow-once") => {
                PromptOutcome::ReviewedAllowOnce(answer.input_bindings)
            }
            ("reject_action", acp::PermissionOptionKind::RejectOnce, "reject-once") => {
                PromptOutcome::ReviewerRejected(
                    answer
                        .feedback
                        .filter(|text| !text.trim().is_empty())
                        .unwrap_or_else(|| "The independent reviewer rejected this action.".into()),
                )
            }
            _ => invalid(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn execution_guard_rejects_changes_after_preparation() {
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reviewed.sh");
        std::fs::write(&path, b"echo approved").unwrap();
        let generation = Arc::new(AtomicU64::new(7));
        let guard = ExecutionGuard::new(
            StoreSnapshot::capture(vec![]).await.unwrap(),
            vec![InputBinding {
                path: std::fs::canonicalize(&path).unwrap(),
                sha256: format!("{:x}", Sha256::digest(b"echo approved")),
            }],
            7,
            generation.clone(),
        );
        assert!(guard.validate().await);
        let prepared_guard = guard.clone();
        tokio::task::yield_now().await;
        std::fs::write(&path, b"echo changed").unwrap();
        assert!(!prepared_guard.validate().await);
        std::fs::write(&path, b"echo approved").unwrap();
        assert!(prepared_guard.validate().await);
        generation.fetch_add(1, Ordering::SeqCst);
        assert!(!prepared_guard.validate().await);
    }

    #[test]
    fn broad_grant_floors_allow_review_but_native_restrictions_do_not() {
        use super::super::types::Decision;
        let findings = vec!["unvetted_env".into(), "file_write".into()];
        assert!(review_eligible(
            &Decision::Allow,
            true,
            true,
            false,
            &findings
        ));
        for native in [Decision::Ask, Decision::PolicyDeny("deny".into())] {
            assert!(!review_eligible(&native, true, true, false, &findings));
        }
        // Hook asks and protected targets are mandatory prompts, regardless of classifier verdict.
        assert!(!review_eligible(
            &Decision::Allow,
            true,
            true,
            true,
            &findings
        ));
        assert!(!review_eligible(
            &Decision::Allow,
            true,
            false,
            false,
            &findings
        ));
        assert!(!review_eligible(
            &Decision::Allow,
            false,
            true,
            false,
            &findings
        ));
        for finding in [
            "opaque_shell",
            "env_injection",
            "exec_or_ambient_git",
            "special_exec_surface",
        ] {
            assert!(!review_eligible(
                &Decision::Allow,
                true,
                true,
                false,
                &[finding.into()]
            ));
        }
        let request = serde_json::to_value(pending()).unwrap();
        assert_eq!(request["securityFindings"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn prepared_guard_rejects_external_store_deny_without_actor_reload() {
        use std::sync::{Arc, atomic::AtomicU64};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("permissions.toml");
        let snapshot = StoreSnapshot::capture(vec![path.clone()]).await.unwrap();
        let guard = ExecutionGuard::new(snapshot, vec![], 0, Arc::new(AtomicU64::new(0)));
        assert!(guard.validate().await);
        let mut state = super::super::state::PermissionState::default();
        state.disallowed_bash_commands.insert("bash".into());
        std::fs::write(&path, toml::to_string(&state).unwrap()).unwrap();
        assert!(!guard.validate().await);
    }

    #[tokio::test]
    async fn later_store_mutation_revokes_earlier_guard_even_if_bytes_restored() {
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("permissions.toml");
        std::fs::write(&path, b"allowed_bash_commands = []").unwrap();
        let generation = Arc::new(AtomicU64::new(2));
        let guard = ExecutionGuard::new(
            StoreSnapshot::capture(vec![path.clone()]).await.unwrap(),
            vec![],
            2,
            generation.clone(),
        );
        assert!(guard.validate().await);
        std::fs::write(&path, b"disallowed_bash_commands = ['bash']").unwrap();
        generation.fetch_add(1, Ordering::SeqCst);
        std::fs::write(&path, b"allowed_bash_commands = []").unwrap();
        assert!(!guard.validate().await);
    }

    fn pending() -> PendingReview {
        PendingReview {
            security_findings: vec![],
            version: 1,
            session_id: "session".into(),
            tool_call_id: "call".into(),
            nonce: "unique-request".into(),
            policy_generation: "3".into(),
            action_digest: "digest".into(),
            eligibility: Eligibility::ClassifierHold {
                reason: "classifier".into(),
            },
        }
    }

    fn answer() -> serde_json::Value {
        serde_json::json!({"version":1,"nonce":"unique-request",
            "policyGeneration":"3","actionDigest":"digest","decision":"allow_once"})
    }

    #[test]
    fn review_requires_exact_binding_and_nonpersistent_option() {
        let review = pending();
        let option = acp::PermissionOption::new(
            "allow-once",
            "Allow once",
            acp::PermissionOptionKind::AllowOnce,
        );
        assert!(matches!(
            review.answer(&answer(), Some(&option)),
            PromptOutcome::ReviewedAllowOnce(_)
        ));
        for key in ["nonce", "policyGeneration", "actionDigest"] {
            let mut response = answer();
            response[key] = "stale".into();
            assert!(matches!(
                review.answer(&response, Some(&option)),
                PromptOutcome::ReviewerRejected(_)
            ));
        }
        let persistent = acp::PermissionOption::new(
            "allow-always",
            "Always",
            acp::PermissionOptionKind::AllowAlways,
        );
        assert!(matches!(
            review.answer(&answer(), Some(&persistent)),
            PromptOutcome::ReviewerRejected(_)
        ));
        assert!(matches!(
            review.answer(&answer(), None),
            PromptOutcome::ReviewerRejected(_)
        ));
    }

    #[test]
    fn human_required_and_malformed_answers_cannot_grant() {
        let mut review = pending();
        let option = acp::PermissionOption::new(
            "allow-once",
            "Allow once",
            acp::PermissionOptionKind::AllowOnce,
        );
        review.eligibility = Eligibility::HumanRequired {
            reason: "policy ask".into(),
        };
        assert!(matches!(
            review.answer(&answer(), Some(&option)),
            PromptOutcome::ReviewerRejected(_)
        ));
        for response in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"decision":"allow_always"}),
        ] {
            assert!(matches!(
                pending().answer(&response, Some(&option)),
                PromptOutcome::ReviewerRejected(_)
            ));
        }
    }

    #[test]
    fn rejection_returns_feedback_without_user_followup() {
        let mut response = answer();
        response["decision"] = "reject_action".into();
        response["feedback"] = "Use the safe alternative.".into();
        let option = acp::PermissionOption::new(
            "reject-once",
            "Reject",
            acp::PermissionOptionKind::RejectOnce,
        );
        assert!(matches!(pending().answer(&response, Some(&option)),
            PromptOutcome::ReviewerRejected(message) if message == "Use the safe alternative."));
    }
}
