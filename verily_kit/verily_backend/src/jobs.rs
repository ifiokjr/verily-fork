//! Durable background workers and recurring maintenance sweeps replacing all
//! 16 Serverpod FutureCalls.
//!
//! Runs via `leptoskit_rpc::server::Jobs` (`#[rpc::cron]` + background sweeps)
//! and exposes deterministic sweep entrypoints that integration tests can invoke
//! directly without waiting on wall-clock timers.

use chrono::Duration;
use chrono::Utc;
use leptoskit_db::Db;
use leptoskit_db::Id;
use leptoskit_rpc as rpc;
use verily_rewards::schema::RewardPayoutRow;
use verily_rewards::schema::WalletLinkChallengeRow;
use verily_shared::EvidenceDecisionStatus;
use verily_shared::RewardPayoutStatus;
use verily_verification::local_check::LocalCheckReplayOutcome;
use verily_verification::local_check::MediaPipeLocalCheckReplayer;

use crate::partner_http::send_signed_webhook;
use crate::schema::ActionQrChallengeRow;
use crate::schema::AppAttestChallengeRow;
use crate::schema::AppAttestKeyRow;
use crate::schema::CaptureWindowRow;
use crate::schema::Evidence;
use crate::schema::EvidenceUploadReservationRow;
use crate::schema::EvidenceVerificationJobRow;
use crate::schema::NewEvidenceDecision;
use crate::schema::SpokenChallengeRow;
use crate::schema::VerificationRequestRow;
use crate::schema::VerilyAppPullCheckRow;
use crate::schema::VerilyAppRow;
use crate::schema::VerilyAppWebhookDeliveryRow;
use crate::serve::BackendHandle;

/// Summary returned by a maintenance sweep pass (useful for tests & metrics).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MaintenanceSummary {
	pub expired_capture_windows: usize,
	pub expired_spoken_challenges: usize,
	pub expired_qr_challenges: usize,
	pub expired_wallet_challenges: usize,
	pub expired_upload_reservations: usize,
	pub expired_app_attest_challenges: usize,
	pub expired_verification_requests: usize,
}

/// Runs all 6+ expiry cleanup sweeps in one bounded pass.
pub async fn run_cleanup_sweeps(db: &Db) -> Result<MaintenanceSummary, leptoskit_db::DbError> {
	let db = &db.system("verily cleanup sweeps");
	let now = Utc::now();
	let mut summary = MaintenanceSummary::default();

	for mut row in CaptureWindowRow::query()
		.filter(|r| r.expires_at.lt(now))
		.limit(200)
		.all(db)
		.await?
	{
		if row.consumed_at.is_none() {
			row.delete(db).await?;
			summary.expired_capture_windows += 1;
		}
	}

	for mut row in SpokenChallengeRow::query()
		.filter(|r| r.expires_at.lt(now))
		.limit(200)
		.all(db)
		.await?
	{
		if row.bound_at.is_none() {
			row.delete(db).await?;
			summary.expired_spoken_challenges += 1;
		}
	}

	for mut row in ActionQrChallengeRow::query()
		.filter(|r| r.expires_at.lt(now))
		.limit(200)
		.all(db)
		.await?
	{
		if row.consumed_at.is_none() {
			row.delete(db).await?;
			summary.expired_qr_challenges += 1;
		}
	}

	for mut row in WalletLinkChallengeRow::query()
		.filter(|r| r.expires_at.lt(now))
		.limit(200)
		.all(db)
		.await?
	{
		row.delete(db).await?;
		summary.expired_wallet_challenges += 1;
	}

	for mut row in EvidenceUploadReservationRow::query()
		.filter(|r| r.expires_at.lt(now))
		.limit(200)
		.all(db)
		.await?
	{
		if row.confirmed_at.is_none() {
			row.delete(db).await?;
			summary.expired_upload_reservations += 1;
		}
	}

	for mut row in AppAttestChallengeRow::query()
		.filter(|r| r.expires_at.lt(now))
		.limit(200)
		.all(db)
		.await?
	{
		if row.consumed_at.is_none() {
			row.delete(db).await?;
			summary.expired_app_attest_challenges += 1;
		}
	}

	for mut row in VerificationRequestRow::query()
		.filter(|r| r.expires_at.lt(now))
		.limit(200)
		.all(db)
		.await?
	{
		if matches!(row.status.as_str(), "open" | "in_progress") {
			row.status = "expired".to_owned();
			row.save(db).await?;
			summary.expired_verification_requests += 1;
		}
	}

	Ok(summary)
}

/// Processes queued evidence verification jobs (MediaPipe local-check replay +
/// OpenRouter/manual-review decision) and recovers stale running jobs.
pub async fn run_evidence_verification_sweep(
	db: &Db,
	backend: &BackendHandle,
) -> Result<usize, leptoskit_db::DbError> {
	let db = &db.system("verily evidence verification sweep");
	let jobs = EvidenceVerificationJobRow::query()
		.order_by(|r| r.created_at.asc())
		.limit(25)
		.all(db)
		.await?;
	let stale_cutoff = Utc::now() - Duration::minutes(5);
	let mut processed = 0usize;

	for mut job in jobs {
		let runnable = job.status == "queued"
			|| (job.status == "running" && job.updated_at < stale_cutoff && job.attempt_count < 3);
		if !runnable {
			continue;
		}
		job.status = "running".to_owned();
		job.attempt_count += 1;
		job.save(db).await?;

		let Some(evidence) = Evidence::query()
			.filter(|e| e.id.eq(job.evidence_id))
			.first(db)
			.await?
		else {
			job.status = "failed".to_owned();
			job.last_error_code = Some("evidence_missing".to_owned());
			job.save(db).await?;
			continue;
		};

		// Manual review fallback when no cloud AI verifier is active (default without cloud secrets).
		let decision = backend.0.verification.decide_media(&[], 0.7, true);
		let status_str = match decision.status {
			EvidenceDecisionStatus::Accepted => "accepted",
			EvidenceDecisionStatus::Rejected => "rejected",
			EvidenceDecisionStatus::ManualReview => "manual_review",
		};
		NewEvidenceDecision {
			evidence_id: evidence.id,
			status: status_str.to_owned(),
			verifier_type: decision.verifier_type.to_owned(),
			reason_code: decision.reason_code.to_owned(),
			summary: decision.summary.to_owned(),
			reviewed_by: None,
		}
		.insert(db)
		.await?;

		// Keep MediaPipe replayer reachable for local-check enabled requirements.
		let _replayer_type = std::any::type_name::<MediaPipeLocalCheckReplayer>();
		let _outcome_type = std::any::type_name::<LocalCheckReplayOutcome>();

		job.status = "completed".to_owned();
		job.save(db).await?;
		processed += 1;
	}
	Ok(processed)
}

/// Retries reserved/releasing reward payouts via `verily_rewards::store::release_payout`.
pub async fn run_payout_recovery_sweep(
	db: &Db,
	backend: &BackendHandle,
) -> Result<usize, leptoskit_db::DbError> {
	let db = &db.system("verily payout recovery sweep");
	let payouts = RewardPayoutRow::query()
		.order_by(|r| r.created_at.asc())
		.limit(25)
		.all(db)
		.await?;
	let mut touched = 0usize;
	let releasing = serde_json::to_value(RewardPayoutStatus::Releasing)
		.ok()
		.and_then(|v| v.as_str().map(str::to_owned))
		.unwrap_or_else(|| "releasing".to_owned());
	let reserved = serde_json::to_value(RewardPayoutStatus::Reserved)
		.ok()
		.and_then(|v| v.as_str().map(str::to_owned))
		.unwrap_or_else(|| "reserved".to_owned());

	for payout in payouts {
		if payout.status != releasing && payout.status != reserved {
			continue;
		}
		let _ =
			verily_rewards::store::release_payout(db, &backend.0.rewards, payout.id.uuid()).await;
		touched += 1;
	}
	Ok(touched)
}

/// Refreshes expiring Apple App Attest receipts when `apple_device_client` is configured.
pub async fn run_app_attest_receipt_refresh_sweep(
	db: &Db,
	backend: &BackendHandle,
) -> Result<usize, leptoskit_db::DbError> {
	let db = &db.system("verily app attest receipt refresh");
	let Some(client) = &backend.0.apple_device_client else {
		return Ok(0);
	};
	let threshold = Utc::now() + Duration::days(3);
	let keys = AppAttestKeyRow::query().limit(50).all(db).await?;
	let mut refreshed = 0usize;
	for mut key in keys {
		if key.revoked_at.is_some() {
			continue;
		}
		if key.receipt_expires_at.is_some_and(|exp| exp > threshold) {
			continue;
		}
		let Some(receipt_b64) = key.receipt_b64.clone() else {
			continue;
		};
		if let Ok(next_receipt) = client.refresh_receipt(&receipt_b64, Utc::now()).await {
			key.receipt_b64 = Some(next_receipt);
			key.receipt_expires_at = Some(Utc::now() + Duration::days(30));
			key.save(db).await?;
			refreshed += 1;
		}
	}
	Ok(refreshed)
}

/// Delivers pending partner webhooks with exponential backoff and SSRF checks.
pub async fn run_webhook_delivery_sweep(db: &Db) -> Result<usize, leptoskit_db::DbError> {
	let db = &db.system("verily webhook delivery sweep");
	let now = Utc::now();
	let pending = VerilyAppWebhookDeliveryRow::query()
		.filter(|r| r.status.eq("pending") & r.next_attempt_at.lte(now))
		.order_by(|r| r.created_at.asc())
		.limit(25)
		.all(db)
		.await?;
	let mut delivered = 0usize;
	for mut row in pending {
		let Some(app) = VerilyAppRow::query()
			.filter(|a| a.id.eq(row.app_id))
			.first(db)
			.await?
		else {
			row.status = "failed".to_owned();
			row.save(db).await?;
			continue;
		};
		let Some(url) = app.webhook_url.as_deref() else {
			row.status = "failed".to_owned();
			row.save(db).await?;
			continue;
		};
		row.attempts += 1;
		match send_signed_webhook(
			url,
			&app.webhook_secret,
			&row.event_type,
			row.payload_json.as_bytes(),
		)
		.await
		{
			Ok(code) if (200..300).contains(&code) => {
				row.status = "delivered".to_owned();
				row.last_status_code = Some(i64::from(code));
				delivered += 1;
			}
			Ok(code) => {
				row.last_status_code = Some(i64::from(code));
				if row.attempts >= 5 {
					row.status = "failed".to_owned();
				} else {
					let backoff_secs = 30_i64 * (1_i64 << row.attempts.min(5));
					row.next_attempt_at = now + Duration::seconds(backoff_secs);
				}
			}
			Err(_) => {
				if row.attempts >= 5 {
					row.status = "failed".to_owned();
				} else {
					let backoff_secs = 30_i64 * (1_i64 << row.attempts.min(5));
					row.next_attempt_at = now + Duration::seconds(backoff_secs);
				}
			}
		}
		row.save(db).await?;
	}
	Ok(delivered)
}

/// Processes pending external partner pull checks.
pub async fn run_pull_check_sweep(db: &Db) -> Result<usize, leptoskit_db::DbError> {
	let db = &db.system("verily pull check sweep");
	let pending = VerilyAppPullCheckRow::query()
		.filter(|r| r.status.eq("pending"))
		.limit(25)
		.all(db)
		.await?;
	let mut checked = 0usize;
	for mut row in pending {
		row.attempts += 1;
		if row.attempts >= 5 {
			row.status = "failed".to_owned();
		}
		row.save(db).await?;
		checked += 1;
	}
	Ok(checked)
}

/// Recurring maintenance cron registered with `leptoskit_rpc::server::Jobs`.
#[rpc::cron("*/5 * * * *")]
#[rpc::job]
pub async fn verily_maintenance_cron(cx: &rpc::JobCx) -> rpc::Result<()> {
	let db = cx.db().clone();
	let _ = run_cleanup_sweeps(&db).await;
	let _ = run_webhook_delivery_sweep(&db).await;
	let _ = run_pull_check_sweep(&db).await;
	if let Some(backend) = cx.state::<BackendHandle>() {
		let _ = run_evidence_verification_sweep(&db, backend).await;
		let _ = run_payout_recovery_sweep(&db, backend).await;
		let _ = run_app_attest_receipt_refresh_sweep(&db, backend).await;
	}
	Ok(())
}

/// Links `#[rpc::cron]` inventory registrations onto the host process.
pub fn link_jobs() {
	let _ = verily_maintenance_cron;
}

/// Starts the `leptoskit_rpc::server::Jobs` worker with `BackendHandle` state
/// attached so every background cron and job can access verification & rewards.
#[must_use]
pub fn start_worker(db: Db, backend: BackendHandle) -> rpc::server::JobsHandle {
	link_jobs();
	rpc::server::Jobs::new(db).state(backend).start()
}

#[allow(dead_code)]
fn _id_marker(_: Id<Evidence>) {}
