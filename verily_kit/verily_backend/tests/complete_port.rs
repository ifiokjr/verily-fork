//! End-to-end integration tests covering the complete LeptosKit port:
//! - `/healthz`, `/.well-known/jwks.json`, `/_verily/local-evidence/*`
//! - 12 templates, `get_draft`, `pause_action`, spatial nearby search
//! - Presigned local upload -> `confirm_media_upload` -> `submit_media_proof` -> job sweep
//! - Rotating venue QR code issue + single-use redemption
//! - Appeals resolution (`resolve_appeal`), moderation report + safety hold hiding action
//! - Verily Apps partner API (`/api/v1/*`, Bearer auth, link exchange, Ed25519 JWS receipt)
//! - Background cleanup & verification sweeps

#![allow(
	clippy::too_many_lines,
	clippy::similar_names,
	reason = "end-to-end port integration scenarios"
)]

mod support;

use leptoskit_auth::Auth;
use leptoskit_auth::Keys;
use leptoskit_axum::axum::body::Body;
use leptoskit_axum::axum::http::Request;
use leptoskit_axum::axum::http::StatusCode;
use leptoskit_axum::axum::http::header;
use sha2::Digest;
use sha2::Sha256;
use support::*;
use tower::ServiceExt as _;
use verily_api::ActionFilter;
use verily_api::AppealStatus;
use verily_api::AttemptStatus;
use verily_api::DraftInput;
use verily_api::ProofKind;
use verily_app::ops::AddAppRedirectUri;
use verily_app::ops::ApproveAppLink;
use verily_app::ops::BeginAttempt;
use verily_app::ops::BeginCapture;
use verily_app::ops::CompleteAttempt;
use verily_app::ops::ConfirmMediaUpload;
use verily_app::ops::CreateApp;
use verily_app::ops::CreateQrChallenge;
use verily_app::ops::GetAction;
use verily_app::ops::GetDraft;
use verily_app::ops::ListAvailableActions;
use verily_app::ops::ListMyAppeals;
use verily_app::ops::ListReviewAppeals;
use verily_app::ops::ListTemplates;
use verily_app::ops::PauseAction;
use verily_app::ops::PublishAction;
use verily_app::ops::ReportContent;
use verily_app::ops::RequestMediaUpload;
use verily_app::ops::ResolveAppeal;
use verily_app::ops::ReviewModerationCase;
use verily_app::ops::SaveAction;
use verily_app::ops::SubmitAppeal;
use verily_app::ops::SubmitLiveProof;
use verily_app::ops::SubmitMediaProof;
use verily_app::ops::SubmitQrProof;
use verily_verification::asn1::hex_lower;

async fn read_json(response: leptoskit_axum::axum::response::Response) -> serde_json::Value {
	let bytes = leptoskit_axum::axum::body::to_bytes(response.into_body(), 1 << 20)
		.await
		.unwrap();
	serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn templates_draft_edit_pause_and_spatial_nearby_work() {
	let world = world().await;
	let ada = world.person("ada@example.com").await;

	let templates = world.call(&ada.identity, ListTemplates {}).await.unwrap();
	assert_eq!(templates.len(), 12);

	let saved = world
		.call(
			&ada.identity,
			SaveAction {
				draft: DraftInput {
					id: None,
					title: "Spot the lighthouse".into(),
					summary: "Take a live photo from the promenade.".into(),
					place_name: "Brighton Pier".into(),
					radius_meters: 250,
					reward_amount: String::new(),
					proofs: vec![ProofKind::Photo, ProofKind::Presence],
					latitude: Some(50.8169),
					longitude: Some(-0.1367),
				},
			},
		)
		.await
		.unwrap();

	let loaded = world
		.call(
			&ada.identity,
			GetDraft {
				action_id: saved.id.clone(),
			},
		)
		.await
		.unwrap();
	assert_eq!(loaded.title, "Spot the lighthouse");
	assert_eq!(loaded.latitude, Some(50.8169));
	assert_eq!(loaded.longitude, Some(-0.1367));

	let published = world
		.call(
			&ada.identity,
			PublishAction {
				action_id: saved.id.clone(),
			},
		)
		.await
		.unwrap();
	assert!(published.is_live());

	// Spatial nearby search finds Brighton Pier from nearby coordinates and skips far coordinates.
	let nearby = world
		.call(
			&ada.identity,
			ListAvailableActions {
				filter: ActionFilter::Nearby,
				latitude: Some(50.82),
				longitude: Some(-0.14),
			},
		)
		.await
		.unwrap();
	assert!(nearby.iter().any(|c| c.id == saved.id));

	let far = world
		.call(
			&ada.identity,
			ListAvailableActions {
				filter: ActionFilter::Nearby,
				latitude: Some(35.6762),
				longitude: Some(139.6503),
			},
		)
		.await
		.unwrap();
	assert!(far.is_empty());

	// Pause hides the action from catalogue; resume brings it back.
	let paused = world
		.call(
			&ada.identity,
			PauseAction {
				action_id: saved.id.clone(),
				paused: true,
			},
		)
		.await
		.unwrap();
	assert!(paused.paused);
	assert!(!paused.live);

	let active_after_pause = world
		.call(
			&ada.identity,
			ListAvailableActions {
				filter: ActionFilter::All,
				latitude: None,
				longitude: None,
			},
		)
		.await
		.unwrap();
	assert!(!active_after_pause.iter().any(|c| c.id == saved.id));

	let resumed = world
		.call(
			&ada.identity,
			PauseAction {
				action_id: saved.id.clone(),
				paused: false,
			},
		)
		.await
		.unwrap();
	assert!(resumed.live);
	assert!(!resumed.paused);
}

#[tokio::test]
async fn venue_qr_challenge_redeems_once_and_verifies_attempt() {
	let world = world().await;
	let creator = world.person("creator@example.com").await;
	let player = world.person("player@example.com").await;

	let saved = world
		.call(
			&creator.identity,
			SaveAction {
				draft: DraftInput {
					id: None,
					title: "Scan the gallery QR".into(),
					summary: "Scan the rotating code at the desk.".into(),
					place_name: "Gallery Desk".into(),
					radius_meters: 50,
					reward_amount: String::new(),
					proofs: vec![ProofKind::VenueCode],
					latitude: None,
					longitude: None,
				},
			},
		)
		.await
		.unwrap();
	world
		.call(
			&creator.identity,
			PublishAction {
				action_id: saved.id.clone(),
			},
		)
		.await
		.unwrap();

	let qr = world
		.call(
			&creator.identity,
			CreateQrChallenge {
				action_id: saved.id.clone(),
				ttl_seconds: Some(600),
			},
		)
		.await
		.unwrap();
	assert!(qr.code.starts_with("vqr_"));

	let opened = world
		.call(
			&player.identity,
			BeginAttempt {
				action_id: saved.id.clone(),
			},
		)
		.await
		.unwrap();
	world
		.call(
			&player.identity,
			BeginCapture {
				attempt_id: opened.attempt_id.clone(),
				requirement_id: opened.requirement_id.clone(),
			},
		)
		.await
		.unwrap();

	let receipt = world
		.call(
			&player.identity,
			SubmitQrProof {
				attempt_id: opened.attempt_id.clone(),
				requirement_id: opened.requirement_id.clone(),
				code: qr.code.clone(),
			},
		)
		.await
		.unwrap();
	assert!(receipt.stored);

	// Reusing the same single-use venue code fails with conflict.
	let other = world.person("other@example.com").await;
	let other_opened = world
		.call(
			&other.identity,
			BeginAttempt {
				action_id: saved.id.clone(),
			},
		)
		.await
		.unwrap();
	assert_conflict(
		world
			.call(
				&other.identity,
				SubmitQrProof {
					attempt_id: other_opened.attempt_id,
					requirement_id: other_opened.requirement_id,
					code: qr.code,
				},
			)
			.await,
		"venueCodeUsed",
	);

	let outcome = world
		.call(
			&player.identity,
			CompleteAttempt {
				attempt_id: opened.attempt_id,
			},
		)
		.await
		.unwrap();
	assert_eq!(outcome.status, AttemptStatus::Verified);
}

#[tokio::test]
async fn moderation_hold_hides_action_and_appeal_resolution_overturns_rejection() {
	let world = world().await;
	let creator = world.person("creator@example.com").await;
	let participant = world.person("participant@example.com").await;
	let reviewer = world.person("reviewer@example.com").await;
	world.grant_reviewer(&reviewer).await;

	let saved = world
		.call(
			&creator.identity,
			SaveAction {
				draft: DraftInput {
					id: None,
					title: "Park bench photo".into(),
					summary: "Take a photo of the oak bench.".into(),
					place_name: "Oak Park".into(),
					radius_meters: 100,
					reward_amount: String::new(),
					proofs: vec![ProofKind::Photo],
					latitude: None,
					longitude: None,
				},
			},
		)
		.await
		.unwrap();
	world
		.call(
			&creator.identity,
			PublishAction {
				action_id: saved.id.clone(),
			},
		)
		.await
		.unwrap();

	// Participant submits proof -> manual review -> rejected -> appeals -> reviewer overturns!
	let opened = world
		.call(
			&participant.identity,
			BeginAttempt {
				action_id: saved.id.clone(),
			},
		)
		.await
		.unwrap();
	world
		.call(
			&participant.identity,
			BeginCapture {
				attempt_id: opened.attempt_id.clone(),
				requirement_id: opened.requirement_id.clone(),
			},
		)
		.await
		.unwrap();
	world
		.call(
			&participant.identity,
			SubmitLiveProof {
				attempt_id: opened.attempt_id.clone(),
				requirement_id: opened.requirement_id.clone(),
				digest_hex: digest(0x42),
			},
		)
		.await
		.unwrap();
	let pending = world
		.call(
			&participant.identity,
			CompleteAttempt {
				attempt_id: opened.attempt_id.clone(),
			},
		)
		.await
		.unwrap();
	assert_eq!(pending.status, AttemptStatus::PendingReview);

	let queue = world
		.call(&reviewer.identity, verily_app::ops::ListReviewQueue {})
		.await
		.unwrap();
	assert_eq!(queue.len(), 1);
	world
		.call(
			&reviewer.identity,
			verily_app::ops::ReviewAttempt {
				review_id: queue[0].id.clone(),
				accept: false,
				note: "Too blurry".into(),
			},
		)
		.await
		.unwrap();

	let appeal = world
		.call(
			&participant.identity,
			SubmitAppeal {
				attempt_id: opened.attempt_id.clone(),
				reason: "The plaque is readable in the top left corner.".into(),
			},
		)
		.await
		.unwrap();
	let my_appeals = world
		.call(&participant.identity, ListMyAppeals {})
		.await
		.unwrap();
	assert_eq!(my_appeals.len(), 1);
	assert_eq!(my_appeals[0].status, AppealStatus::Pending);

	let review_appeals = world
		.call(&reviewer.identity, ListReviewAppeals {})
		.await
		.unwrap();
	assert_eq!(review_appeals.len(), 1);

	let resolved = world
		.call(
			&reviewer.identity,
			ResolveAppeal {
				appeal_id: appeal.id,
				overturn: true,
				note: "Checked again, plaque is visible.".into(),
			},
		)
		.await
		.unwrap();
	assert_eq!(resolved.status, AppealStatus::Accepted);

	// Moderation report + safety hold hides the action from non-creators.
	let report = world
		.call(
			&participant.identity,
			ReportContent {
				target_kind: "action".into(),
				target_id: saved.id.clone(),
				reason: "unsafe_location".into(),
				notes: Some("Construction zone".into()),
			},
		)
		.await
		.unwrap();
	world
		.call(
			&reviewer.identity,
			ReviewModerationCase {
				case_id: report.id,
				new_status: "held".into(),
				note: "Holding pending review.".into(),
			},
		)
		.await
		.unwrap();

	assert_not_found(
		world
			.call(
				&participant.identity,
				GetAction {
					action_id: saved.id.clone(),
				},
			)
			.await,
	);
	let visible_list = world
		.call(
			&participant.identity,
			ListAvailableActions {
				filter: ActionFilter::All,
				latitude: None,
				longitude: None,
			},
		)
		.await
		.unwrap();
	assert!(!visible_list.iter().any(|c| c.id == saved.id));
}

#[tokio::test]
async fn partner_http_api_jwks_healthz_local_upload_and_jobs_work_end_to_end() {
	let _ = verily_app::ops::BACKEND;
	let db = leptoskit_db::testing::sqlite().await;
	let auth = Auth::builder(&db, Keys::single("test", [7; 32]));
	let host = verily_backend::start(&db, auth, None, verily_backend::Options::new(&db)).unwrap();
	let router = host.router.clone();

	// 1. /healthz and /.well-known/jwks.json
	let health = router
		.clone()
		.oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
		.await
		.unwrap();
	assert_eq!(health.status(), StatusCode::OK);

	let jwks_resp = router
		.clone()
		.oneshot(
			Request::get("/.well-known/jwks.json")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(jwks_resp.status(), StatusCode::OK);
	let jwks = read_json(jwks_resp).await;
	assert_eq!(jwks["keys"][0]["crv"], "Ed25519");

	// 2. Sign in a creator and register a Verily App.
	let sign_in = host
		.auth
		.dev_sign_in(
			"partner@example.com",
			&leptoskit_auth::RequestInfo::default(),
		)
		.await
		.unwrap();
	let signed_in = sign_in.signed_in();
	let identity = leptoskit_rpc::Identity::new(
		leptoskit_auth::context(Some(signed_in.clone()))
			.with(host.rewards.clone())
			.with(host.backend.clone()),
	)
	.with_caller(signed_in.session.to_string());

	let created_app = leptoskit_rpc::server::call_as(
		&db,
		identity.clone(),
		None,
		CreateApp {
			name: "FitQuest".into(),
			slug: "fitquest".into(),
			webhook_url: Some("https://partner.example/hooks/verily".into()),
		},
	)
	.await
	.unwrap();
	assert!(created_app.api_key_once.starts_with("vk_"));

	leptoskit_rpc::server::call_as(
		&db,
		identity.clone(),
		None,
		AddAppRedirectUri {
			app_id: created_app.app.id.clone(),
			uri: "fitquest://linked".into(),
		},
	)
	.await
	.unwrap();

	// 3. Approve link -> partner exchanges code over HTTP Bearer API!
	let exchange_view = leptoskit_rpc::server::call_as(
		&db,
		identity.clone(),
		None,
		ApproveAppLink {
			app_slug: "fitquest".into(),
			redirect_uri: "fitquest://linked".into(),
			state: Some("xyz".into()),
		},
	)
	.await
	.unwrap();

	let link_resp = router
		.clone()
		.oneshot(
			Request::post("/api/v1/links/exchange")
				.header(
					header::AUTHORIZATION,
					format!("Bearer {}", created_app.api_key_once),
				)
				.header(header::CONTENT_TYPE, "application/json")
				.body(Body::from(
					serde_json::json!({
						"code": exchange_view.code,
						"redirectUri": "fitquest://linked",
						"externalUserId": "ext_user_42"
					})
					.to_string(),
				))
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(link_resp.status(), StatusCode::OK);
	let link_json = read_json(link_resp).await;
	assert_eq!(link_json["externalUserId"], "ext_user_42");

	// 4. Local evidence upload -> confirm -> submit_media_proof -> verification job sweep!
	let saved = leptoskit_rpc::server::call_as(
		&db,
		identity.clone(),
		None,
		SaveAction {
			draft: DraftInput {
				id: None,
				title: "Upload test photo".into(),
				summary: "Take one photo.".into(),
				place_name: "Studio".into(),
				radius_meters: 0,
				reward_amount: String::new(),
				proofs: vec![ProofKind::Photo],
				latitude: None,
				longitude: None,
			},
		},
	)
	.await
	.unwrap();
	leptoskit_rpc::server::call_as(
		&db,
		identity.clone(),
		None,
		PublishAction {
			action_id: saved.id.clone(),
		},
	)
	.await
	.unwrap();

	let opened = leptoskit_rpc::server::call_as(
		&db,
		identity.clone(),
		None,
		BeginAttempt {
			action_id: saved.id.clone(),
		},
	)
	.await
	.unwrap();
	leptoskit_rpc::server::call_as(
		&db,
		identity.clone(),
		None,
		BeginCapture {
			attempt_id: opened.attempt_id.clone(),
			requirement_id: opened.requirement_id.clone(),
		},
	)
	.await
	.unwrap();

	let bytes = b"verily-live-jpeg-payload";
	let sha_hex = hex_lower(&Sha256::digest(bytes));
	let plan = leptoskit_rpc::server::call_as(
		&db,
		identity.clone(),
		None,
		RequestMediaUpload {
			attempt_id: opened.attempt_id.clone(),
			requirement_id: opened.requirement_id.clone(),
			mime_type: "image/jpeg".into(),
			byte_length: bytes.len() as i64,
		},
	)
	.await
	.unwrap();

	let put_path = format!("/_verily/local-evidence/{}", plan.object_key);
	let put_resp = router
		.clone()
		.oneshot(
			Request::put(&put_path)
				.header(header::CONTENT_TYPE, "image/jpeg")
				.body(Body::from(bytes.as_slice()))
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(put_resp.status(), StatusCode::OK);
	let put_json = read_json(put_resp).await;
	let version_id = put_json["versionId"].as_str().unwrap().to_owned();

	let confirmed = leptoskit_rpc::server::call_as(
		&db,
		identity.clone(),
		None,
		ConfirmMediaUpload {
			reservation_id: plan.reservation_id.clone(),
			version_id,
			expected_sha256_hex: sha_hex.clone(),
		},
	)
	.await
	.unwrap();
	assert_eq!(confirmed.sha256_hex, sha_hex);

	let submitted = leptoskit_rpc::server::call_as(
		&db,
		identity.clone(),
		None,
		SubmitMediaProof {
			attempt_id: opened.attempt_id,
			requirement_id: opened.requirement_id,
			reservation_id: plan.reservation_id,
		},
	)
	.await
	.unwrap();
	assert!(submitted.stored);

	// Run background verification & cleanup sweeps directly.
	let verified_jobs = verily_backend::jobs::run_evidence_verification_sweep(&db, &host.backend)
		.await
		.unwrap();
	assert_eq!(verified_jobs, 1);
	let summary = verily_backend::jobs::run_cleanup_sweeps(&db).await.unwrap();
	assert_eq!(summary.expired_verification_requests, 0);
}
