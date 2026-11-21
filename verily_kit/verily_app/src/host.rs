//! Calls the shell's native live-capture, attestation, MediaPipe, and location
//! plugins (`verily-capture`, `verily-attest`, `mediapipe`, `location`).
//!
//! `beginCapture` must have already succeeded before [`open_live`] runs. The
//! key attestation challenge (`SHA-256(captureChallenge || attemptId)`) is
//! always prepared on `verily-attest` BEFORE any camera, microphone, sensor, or
//! QR scanner opens. This module NEVER opens an image picker, document picker,
//! or photo gallery.

use crate::live;
use crate::model::CaptureWindow;
use crate::model::LiveProof;

/// What the screen does after `beginCapture` returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureStep {
	/// The shell plugin may open. This is the only success.
	OpenPlugin,
	/// The shell has no capture plugin. The screen shows the failure copy.
	PluginMissing,
}

/// Live capture continues only when the shell plugin is installed.
#[must_use]
pub const fn next_capture_step(plugin_ready: bool) -> CaptureStep {
	if plugin_ready {
		CaptureStep::OpenPlugin
	} else {
		CaptureStep::PluginMissing
	}
}

/// Why a live capture or attestation did not finish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostFault {
	/// The shell did not register the plugin. Not a reason to pick a file.
	PluginMissing,
	/// The plugin answered, and the answer was not a live proof.
	Rejected,
}

/// Signed attestation bundle produced by `verily-attest` after capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceAttestationPayload {
	pub platform: &'static str,
	pub payload_b64: String,
	pub key_id_b64: Option<String>,
	pub integrity_token: Option<String>,
}

/// Opens the live sensor for `window` via `verily-capture`, enforcing that
/// `verily-attest` prepares the per-window hardware key first.
///
/// Never falls back to a photo library or file picker. On web or test hosts
/// without native plugins, returns `Err(HostFault::PluginMissing)`.
pub async fn open_live(window: &CaptureWindow) -> Result<LiveProof, HostFault> {
	if !live::plugin_allowed(live::CAMERA)
		|| !live::plugin_allowed(live::APP_INTEGRITY)
		|| !live::plugin_allowed(live::PERMISSIONS)
		|| live::plugin_allowed(live::IMAGE_PICKER)
		|| live::plugin_allowed(live::DOCUMENT_PICKER)
	{
		return Err(HostFault::Rejected);
	}
	let challenge = live::key_challenge(window).map_err(|_| HostFault::Rejected)?;
	if next_capture_step(capture_ready()) != CaptureStep::OpenPlugin {
		let _ = challenge;
		return Err(HostFault::PluginMissing);
	}

	#[cfg(all(feature = "native", target_arch = "wasm32"))]
	{
		native_capture::capture_live(window, &challenge).await
	}
	#[cfg(not(all(feature = "native", target_arch = "wasm32")))]
	{
		let _ = challenge;
		Err(HostFault::PluginMissing)
	}
}

/// Signs and attests `digest_hex` using `verily-attest` on native targets.
pub async fn attest_captured_digest(
	window: &CaptureWindow,
	digest_hex: &str,
) -> Result<DeviceAttestationPayload, HostFault> {
	#[cfg(all(feature = "native", target_arch = "wasm32"))]
	{
		native_capture::attest_digest(window, digest_hex).await
	}
	#[cfg(not(all(feature = "native", target_arch = "wasm32")))]
	{
		let _ = (window, digest_hex);
		Err(HostFault::PluginMissing)
	}
}

/// Scans a rotating venue QR code through `verily-capture` on native mobile.
pub async fn scan_venue_qr() -> Result<String, HostFault> {
	#[cfg(all(feature = "native", target_arch = "wasm32"))]
	{
		let plugin =
			verily_capture::guest::VerilyCapture::new().map_err(|_| HostFault::PluginMissing)?;
		plugin.scan_qr().await.map_err(|_| HostFault::Rejected)
	}
	#[cfg(not(all(feature = "native", target_arch = "wasm32")))]
	{
		Err(HostFault::PluginMissing)
	}
}

/// Captures a bounded canonical device motion trace JSON via `verily-capture`.
pub async fn capture_motion_trace(duration_ms: u32) -> Result<String, HostFault> {
	#[cfg(all(feature = "native", target_arch = "wasm32"))]
	{
		let plugin =
			verily_capture::guest::VerilyCapture::new().map_err(|_| HostFault::PluginMissing)?;
		plugin
			.capture_motion(duration_ms.clamp(1_000, 30_000))
			.await
			.map_err(|_| HostFault::Rejected)
	}
	#[cfg(not(all(feature = "native", target_arch = "wasm32")))]
	{
		let _ = duration_ms;
		Err(HostFault::PluginMissing)
	}
}

/// Fetches a one-shot device GPS fix for Nearby catalogue ranking (coordinates
/// are coarsened on the server and never exposed on public cards).
#[cfg_attr(not(all(feature = "native", target_arch = "wasm32")), allow(dead_code))]
pub async fn current_location() -> Option<(f64, f64)> {
	#[cfg(all(feature = "native", target_arch = "wasm32"))]
	{
		let plugin = verily_capture::guest::VerilyCapture::new().ok()?;
		let fix = plugin.capture_location().await.ok()?;
		if fix.is_mock {
			return None;
		}
		Some((fix.latitude, fix.longitude))
	}
	#[cfg(not(all(feature = "native", target_arch = "wasm32")))]
	{
		None
	}
}

fn capture_ready() -> bool {
	#[cfg(all(feature = "native", target_arch = "wasm32"))]
	{
		verily_capture::guest::VerilyCapture::new().is_ok()
	}
	#[cfg(not(all(feature = "native", target_arch = "wasm32")))]
	{
		false
	}
}

#[cfg(all(feature = "native", target_arch = "wasm32"))]
mod native_capture {
	use base64::Engine;
	use base64::engine::general_purpose::STANDARD;

	use super::DeviceAttestationPayload;
	use super::HostFault;
	use crate::model::CaptureWindow;
	use crate::model::LiveProof;
	use crate::model::ProofKind;

	pub(super) async fn capture_live(
		window: &CaptureWindow,
		challenge: &[u8; 32],
	) -> Result<LiveProof, HostFault> {
		// Step 1: ALWAYS prepare the per-window attested hardware key before
		// opening any camera, microphone, sensor, or scanner.
		let attest =
			verily_attest::guest::VerilyAttest::new().map_err(|_| HostFault::PluginMissing)?;
		let capture_id = format!("{}:{}", window.attempt_id, window.requirement_id);
		if cfg!(feature = "android") {
			attest
				.prepare_capture_key(&verily_attest::PrepareCaptureKey {
					capture_id,
					attestation_challenge: challenge.to_vec(),
				})
				.await
				.map_err(|_| HostFault::Rejected)?;
		}

		let capture =
			verily_capture::guest::VerilyCapture::new().map_err(|_| HostFault::PluginMissing)?;
		match window.kind {
			ProofKind::Photo => {
				let media = capture
					.capture_photo(verily_capture::CameraFacing::Back)
					.await
					.map_err(|_| HostFault::Rejected)?;
				Ok(LiveProof {
					digest_hex: media.sha256_hex,
				})
			}
			ProofKind::Video => {
				// Ensure MediaPipe guest bridge is reachable for movement tracking.
				let _mp = mediapipe::bridge::guest::GuestMediaPipe::new().ok();
				capture
					.start_video(verily_capture::StartVideoRequest {
						facing: verily_capture::CameraFacing::Back,
						max_duration_seconds: 60,
						camera_session_id: 1,
						record_audio: true,
					})
					.await
					.map_err(|_| HostFault::Rejected)?;
				let media = capture
					.stop_video()
					.await
					.map_err(|_| HostFault::Rejected)?;
				Ok(LiveProof {
					digest_hex: media.sha256_hex,
				})
			}
			ProofKind::Audio => {
				capture
					.start_audio(60)
					.await
					.map_err(|_| HostFault::Rejected)?;
				let media = capture
					.stop_audio()
					.await
					.map_err(|_| HostFault::Rejected)?;
				Ok(LiveProof {
					digest_hex: media.sha256_hex,
				})
			}
			ProofKind::VenueCode => {
				let code = capture.scan_qr().await.map_err(|_| HostFault::Rejected)?;
				Ok(LiveProof {
					digest_hex: verily_shared::sha256_hex(code.trim().as_bytes()),
				})
			}
			ProofKind::Movement => {
				let trace = capture
					.capture_motion(10_000)
					.await
					.map_err(|_| HostFault::Rejected)?;
				Ok(LiveProof {
					digest_hex: verily_shared::sha256_hex(trace.as_bytes()),
				})
			}
			ProofKind::Presence => {
				let loc = capture
					.capture_location()
					.await
					.map_err(|_| HostFault::Rejected)?;
				if loc.is_mock {
					return Err(HostFault::Rejected);
				}
				let payload = format!(
					"{:.6},{:.6},{:.2},{}",
					loc.latitude, loc.longitude, loc.accuracy_meters, loc.captured_at_ms
				);
				Ok(LiveProof {
					digest_hex: verily_shared::sha256_hex(payload.as_bytes()),
				})
			}
			ProofKind::Note | ProofKind::App => Err(HostFault::Rejected),
		}
	}

	pub(super) async fn attest_digest(
		window: &CaptureWindow,
		digest_hex: &str,
	) -> Result<DeviceAttestationPayload, HostFault> {
		let attest =
			verily_attest::guest::VerilyAttest::new().map_err(|_| HostFault::PluginMissing)?;
		if cfg!(feature = "android") {
			let capture_id = format!("{}:{}", window.attempt_id, window.requirement_id);
			let proof = attest
				.sign_capture_manifest(&verily_attest::SignCaptureManifest {
					capture_id,
					manifest: digest_hex.as_bytes().to_vec(),
				})
				.await
				.map_err(|_| HostFault::Rejected)?;
			let chain_b64: Vec<String> = proof
				.certificate_chain_der
				.iter()
				.map(|der| STANDARD.encode(der))
				.collect();
			let chain_json = serde_json::to_vec(&chain_b64).map_err(|_| HostFault::Rejected)?;
			let cloud_project = option_env!("VERILY_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER")
				.and_then(|s| s.parse::<u64>().ok())
				.unwrap_or(0);
			let integrity_token = if cloud_project > 0 {
				attest
					.request_play_integrity(&verily_attest::PlayIntegrityRequest {
						request_hash: digest_hex.to_owned(),
						cloud_project_number: cloud_project,
					})
					.await
					.ok()
			} else {
				None
			};
			return Ok(DeviceAttestationPayload {
				platform: "android",
				payload_b64: STANDARD.encode(chain_json),
				key_id_b64: None,
				integrity_token,
			});
		}
		if cfg!(feature = "ios") {
			let Some(stored) = attest
				.read_app_attest_key("current")
				.await
				.map_err(|_| HostFault::Rejected)?
			else {
				return Err(HostFault::Rejected);
			};
			let digest_bytes = verily_shared::sha256_bytes(digest_hex.as_bytes());
			let assertion = attest
				.generate_app_attest_assertion(&verily_attest::KeyHashRequest {
					key_id: stored.key_id.clone(),
					client_data_hash: digest_bytes,
				})
				.await
				.map_err(|_| HostFault::Rejected)?;
			return Ok(DeviceAttestationPayload {
				platform: "ios",
				payload_b64: STANDARD.encode(assertion),
				key_id_b64: Some(stored.key_id),
				integrity_token: None,
			});
		}
		Err(HostFault::PluginMissing)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_missing_plugin_does_not_become_a_library() {
		assert_eq!(next_capture_step(false), CaptureStep::PluginMissing);
		assert_eq!(next_capture_step(true), CaptureStep::OpenPlugin);
		assert!(!live::plugin_allowed(live::IMAGE_PICKER));
		assert!(!live::plugin_allowed(live::DOCUMENT_PICKER));
	}
}
