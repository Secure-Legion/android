/// Loss-Adaptive FEC Controller for Tor Voice Calls
///
/// Dynamically adjusts Opus FEC and packet loss percentage based on
/// measured network loss using EMA smoothing to prevent flapping.
///
/// Usage:
/// ```rust
/// let mut fec = LossAdaptiveFec::new();
/// // Every frame or window:
/// fec.update(measured_loss_rate); // 0.0..1.0
/// if fec.should_apply() {
/// let target = fec.desired_packet_loss_perc();
/// opus_set_packet_loss_perc(encoder, target)?;
/// }
/// ```
use std::os::raw::c_void;

#[derive(Debug)]
pub struct LossAdaptiveFec {
    /// Exponential moving average of loss rate (0.0..1.0)
    ema_loss: f32,

    /// Last packet loss % value pushed to Opus encoder
    last_set: i32,

    /// Frame tick counter (for update rate limiting)
    tick: u32,

    /// EMA smoothing factor (0.10–0.25 works well for Tor)
    alpha: f32,
}

impl Default for LossAdaptiveFec {
    fn default() -> Self {
        Self::new()
    }
}

impl LossAdaptiveFec {
    /// Create new adaptive FEC controller with default settings
    pub fn new() -> Self {
        Self {
            ema_loss: 0.0,
            last_set: 25, // Start with 25% (our static default)
            tick: 0,
            alpha: 0.15, // 0.15 = balanced responsiveness
        }
    }

    /// Create with custom EMA alpha (smoothing factor)
    /// - Lower alpha (0.05-0.10): More stable, slower to adapt
    /// - Higher alpha (0.20-0.30): More responsive, may flap
    /// - Recommended: 0.15 for Tor (good balance)
    pub fn with_alpha(alpha: f32) -> Self {
        Self {
            ema_loss: 0.0,
            last_set: 25,
            tick: 0,
            alpha: alpha.clamp(0.05, 0.30),
        }
    }

    /// Update with new loss measurement
    ///
    /// @param window_loss Measured packet loss rate (0.0 = no loss, 1.0 = 100% loss)
    /// Should be calculated over a recent window (e.g., last 5 seconds)
    pub fn update(&mut self, window_loss: f32) {
        // EMA smoothing: stable, avoids flapping
        // New EMA = (1 - α) * old_EMA + α * new_sample
        self.ema_loss = (1.0 - self.alpha) * self.ema_loss + self.alpha * window_loss.clamp(0.0, 1.0);
        self.tick = self.tick.wrapping_add(1);
    }

    /// Get desired Opus packet loss percentage based on measured loss
    ///
    /// Applies headroom multiplier (1.25x) to anticipate Tor burst loss
    /// Clamps to sane range (5-35%) to avoid extreme values
    pub fn desired_packet_loss_perc(&self) -> i32 {
        // Convert 0.0..1.0 to percentage
        let mut p = (self.ema_loss * 100.0) as i32;

        // Add 25% headroom for Tor burst loss
        // (Tor loss is spiky, not smooth - anticipate bursts)
        p = (p as f32 * 1.25).round() as i32;

        // Clamp to sane range:
        // - Min 5%: Always have some FEC even on good networks
        // - Max 35%: Beyond 35%, quality degrades too much (use lower bitrate instead)
        p.clamp(5, 35)
    }

    /// Check if we should apply Opus CTL update now
    ///
    /// Updates at most once per second (assuming 40ms frames = 25 fps)
    /// Prevents rapid oscillation that can destabilize encoder
    pub fn should_apply(&self) -> bool {
        // Update every 25 frames (1 second at 40ms frames)
        self.tick % 25 == 0
    }

    /// Get current EMA loss rate (for debugging/telemetry)
    pub fn get_ema_loss(&self) -> f32 {
        self.ema_loss
    }

    /// Get last set packet loss percentage (for debugging)
    pub fn get_last_set(&self) -> i32 {
        self.last_set
    }

    /// Apply FEC update to Opus encoder (with hysteresis)
    ///
    /// Only updates if:
    /// 1. It's time to update (should_apply() returns true)
    /// 2. The change is meaningful (≥3% difference)
    ///
    /// Returns true if encoder was updated
    pub unsafe fn maybe_update_encoder(
        &mut self,
        encoder_ptr: *mut c_void
    ) -> Result<bool, i32> {
        if !self.should_apply() {
            return Ok(false);
        }

        let target = self.desired_packet_loss_perc();

        // Hysteresis: only push if meaningfully different
        // (prevents oscillation around threshold)
        if (target - self.last_set).abs() < 3 {
            return Ok(false);
        }

        // Enable FEC when expected loss ≥ 10%
        let enable_fec = target >= 10;

        // Apply to encoder
        crate::audio::opus_ctl::opus_set_inband_fec(encoder_ptr, enable_fec)?;
        crate::audio::opus_ctl::opus_set_packet_loss_perc(encoder_ptr, target)?;

        log::info!(
            "Adaptive FEC: loss={:.1}% → target={}% (was {}%), FEC={}",
            self.ema_loss * 100.0,
            target,
            self.last_set,
            enable_fec
        );

        self.last_set = target;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ema_smoothing() {
        let mut fec = LossAdaptiveFec::new();

        // Simulate sudden loss spike
        fec.update(0.30); // 30% loss

        // EMA should smooth it (won't jump to 30% immediately)
        assert!(fec.get_ema_loss() < 0.30);
        assert!(fec.get_ema_loss() > 0.0);
    }

    #[test]
    fn test_headroom_multiplier() {
        let mut fec = LossAdaptiveFec::new();

        // Set EMA to 20%
        for _ in 0..20 {
            fec.update(0.20);
        }

        // Desired should be 20% * 1.25 = 25%
        let target = fec.desired_packet_loss_perc();
        assert_eq!(target, 25);
    }

    #[test]
    fn test_clamps_to_sane_range() {
        let mut fec = LossAdaptiveFec::new();

        // Extreme loss (50%)
        for _ in 0..50 {
            fec.update(0.50);
        }

        // Should clamp to max 35%
        let target = fec.desired_packet_loss_perc();
        assert!(target <= 35);
    }

    #[test]
    fn test_minimum_floor() {
        let mut fec = LossAdaptiveFec::new();

        // No loss
        for _ in 0..20 {
            fec.update(0.0);
        }

        // Should still have minimum 5% FEC
        let target = fec.desired_packet_loss_perc();
        assert!(target >= 5);
    }

    #[test]
    fn test_update_rate_limiting() {
        let fec = LossAdaptiveFec::new();

        // Should only update every 25 frames
        assert!(!fec.should_apply()); // tick 0

        let mut fec = LossAdaptiveFec::new();
        for _ in 0..24 {
            fec.update(0.10);
            assert!(!fec.should_apply());
        }
        fec.update(0.10);
        assert!(fec.should_apply()); // tick 25
    }
}
