//! One admission budget shared by validation, lock waiting and refresh exchange.
use anyhow::{Result, ensure};
use std::time::{Duration, Instant};

pub struct AccessBudget {
    deadline: Instant,
}

impl Default for AccessBudget {
    fn default() -> Self {
        Self::until(Instant::now() + Duration::from_secs(8))
    }
}

impl AccessBudget {
    pub fn until(deadline: Instant) -> Self {
        Self { deadline }
    }

    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    pub fn check(&self) -> Result<()> {
        ensure!(
            !self.remaining().is_zero(),
            "OAuth access budget exhausted; retry access"
        );
        Ok(())
    }

    pub fn exchange_timeout(&self) -> Result<Duration> {
        // Reserve persistence time inside the helper's 8s budget, leaving
        // another second before OpenCode kills its 9s subprocess (OMP: 10s).
        // Disk stalls/process suspension are not bounded; real crashes still
        // retain the durable uncertain-refresh fence.
        let available = self.remaining().saturating_sub(Duration::from_secs(1));
        ensure!(
            !available.is_zero(),
            "insufficient OAuth refresh budget; no exchange was sent"
        );
        Ok(available.min(Duration::from_secs(5)))
    }
}
