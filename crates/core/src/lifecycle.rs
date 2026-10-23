//! PRD 7.4 transition rules for a finding seen again in a run: reopen after expiry, flap when
//! it comes back quickly too often, settle after enough stable runs. Pure: repositories load
//! the inputs and persist the result.
use chrono::{DateTime, Duration, Utc};

/// A finding that comes back within this long of resolving came back quickly.
pub const FLAP_WINDOW: Duration = Duration::hours(24);
/// Events count towards flapping within this span.
pub const FLAP_SPAN: Duration = Duration::days(7);
pub const FLAP_TIMES: i32 = 3;
/// Consecutive seen runs after which a flapping finding counts as stable again.
pub const STABLE_RUNS: i32 = 7;

/// The stored state the rules read.
#[derive(Debug, Clone)]
pub struct SeenFinding<'a> {
    pub status: &'a str,
    pub flap_count: i32,
    pub stable_runs: i32,
    pub accepted_until: Option<DateTime<Utc>>,
    pub snoozed_until: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
}

/// `flapping` and `reopened` events of the finding within `FLAP_SPAN`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecentEvents {
    pub flapping: i64,
    pub reopened: i64,
}

/// The next state: status, events to write, flap counter, stable-run counter.
#[derive(Debug, Clone, PartialEq)]
pub struct Next {
    pub status: String,
    pub events: Vec<&'static str>,
    pub flap_count: i32,
    pub stable: i32,
}

impl SeenFinding<'_> {
    /// True when `next` reads `RecentEvents` (a resolved finding is back).
    pub fn reappears(&self) -> bool {
        !matches!(self.status, "open" | "flapping" | "accepted" | "snoozed")
    }

    /// The rules for this finding seen again at `now`.
    pub fn next(&self, recent: RecentEvents, now: DateTime<Utc>) -> Next {
        let expired = |until: Option<DateTime<Utc>>| until.is_some_and(|u| u <= now);
        let next = |status: &str, events: Vec<&'static str>, flap_count| Next {
            status: status.into(),
            events,
            flap_count,
            stable: self.stable_runs + 1,
        };
        match self.status {
            "open" => next("open", vec!["seen"], self.flap_count),
            "flapping" if self.stable_runs + 1 >= STABLE_RUNS => next("open", vec!["reopened"], 0),
            // Reported once when it started flapping; afterwards only counters move.
            "flapping" => next("flapping", vec![], self.flap_count),
            "accepted" if expired(self.accepted_until) => {
                next("open", vec!["reopened"], self.flap_count)
            }
            "snoozed" if expired(self.snoozed_until) => {
                next("open", vec!["reopened"], self.flap_count)
            }
            "accepted" | "snoozed" => next(self.status, vec![], self.flap_count),
            _ => self.reappeared(recent, now),
        }
    }

    /// A resolved finding is back: reopened, or flapping once it came back quickly too often.
    fn reappeared(&self, recent: RecentEvents, now: DateTime<Utc>) -> Next {
        let quick = self.resolved_at.is_some_and(|r| now - r <= FLAP_WINDOW);
        let flap_count = self.flap_count + i32::from(quick);
        let (status, events) = if flap_count >= FLAP_TIMES && recent.flapping > 0 {
            ("flapping", vec![])
        } else if quick && flap_count >= FLAP_TIMES && recent.reopened + 1 >= i64::from(FLAP_TIMES)
        {
            ("flapping", vec!["reopened", "flapping"])
        } else {
            ("open", vec!["reopened"])
        };
        Next {
            status: status.into(),
            events,
            flap_count,
            stable: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(status: &str) -> SeenFinding<'_> {
        SeenFinding {
            status,
            flap_count: 0,
            stable_runs: 0,
            accepted_until: None,
            snoozed_until: None,
            resolved_at: None,
        }
    }

    #[test]
    fn open_is_seen_and_unexpired_accept_stays_quiet() {
        let now = Utc::now();
        let n = seen("open").next(RecentEvents::default(), now);
        assert_eq!(
            (n.status.as_str(), n.events, n.stable),
            ("open", vec!["seen"], 1)
        );
        let accepted = SeenFinding {
            accepted_until: Some(now + Duration::days(1)),
            ..seen("accepted")
        };
        assert!(accepted
            .next(RecentEvents::default(), now)
            .events
            .is_empty());
        let expired = SeenFinding {
            accepted_until: Some(now),
            ..seen("accepted")
        };
        assert_eq!(
            expired.next(RecentEvents::default(), now).events,
            ["reopened"]
        );
    }

    #[test]
    fn quick_third_return_flaps_once_and_stable_runs_settle_it() {
        let now = Utc::now();
        let back = SeenFinding {
            flap_count: 2,
            resolved_at: Some(now - Duration::hours(1)),
            ..seen("resolved")
        };
        assert!(back.reappears());
        let recent = RecentEvents {
            flapping: 0,
            reopened: 2,
        };
        let n = back.next(recent, now);
        assert_eq!(
            (n.status.as_str(), n.events, n.flap_count),
            ("flapping", vec!["reopened", "flapping"], 3)
        );
        let again = back.next(
            RecentEvents {
                flapping: 1,
                ..recent
            },
            now,
        );
        assert_eq!((again.status.as_str(), again.events.len()), ("flapping", 0));
        let stable = SeenFinding {
            stable_runs: STABLE_RUNS - 1,
            flap_count: 3,
            ..seen("flapping")
        };
        let n = stable.next(RecentEvents::default(), now);
        assert_eq!((n.status.as_str(), n.flap_count), ("open", 0));
    }
}
