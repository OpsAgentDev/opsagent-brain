//! Schedule maths and default schedules (PRD 7.3). Cron is evaluated in the org's IANA zone.
use std::str::FromStr;

use chrono::{
    DateTime, Duration, LocalResult, NaiveDateTime, NaiveTime, Offset, TimeZone, Timelike, Utc,
};
use chrono_tz::Tz;
use cron::Schedule;
use sea_orm::{ConnectionTrait, DbErr};
use uuid::Uuid;

use super::ledger_storage::stmt;

/// Nightly full scan at 02:00 local unless the connection sets `scan_time_local`.
pub const FULL_SCAN: &str = "0 2 * * *";
/// Weekly verification; daily while the connection is revoked, so a returned role recovers.
pub const VERIFY_WEEKLY: &str = "0 3 * * 1";
pub const VERIFY_REVOKED: &str = "0 4 * * *";

/// `HH:MM` local as a daily cron (`M H * * *`).
pub fn daily_at(t: NaiveTime) -> String {
    format!("{} {} * * *", t.minute(), t.hour())
}

const DOW: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// Standard cron (Mon=1, Sun=0|7) to the `cron` crate (Sun=1): numeric weekdays become names.
fn to_crate_syntax(expr: &str) -> Option<String> {
    let f: Vec<&str> = expr.split_whitespace().collect();
    if f.len() != 5 {
        return None;
    }
    let (mut dow, mut num, mut prev) = (String::new(), String::new(), ' ');
    for c in f[4].chars().chain([' ']) {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        if !num.is_empty() {
            match (prev, num.parse::<usize>()) {
                ('/', _) => dow += &num, // step, not a weekday
                (_, Ok(n)) if n <= 7 => dow += DOW[n % 7],
                _ => return None,
            }
            num.clear();
        }
        prev = c;
        dow.push(c);
    }
    dow.pop();
    Some(format!("0 {} {} {} {} {}", f[0], f[1], f[2], f[3], dow))
}

/// A local wall-clock time as an instant: overlap takes the first occurrence; a time inside a
/// gap is read with the offset in effect before the gap, i.e. shifted forward by the gap size
/// (02:30 on spring-forward day runs at 03:30; Lord Howe's 30min gap shifts by 30min).
fn instant(tz: Tz, local: NaiveDateTime) -> Option<DateTime<Utc>> {
    match tz.from_local_datetime(&local) {
        LocalResult::Single(t) | LocalResult::Ambiguous(t, _) => Some(t.to_utc()),
        LocalResult::None => {
            // No zone has two transitions within a day, so a day earlier is before the gap.
            let before = tz.offset_from_utc_datetime(&(local - Duration::days(1)));
            let off = Duration::seconds(before.fix().local_minus_utc().into());
            Some((local - off).and_utc())
        }
    }
}

/// Next occurrence strictly after `after`. `None` if the cron or zone is invalid.
pub fn next_after(cron_local: &str, tz: &str, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let tz = Tz::from_str(tz).ok()?;
    let schedule = Schedule::from_str(&to_crate_syntax(cron_local)?).ok()?;
    // Enumerate wall-clock times by pretending local time is UTC, so DST never skews the walk.
    let local = after.with_timezone(&tz).naive_local().and_utc();
    schedule
        .after(&local)
        .take(8)
        .filter_map(|n| instant(tz, n.naive_utc()))
        .find(|t| *t > after)
}

/// The first instant of the local day after `now`'s, minus a second: `next_after` from here
/// yields the first occurrence tomorrow.
pub fn end_of_local_day(tz: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let tz = Tz::from_str(tz).ok()?;
    let tomorrow = now.with_timezone(&tz).date_naive().succ_opt()?;
    Some(instant(tz, tomorrow.and_hms_opt(0, 0, 0)?)? - Duration::seconds(1))
}

async fn org_timezone(db: &impl ConnectionTrait, organisation_id: Uuid) -> Result<String, DbErr> {
    Ok(db
        .query_one_raw(stmt(
            "SELECT timezone FROM organisations WHERE id = $1",
            vec![organisation_id.into()],
        ))
        .await?
        .map(|r| r.try_get("", "timezone"))
        .transpose()?
        .unwrap_or_else(|| "UTC".into()))
}

/// Points the connection's `job_type` schedule at `cron` (in its stored zone), next due after
/// `from(zone)`. No-op if the schedule is missing or already on `cron`.
pub async fn set_cron(
    db: &impl ConnectionTrait,
    organisation_id: Uuid,
    connection_id: Uuid,
    job_type: &str,
    cron: &str,
    from: impl Fn(&str) -> Option<DateTime<Utc>>,
) -> Result<(), DbErr> {
    let Some(row) = db
        .query_one_raw(stmt(
            "SELECT id, timezone FROM schedules WHERE organisation_id = $1 AND connection_id = $2 \
             AND job_type = $3 AND cron_local <> $4",
            vec![
                organisation_id.into(),
                connection_id.into(),
                job_type.into(),
                cron.into(),
            ],
        ))
        .await?
    else {
        return Ok(());
    };
    let (id, tz): (Uuid, String) = (row.try_get("", "id")?, row.try_get("", "timezone")?);
    let next = from(&tz).and_then(|t| next_after(cron, &tz, t));
    db.execute_raw(stmt(
        "UPDATE schedules SET cron_local = $3, next_due_at = $4, updated_at = now() \
         WHERE organisation_id = $1 AND id = $2",
        vec![organisation_id.into(), id.into(), cron.into(), next.into()],
    ))
    .await?;
    Ok(())
}

/// Default schedules for a newly connected connection: the nightly scan (at `scan_time` when
/// set) and the weekly verify. Idempotent on `(connection_id, job_type)`.
pub async fn create_defaults(
    db: &impl ConnectionTrait,
    organisation_id: Uuid,
    connection_id: Uuid,
    scan_time: Option<NaiveTime>,
    now: DateTime<Utc>,
) -> Result<(), DbErr> {
    let tz = org_timezone(db, organisation_id).await?;
    let scan = scan_time.map_or_else(|| FULL_SCAN.to_owned(), daily_at);
    for (job, cron) in [("full_scan", scan.as_str()), ("verify", VERIFY_WEEKLY)] {
        db.execute_raw(stmt(
            "INSERT INTO schedules (id, organisation_id, connection_id, job_type, cron_local, timezone, next_due_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (connection_id, job_type) DO NOTHING",
            vec![
                Uuid::now_v7().into(),
                organisation_id.into(),
                connection_id.into(),
                job.into(),
                cron.into(),
                tz.clone().into(),
                next_after(cron, &tz, now).into(),
            ],
        ))
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn scan_time_becomes_a_daily_cron_from_tomorrow() {
        let t = NaiveTime::from_hms_opt(6, 30, 0).unwrap();
        assert_eq!(daily_at(t), "30 6 * * *");
        // 23:00 UTC on the 22nd is the 23rd in Berlin: "tomorrow" is the 24th there.
        let end = end_of_local_day("Europe/Berlin", at("2026-10-22T23:00:00Z")).unwrap();
        assert_eq!(end, at("2026-10-23T21:59:59Z"));
        assert_eq!(
            next_after(&daily_at(t), "Europe/Berlin", end),
            Some(at("2026-10-24T04:30:00Z"))
        );
    }

    #[test]
    fn weekday_numbers_follow_standard_cron() {
        // 2026-10-22 is a Thursday; next Monday 03:00 UTC is the 26th.
        assert_eq!(
            next_after("0 3 * * 1", "UTC", at("2026-10-22T00:00:00Z")),
            Some(at("2026-10-26T03:00:00Z"))
        );
        assert_eq!(
            next_after("0 3 * * 0", "UTC", at("2026-10-22T00:00:00Z")),
            Some(at("2026-10-25T03:00:00Z"))
        );
        assert_eq!(
            next_after("*/15 * * * *", "UTC", at("2026-10-22T00:01:00Z")),
            Some(at("2026-10-22T00:15:00Z"))
        );
        assert_eq!(next_after("bad", "UTC", at("2026-10-22T00:00:00Z")), None);
    }

    #[test]
    fn dst_gap_shifts_forward_and_overlap_runs_once() {
        // 02:30 EST does not exist on 2026-03-08: runs at 03:30 EDT (07:30Z).
        assert_eq!(
            next_after("30 2 * * *", "America/New_York", at("2026-03-08T06:00:00Z")),
            Some(at("2026-03-08T07:30:00Z"))
        );
        // 01:30 happens twice on 2026-11-01: first (EDT, 05:30Z) only.
        let first = next_after("30 1 * * *", "America/New_York", at("2026-11-01T00:00:00Z"));
        assert_eq!(first, Some(at("2026-11-01T05:30:00Z")));
        assert_eq!(
            next_after("30 1 * * *", "America/New_York", first.unwrap()),
            Some(at("2026-11-02T06:30:00Z"))
        );
    }

    #[test]
    fn dst_gaps_of_other_sizes_are_never_skipped() {
        // Lord Howe springs forward 02:00 -> 02:30 on 2026-10-04 (+10:30 -> +11:00).
        // 02:15 does not exist; it runs at 02:45 (+11:00) = 15:45Z on the 3rd.
        assert_eq!(
            next_after(
                "15 2 * * *",
                "Australia/Lord_Howe",
                at("2026-10-03T12:00:00Z")
            ),
            Some(at("2026-10-03T15:45:00Z"))
        );
        // Troll: 2h gap, 01:00 -> 03:00 UTC on 2026-03-29; 01:30 runs at 03:30 (+2) = 01:30Z.
        assert_eq!(
            next_after("30 1 * * *", "Antarctica/Troll", at("2026-03-28T12:00:00Z")),
            Some(at("2026-03-29T01:30:00Z"))
        );
    }
}
