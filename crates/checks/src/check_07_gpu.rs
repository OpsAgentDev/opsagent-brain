use crate::ctx::{draft, Check, CheckCtx};
use chrono::{DateTime, Utc};
use opsagent_connectors::Capability;
use opsagent_core::finding::{FindingDraft, Severity};
use opsagent_core::resource::Provider;

pub struct GpuAndTraining;

const IDLE_PCT: f64 = 5.0;
const NO_HISTORY_LIMIT_S: i64 = 24 * 3600;

impl Check for GpuAndTraining {
    fn id(&self) -> &'static str {
        "07"
    }
    fn supported(&self) -> &[Provider] {
        &[Provider::Aws, Provider::Fake]
    }
    fn required(&self) -> &[Capability] {
        &[Capability::Gpu]
    }

    // Reads only contract keys; nothing else on a resource reaches evidence.
    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft> {
        let mut out = vec![];
        for r in ctx.resources {
            let a = &r.attributes;
            let id = &r.identity;
            let (variant, sev, title, step, ex) = match r.service() {
                "ec2" if a["accelerated"] == true && a["state"] == "running" => {
                    let Some(u) = a["gpu_util_24h"].as_f64().filter(|u| *u < IDLE_PCT) else {
                        continue;
                    };
                    (
                        "idle_gpu",
                        Severity::High,
                        format!("Idle GPU instance {id}"),
                        "Stop or terminate the instance, or move work onto it.",
                        format!("gpu_util_24h={u}"),
                    )
                }
                "sagemaker" if a["status"] == "InProgress" => {
                    let Some(start) = a["started_at"]
                        .as_str()
                        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                    else {
                        continue;
                    };
                    let run_s = (ctx.now - start).num_seconds();
                    let median = a["median_runtime_s"].as_u64();
                    let limit = median.map_or(NO_HISTORY_LIMIT_S, |m| 3 * m as i64);
                    if run_s <= limit {
                        continue;
                    }
                    (
                        "stuck_training_job",
                        Severity::Medium,
                        format!("Training job {id} may be stuck"),
                        "Check the job's logs and stop it if it is not making progress.",
                        format!(
                            "runtime_s={run_s} median_runtime_s={}",
                            a["median_runtime_s"]
                        ),
                    )
                }
                _ => continue,
            };
            let s = format!("{title}.");
            out.push(draft(ctx, "07", r, variant, sev, (title, s, step), ex));
        }
        out
    }
}
