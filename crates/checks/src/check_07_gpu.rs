use crate::ctx::{draft, short, Check, CheckCtx};
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
            let (n, id) = (short(r), &r.identity);
            let (variant, sev, title, s, step, ex) = match r.service() {
                "ec2" if a["accelerated"] == true && a["state"] == "running" => {
                    let Some(u) = a["gpu_util_24h"].as_f64().filter(|u| *u < IDLE_PCT) else {
                        continue;
                    };
                    (
                        "idle_gpu",
                        Severity::High,
                        format!("Idle GPU instance {n}"),
                        format!("{id} averaged {u}% GPU use over the last 24 hours."),
                        "GPU instances are among the most expensive in AWS and bill every second they run. Stop it if no work is planned: EC2 console > Instances > Instance state > Stop, or `aws ec2 stop-instances --instance-ids <instance-id>`.",
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
                        format!("Training job {n} may be stuck"),
                        format!("{id} has run for {} hours, longer than its usual runtime.", run_s / 3600),
                        "A stuck job keeps billing for its instances. SageMaker console > Training jobs > the job > View logs; if it is not progressing, Stop it, or `aws sagemaker stop-training-job --training-job-name <job>`.",
                        format!(
                            "runtime_s={run_s} median_runtime_s={}",
                            a["median_runtime_s"]
                        ),
                    )
                }
                _ => continue,
            };
            out.push(draft(ctx, "07", r, variant, sev, (title, s, step), ex));
        }
        out
    }
}
