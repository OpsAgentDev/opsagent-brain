//! Deterministic checks over inventory, cost, and metrics. Framework-free.
pub mod check_01_cost;
pub mod check_02_iam;
pub mod check_03_exposure;
pub mod check_04_backups;
pub mod check_05_certificates;
pub mod check_07_gpu;
pub mod ctx;

pub use ctx::{Check, CheckCtx, MetricStore};

/// Checks in id order.
pub fn all() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(check_01_cost::CostAndIdle),
        Box::new(check_02_iam::IamHygiene),
        Box::new(check_03_exposure::PublicExposure),
        Box::new(check_04_backups::Backups),
        Box::new(check_05_certificates::Certificates),
        Box::new(check_07_gpu::GpuAndTraining),
    ]
}
