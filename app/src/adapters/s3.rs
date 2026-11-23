//! The contacts export's S3 write, with the process's default AWS credentials.
use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};

use crate::{
    actions::runs::ObjectStore,
    error::{AppError, AppResult},
};

pub struct S3Store {
    bucket: String,
}

impl S3Store {
    pub fn new(bucket: &str) -> Self {
        Self {
            bucket: bucket.to_owned(),
        }
    }
}

#[async_trait]
impl ObjectStore for S3Store {
    /// Loads the credentials per call: the export runs once a week.
    async fn put(&self, key: &str, body: Vec<u8>) -> AppResult<()> {
        let mut cfg = aws_config::defaults(BehaviorVersion::latest()).load().await;
        if cfg.region().is_none() {
            cfg = cfg
                .to_builder()
                .region(Region::from_static("us-west-2"))
                .build();
        }
        aws_sdk_s3::Client::new(&cfg)
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type("text/csv")
            .body(body.into())
            .send()
            .await
            // Provider error text can name the account (logging.md): the caller logs a code.
            .map_err(|_| AppError::Internal("s3 put failed".into()))?;
        Ok(())
    }
}
