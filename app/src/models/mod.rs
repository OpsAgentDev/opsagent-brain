pub mod _entities;
pub mod audit;
pub mod magic_links;
pub mod members;
pub mod organisations;
pub mod users;

use sea_orm::prelude::DateTimeWithTimeZone;

pub fn now() -> DateTimeWithTimeZone {
    chrono::Utc::now().into()
}
