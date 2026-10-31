//! `HostResolver` contract, run against the system resolver and the in-memory one.
use opsagent_brain::adapters::{dns::SystemResolver, memory::FixedResolver};
use opsagent_core::endpoint::{EndpointRefusal, HostResolver};
use std::collections::HashMap;

async fn literal_resolves_to_itself(r: &dyn HostResolver) {
    let got = r.resolve("1.1.1.1", 443).await.unwrap();
    assert_eq!(got, vec!["1.1.1.1:443".parse().unwrap()]);
}

async fn unknown_name_is_unreachable(r: &dyn HostResolver) {
    let got = r.resolve("nothing.invalid", 443).await;
    assert_eq!(got, Err(EndpointRefusal::Unreachable));
}

macro_rules! resolver_contract {
    ($($name:ident: $make:expr),*) => {$(
        mod $name {
            use super::*;
            #[tokio::test]
            async fn resolver_ip_literal_resolves_to_itself() {
                literal_resolves_to_itself(&$make).await;
            }
            #[tokio::test]
            async fn resolver_unknown_name_is_unreachable() {
                unknown_name_is_unreachable(&$make).await;
            }
        }
    )*};
}

resolver_contract!(system: SystemResolver, fixed: FixedResolver::new(HashMap::new()));
