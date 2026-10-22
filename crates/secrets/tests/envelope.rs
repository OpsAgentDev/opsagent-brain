use opsagent_secrets::{generate_dek, open, seal, Aad, EnvKek, Kek, SecretsError, WrappedDek};
use uuid::Uuid;

const ORG: Uuid = Uuid::from_u128(1);

fn aad(org: Uuid, column: &'static str) -> Aad {
    Aad {
        organisation_id: org,
        table: "connections",
        column,
    }
}

#[test]
fn round_trip() {
    let dek = generate_dek();
    let a = aad(Uuid::new_v4(), "token");
    let s = seal(&dek, b"hunter2", &a);
    assert_eq!(&*open(&dek, &s, &a).unwrap(), b"hunter2");
}

#[test]
fn wrong_column_fails() {
    let dek = generate_dek();
    let org = Uuid::new_v4();
    let s = seal(&dek, b"x", &aad(org, "token"));
    assert!(matches!(
        open(&dek, &s, &aad(org, "other")),
        Err(SecretsError::Decrypt)
    ));
}

#[test]
fn wrong_org_fails() {
    let dek = generate_dek();
    let s = seal(&dek, b"x", &aad(Uuid::new_v4(), "token"));
    assert!(open(&dek, &s, &aad(Uuid::new_v4(), "token")).is_err());
}

#[test]
fn nonce_is_random_per_seal() {
    let dek = generate_dek();
    let a = aad(Uuid::new_v4(), "token");
    assert_ne!(seal(&dek, b"x", &a).nonce, seal(&dek, b"x", &a).nonce);
}

#[test]
fn wrap_unwrap_round_trip() {
    let kek = EnvKek::new([1; 32], 1, None);
    let dek = generate_dek();
    let w = kek.wrap(ORG, &dek).unwrap();
    assert_eq!(w.version, 1);
    assert_eq!(*kek.unwrap(ORG, &w).unwrap(), *dek);
}

#[test]
fn v2_unwraps_v1_blob_with_prev() {
    let old = [1u8; 32];
    let dek = generate_dek();
    let w = EnvKek::new(old, 1, None).wrap(ORG, &dek).unwrap();
    let v2 = EnvKek::new([2; 32], 2, Some(old));
    assert_eq!(*v2.unwrap(ORG, &w).unwrap(), *dek);
    assert_eq!(v2.wrap(ORG, &dek).unwrap().version, 2);
}

#[test]
fn v2_without_prev_fails_naming_version() {
    let dek = generate_dek();
    let w = EnvKek::new([1; 32], 1, None).wrap(ORG, &dek).unwrap();
    let err = EnvKek::new([2; 32], 2, None).unwrap(ORG, &w).unwrap_err();
    assert!(matches!(err, SecretsError::UnknownVersion(1)));
    assert!(err.to_string().contains('1'));
}

#[test]
fn hkdf_info_differs_per_version() {
    // Same raw key under different versions derives different wrapping keys.
    let dek = generate_dek();
    let w1 = EnvKek::new([9; 32], 1, None).wrap(ORG, &dek).unwrap();
    let k2 = EnvKek::new([9; 32], 2, None);
    // A v1-labelled blob cannot be unwrapped by the same key as v2 wrapping key.
    let forged = WrappedDek {
        blob: w1.blob.clone(),
        version: 2,
    };
    assert!(matches!(
        k2.unwrap(ORG, &forged),
        Err(SecretsError::Decrypt)
    ));
    let w2 = k2.wrap(ORG, &dek).unwrap();
    assert_ne!(w1.blob[12..], w2.blob[12..]);
}

#[test]
fn from_env_validates() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    std::env::set_var("OPSAGENT_KEK", STANDARD.encode([7u8; 31]));
    assert!(matches!(
        EnvKek::from_env(),
        Err(SecretsError::BadKeyLength(31))
    ));
    std::env::set_var("OPSAGENT_KEK", "!!notbase64");
    assert!(matches!(EnvKek::from_env(), Err(SecretsError::BadBase64)));
    std::env::set_var("OPSAGENT_KEK", STANDARD.encode([7u8; 32]));
    std::env::set_var("OPSAGENT_KEK_VERSION", "3");
    std::env::set_var("OPSAGENT_KEK_PREV", STANDARD.encode([6u8; 32]));
    assert_eq!(EnvKek::from_env().unwrap().current_version(), 3);
}

#[test]
fn dek_wrapped_for_org_a_fails_for_org_b() {
    let kek = EnvKek::new([1; 32], 1, None);
    let w = kek.wrap(Uuid::new_v4(), &generate_dek()).unwrap();
    assert!(matches!(
        kek.unwrap(Uuid::new_v4(), &w),
        Err(SecretsError::Decrypt)
    ));
}
