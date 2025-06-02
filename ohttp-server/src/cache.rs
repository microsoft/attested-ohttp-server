use crate::utils;
use moka::future::Cache;
use ohttp::{
    KeyConfig, SymmetricSuite,
    hpke::{Aead, Kdf, Kem},
};
use std::sync::{Arc, LazyLock};
use tokio::time::Duration;

use utils::Res;

// We cache both successful key releases from the KMS as well as SKR errors,
// as guest attestation is very expensive (IMDS + TPM createPrimary + RSA decrypt x2)
// ValidKey expire based on the TTL of the cache (24 hours)
// SKRError are manually invalidated (see import_config), after 60 seconds
#[derive(Clone)]
pub enum CachedKey {
    SKRError(std::time::SystemTime),
    ValidKey(Box<KeyConfig>, String),
}

pub static CACHE: LazyLock<Arc<Cache<u8, CachedKey>>> = LazyLock::new(|| {
    Arc::new(
        Cache::builder()
            .time_to_live(Duration::from_secs(24 * 60 * 60))
            .build(),
    )
});

use tracing::error;
pub async fn cache_local_config() -> Res<()> {
    let config: KeyConfig = KeyConfig::new(
        0,
        Kem::P384Sha384,
        vec![
            SymmetricSuite::new(Kdf::HkdfSha384, Aead::Aes256Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
        ],
    )
    .map_err(|e| {
        error!("{e}");
        e
    })?;

    CACHE
        .insert(
            0,
            CachedKey::ValidKey(
                Box::new(config),
                "<LOCALLY GENERATED KEY, NO ATTESTATION TOKEN>".to_owned(),
            ),
        )
        .await;
    Ok(())
}
