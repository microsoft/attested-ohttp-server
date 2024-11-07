// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Incorrect CBOR encoding in returned private key")]
    KMSCBOREncoding,
    #[error("Bad CBOR key type, expected P-384(2)")]
    KMSCBORKeyType,
    #[error("Unexpected field in exported private key from KMS")]
    KMSField,
    #[error("Bad key identifier in SKR response")]
    KMSKeyId,
    #[error("Invalid secret exponent in SKR response")]
    KMSExponent,
    #[error("KMS returned an unexpected status code: {0}")]
    KMSUnexpected(u16),
    #[error("Max retries reached, giving up. Cannot reach key management service")]
    KMSUnreachable,
    #[error("Private key missing from SKR response")]
    PrivateKeyMissing,
}
