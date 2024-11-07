// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AttestError {
    #[error("Failed to convert endpoint URL to CString")]
    Convertion,
    #[error("CVM guest attestation library returned error: {0}")]
    MAAToken(i32),
}
