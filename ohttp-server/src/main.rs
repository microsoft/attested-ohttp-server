// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![deny(clippy::pedantic)]

use clap::Parser;
use ohttp_server::{cache::cache_local_config, discover, init, score, utils::Args};
use std::sync::Arc;
use warp::Filter;
type Res<T> = Result<T, Box<dyn std::error::Error>>;
use tracing::error;
use uuid::Uuid;
use warp::http::HeaderMap;

#[tokio::main]
async fn main() -> Res<()> {
    init();

    let args = Args::parse();
    let address = args.address;

    // Generate a fresh key for local testing. KID is set to 0.
    if args.local_key {
        cache_local_config().await.map_err(|e| {
            error!("{e}");
            e
        })?;
    }

    let argsc = Arc::new(args);
    let args1 = Arc::clone(&argsc);
    let score = warp::post()
        .and(warp::path::path("score"))
        .and(warp::path::end())
        .and(warp::header::headers_cloned())
        .and(warp::body::bytes())
        .and(warp::any().map(move || Arc::clone(&args1)))
        .and_then(
            |headers: HeaderMap, body: warp::hyper::body::Bytes, args: Arc<Args>| {
                let uuid = headers
                    .get("apim-request-id")
                    .and_then(|val| val.to_str().ok())
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .unwrap_or_else(Uuid::new_v4);
                score(headers, body, args, uuid)
            },
        );
    let args2 = Arc::clone(&argsc);
    let discover = warp::get()
        .and(warp::path("discover"))
        .and(warp::path::end())
        .and(warp::any().map(move || Arc::clone(&args2)))
        .and_then(discover);

    let routes = score.or(discover);
    warp::serve(routes).run(address).await;

    Ok(())
}
