/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

use std::path::Path;
use std::process::Command;

use anyhow::Context as _;
use serde::Deserialize;
use serde_json::Value;

use crate::config::ArtifactEntry;
use crate::config::HashAlgorithm;
use crate::digest::Digest;
use crate::dotslash_cache::DotslashCache;
use crate::provider::FetchResult;
use crate::provider::Provider;
use crate::util::CommandDisplay;
use crate::util::CommandStderrDisplay;
use crate::util::FileLock;
use crate::util::fs_ctx;

pub struct NixSubstituterProvider {}

#[derive(Deserialize, Debug)]
struct NixSubstituterProviderConfig {
    store_path: String,
    substituter: Option<String>,
    trusted_public_keys: Option<String>,
}

impl Provider for NixSubstituterProvider {
    fn fetch_artifact(
        &self,
        provider_config: &Value,
        destination: &Path,
        _fetch_lock: &FileLock,
        artifact_entry: &ArtifactEntry,
    ) -> anyhow::Result<FetchResult> {
        #[cfg(not(unix))]
        return Err(anyhow::format_err!(
            "nix-substituter provider is only supported on Unix"
        ));

        let NixSubstituterProviderConfig {
            store_path,
            substituter,
            trusted_public_keys,
        } = <_>::deserialize(provider_config)?;

        let store_path_hash = blake3::hash(store_path.as_bytes());
        let store_path_hex = store_path_hash.to_hex();

        // The digest field must be the blake3 hash of the store_path string.
        // This ensures the dotslash cache key is unique per store path.
        match artifact_entry.hash {
            HashAlgorithm::Blake3 => {
                let expected = Digest::try_from(store_path_hex.to_string())?;
                if artifact_entry.digest != expected {
                    return Err(anyhow::format_err!(
                        "nix-substituter: digest must be blake3 of store_path.\n\
                         expected digest: {expected}\n\
                         got digest:      {}",
                        artifact_entry.digest,
                    ));
                }
            }
            _ => {
                return Err(anyhow::format_err!(
                    "nix-substituter: hash algorithm must be \"blake3\""
                ));
            }
        }

        // Compute a stable GC root path based on the store path.
        let cache = DotslashCache::new();
        let gcroots_dir = cache.cache_dir().join("nix-gcroots");
        fs_ctx::create_dir_all(&gcroots_dir)?;
        let gcroot_path = gcroots_dir.join(store_path_hash.to_hex().to_string());

        // Run nix-store --realise to fetch and realise the store path.
        let mut command = Command::new("nix-store");
        command
            .arg("--realise")
            .arg(&store_path)
            .arg("--add-root")
            .arg(&gcroot_path);

        if let Some(ref substituter) = substituter {
            command
                .arg("--option")
                .arg("extra-substituters")
                .arg(substituter);
        }

        if let Some(ref trusted_public_keys) = trusted_public_keys {
            command
                .arg("--option")
                .arg("extra-trusted-public-keys")
                .arg(trusted_public_keys);
        }

        let output = command
            .output()
            .with_context(|| format!("{}", CommandDisplay::new(&command)))
            .context("failed to run nix-store")?;

        if !output.status.success() {
            return Err(anyhow::format_err!(
                "{}",
                CommandStderrDisplay::new(&output)
            ))
            .with_context(|| format!("{}", CommandDisplay::new(&command)))
            .context("nix-store --realise failed");
        }

        // Construct the full binary path inside the store path.
        let binary_path = Path::new(&store_path).join(artifact_entry.path.as_str());

        // Create a symlink at destination pointing to the binary.
        #[cfg(unix)]
        std::os::unix::fs::symlink(&binary_path, destination)
            .with_context(|| format!("failed to create symlink at `{}`", destination.display()))?;

        Ok(FetchResult::PreVerified)
    }
}
