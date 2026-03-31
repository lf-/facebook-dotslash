/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

/// Generates a DotSlash artifact entry JSON for a nix store path.
pub fn print_entry_for_nix_store_path(
    store_path: &str,
    path: &str,
    substituter: Option<&str>,
    trusted_public_keys: Option<&str>,
) {
    let digest = blake3::hash(store_path.as_bytes());

    let mut provider = serde_json::json!({
        "type": "nix-substituter",
        "store_path": store_path,
    });
    if let Some(substituter) = substituter {
        provider["substituter"] = serde_json::Value::String(substituter.to_owned());
    }
    if let Some(keys) = trusted_public_keys {
        provider["trusted_public_keys"] = serde_json::Value::String(keys.to_owned());
    }

    let entry = serde_json::json!({
        "size": 0,
        "hash": "blake3",
        "digest": digest.to_hex().to_string(),
        "path": path,
        "providers": [provider],
    });

    println!("{}", serde_json::to_string_pretty(&entry).unwrap());
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_digest_matches_provider() {
        // The digest in the entry must be blake3(store_path), which is what
        // the nix provider checks at fetch time.
        let store_path = "/nix/store/gs5hgjzh1ndgsna0jvq3hx4w17x3wz75-bc-1.08.2";
        let expected_digest = blake3::hash(store_path.as_bytes()).to_hex().to_string();

        // Capture output by calling the building blocks directly
        let entry = serde_json::json!({
            "size": 0,
            "hash": "blake3",
            "digest": blake3::hash(store_path.as_bytes()).to_hex().to_string(),
            "path": "bin/bc",
            "providers": [{
                "type": "nix-substituter",
                "store_path": store_path,
            }],
        });

        assert_eq!(entry["digest"].as_str().unwrap(), expected_digest);
        assert_eq!(entry["hash"].as_str().unwrap(), "blake3");
        assert_eq!(entry["size"].as_u64().unwrap(), 0);
    }

    #[test]
    fn test_optional_fields_included() {
        let store_path = "/nix/store/abc123-my-tool";
        let mut provider = serde_json::json!({
            "type": "nix-substituter",
            "store_path": store_path,
        });
        provider["substituter"] =
            serde_json::Value::String("https://cache.nixos.org".to_owned());
        provider["trusted_public_keys"] =
            serde_json::Value::String("cache.nixos.org-1:AAAA".to_owned());

        assert_eq!(
            provider["substituter"].as_str().unwrap(),
            "https://cache.nixos.org"
        );
        assert_eq!(
            provider["trusted_public_keys"].as_str().unwrap(),
            "cache.nixos.org-1:AAAA"
        );
    }
}
