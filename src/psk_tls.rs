/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! OpenSSL TLS-PSK transport settings for gRPC (tonic-tls).
//!
//! Uses TLS 1.2 DHE-PSK ciphersuites (forward secrecy) and ALPN `h2`. Credentials come
//! from `[tls]` in `mnccd_config.toml` when `tls.mode = "psk"`.

use openssl::error::ErrorStack;
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion};

/// Wire-format ALPN list advertising HTTP/2 (`h2`), required for gRPC.
const ALPN_H2_PROTO: &[u8] = b"\x02h2";

// Ephemeral DH + PSK: session keys are not the PSK alone; past captures stay safe if the
// cluster PSK is later exposed. mozilla_intermediate supplies FFDHE-2048 DH params on the server.
const PSK_CIPHERS: &str = "DHE-PSK-AES256-GCM-SHA384:DHE-PSK-AES128-GCM-SHA256";

/// OpenSSL `SSL_MAX_PSK_LEN` (bytes). Longer keys cannot be used in PSK callbacks.
const MAX_PSK_KEY_LEN: usize = 256;

/// OpenSSL `PSK_MAX_IDENTITY_LEN` is 128 bytes; the client callback appends a null
/// terminator, so the identity itself may be at most 127 bytes.
const MAX_PSK_IDENTITY_LEN: usize = 127;

/// Placeholder `tls.psk_key` values shipped in samples/docs. Rejected at load so an
/// unchanged package config cannot be used as a real cluster secret.
const FORBIDDEN_SAMPLE_PSK_KEYS: &[&str] = &["replace-with-a-long-random-secret"];

/// PSK identity and key used for cluster gRPC connections.
#[derive(Clone)]
pub struct PskTlsConfig {
    pub identity: Vec<u8>,
    pub key: Vec<u8>,
}

impl std::fmt::Debug for PskTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PskTlsConfig")
            .field("identity", &String::from_utf8_lossy(&self.identity))
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl PskTlsConfig {
    pub fn from_strings(identity: &str, key: &str) -> Result<Self, String> {
        let identity = identity.trim();
        if identity.is_empty() {
            return Err("tls.psk_identity must not be empty when tls.mode = \"psk\"".into());
        }
        let identity_bytes = identity.as_bytes();
        if identity_bytes.len() > MAX_PSK_IDENTITY_LEN {
            return Err(format!(
                "tls.psk_identity must not exceed {MAX_PSK_IDENTITY_LEN} bytes when tls.mode = \"psk\""
            ));
        }
        let key = key.trim();
        if key.is_empty() {
            return Err("tls.psk_key must not be empty when tls.mode = \"psk\"".into());
        }
        if FORBIDDEN_SAMPLE_PSK_KEYS
            .iter()
            .any(|&s| s.eq_ignore_ascii_case(key))
        {
            return Err(
                "tls.psk_key must not use the sample placeholder from mnccd_config.toml; \
                 set a unique cluster secret"
                    .into(),
            );
        }
        let key_bytes = key.as_bytes();
        if key_bytes.len() > MAX_PSK_KEY_LEN {
            return Err(format!(
                "tls.psk_key must not exceed {MAX_PSK_KEY_LEN} bytes when tls.mode = \"psk\""
            ));
        }
        Ok(Self {
            identity: identity_bytes.to_vec(),
            key: key_bytes.to_vec(),
        })
    }
}

/// Build an OpenSSL server acceptor for TLS-PSK + ALPN h2.
pub fn server_acceptor(cfg: &PskTlsConfig) -> Result<SslAcceptor, ErrorStack> {
    let identity = cfg.identity.clone();
    let key = cfg.key.clone();

    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls_server())?;
    acceptor.set_cipher_list(PSK_CIPHERS)?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    acceptor.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    acceptor.set_alpn_protos(ALPN_H2_PROTO)?;
    acceptor.set_psk_server_callback(move |_ssl, client_identity, psk_buf| {
        let Some(id) = client_identity else {
            return Ok(0);
        };
        if id != identity.as_slice() {
            return Ok(0);
        }
        if psk_buf.len() < key.len() {
            return Ok(0);
        }
        psk_buf[..key.len()].copy_from_slice(&key);
        Ok(key.len())
    });
    Ok(acceptor.build())
}

/// Build an OpenSSL client connector for TLS-PSK + ALPN h2.
pub fn client_connector(cfg: &PskTlsConfig) -> Result<SslConnector, ErrorStack> {
    let identity = cfg.identity.clone();
    let key = cfg.key.clone();

    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_cipher_list(PSK_CIPHERS)?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_alpn_protos(ALPN_H2_PROTO)?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_psk_client_callback(move |_ssl, _hint, identity_buf, psk_buf| {
        if identity_buf.len() < identity.len() + 1 || psk_buf.len() < key.len() {
            return Ok(0);
        }
        identity_buf[..identity.len()].copy_from_slice(&identity);
        identity_buf[identity.len()] = 0;
        psk_buf[..key.len()].copy_from_slice(&key);
        Ok(key.len())
    });
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_psk_key() {
        let cfg = PskTlsConfig::from_strings("mnccd-cluster", "super-secret-key").unwrap();
        let debug = format!("{cfg:?}");
        assert!(debug.contains("mnccd-cluster"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret-key"));
    }

    #[test]
    fn psk_key_max_length_enforced_at_parse() {
        let key_256 = "x".repeat(MAX_PSK_KEY_LEN);
        assert!(PskTlsConfig::from_strings("id", &key_256).is_ok());

        let key_257 = "x".repeat(MAX_PSK_KEY_LEN + 1);
        let err = PskTlsConfig::from_strings("id", &key_257).unwrap_err();
        assert!(err.contains("256"));
        assert!(err.contains("tls.psk_key"));
    }

    #[test]
    fn psk_identity_max_length_enforced_at_parse() {
        let id_127 = "x".repeat(MAX_PSK_IDENTITY_LEN);
        assert!(PskTlsConfig::from_strings(&id_127, "key").is_ok());

        let id_128 = "x".repeat(MAX_PSK_IDENTITY_LEN + 1);
        let err = PskTlsConfig::from_strings(&id_128, "key").unwrap_err();
        assert!(err.contains("127"));
        assert!(err.contains("tls.psk_identity"));
    }

    #[test]
    fn rejects_sample_placeholder_psk_key() {
        let err = PskTlsConfig::from_strings("mnccd-cluster", "replace-with-a-long-random-secret")
            .unwrap_err();
        assert!(
            err.contains("sample placeholder"),
            "expected sample-key rejection, got: {err}"
        );

        let err = PskTlsConfig::from_strings("mnccd-cluster", "Replace-With-A-Long-Random-Secret")
            .unwrap_err();
        assert!(
            err.contains("sample placeholder"),
            "expected case-insensitive sample-key rejection, got: {err}"
        );
    }

    #[test]
    fn accepts_non_sample_psk_key() {
        assert!(PskTlsConfig::from_strings("mnccd-cluster", "unit-test-psk-key").is_ok());
    }
}
