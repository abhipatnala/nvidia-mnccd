/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! gRPC interceptor that admits only callers whose IP is in `node_ips`.

use std::collections::HashSet;
use std::net::IpAddr;
use tonic::service::Interceptor;
use tonic::transport::server::TcpConnectInfo;
use tonic::{Request, Status};
use tracing::warn;

/// gRPC status message for denied callers. Intentionally fixed: the peer IP is
/// logged server-side and must not be returned over the wire.
const REQUEST_DENIED: &str = "request denied";

/// Rejects gRPC requests whose peer IP is not in the configured cluster node list.
///
/// Peer address is taken from tonic's [`Request::remote_addr`] (plain TCP and
/// tonic mTLS) and, when that is `None`, from tonic-tls OpenSSL
/// [`SslConnectInfo`](tonic_tls::openssl::SslConnectInfo) (TLS-PSK). Unknown
/// or unreadable peer addresses are denied.
#[derive(Clone, Debug)]
pub(crate) struct NodeAllowlistInterceptor {
    allowed: HashSet<IpAddr>,
}

impl NodeAllowlistInterceptor {
    /// Builds an allowlist from `node_ips` strings (IPv4 and IPv6).
    pub(crate) fn from_node_ips(node_ips: &[String]) -> Result<Self, String> {
        let allowed = node_ips
            .iter()
            .map(|s| {
                s.parse::<IpAddr>()
                    .map(canonical_ip)
                    .map_err(|e| format!("invalid IP in node_ips {s:?}: {e}"))
            })
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(Self { allowed })
    }
}

impl Interceptor for NodeAllowlistInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        match remote_ip_from_request(&request) {
            Some(ip) if self.allowed.contains(&ip) => Ok(request),
            Some(ip) => {
                warn!(%ip, "rejecting gRPC request from IP not in node_ips");
                Err(Status::permission_denied(REQUEST_DENIED))
            }
            None => {
                warn!("rejecting gRPC request: caller address is unavailable");
                Err(Status::permission_denied(REQUEST_DENIED))
            }
        }
    }
}

/// Canonicalizes IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4 so a v4 `node_ips`
/// entry matches a dual-stack listener's mapped peer address.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Peer IP for allowlist checks, covering plain, tonic mTLS, and tonic-tls PSK.
fn remote_ip_from_request<T>(request: &Request<T>) -> Option<IpAddr> {
    if let Some(addr) = request.remote_addr() {
        return Some(canonical_ip(addr.ip()));
    }
    request
        .extensions()
        .get::<tonic_tls::openssl::SslConnectInfo<TcpConnectInfo>>()
        .and_then(|info| info.get_ref().remote_addr())
        .map(|addr| canonical_ip(addr.ip()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tonic::Code;

    fn interceptor(ips: &[&str]) -> NodeAllowlistInterceptor {
        let node_ips: Vec<String> = ips.iter().map(|s| (*s).to_string()).collect();
        NodeAllowlistInterceptor::from_node_ips(&node_ips).unwrap()
    }

    fn request_from(remote: Option<SocketAddr>) -> Request<()> {
        let mut request = Request::new(());
        request.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: remote,
        });
        request
    }

    fn call(
        interceptor: &mut NodeAllowlistInterceptor,
        remote: Option<SocketAddr>,
    ) -> Result<Request<()>, Status> {
        interceptor.call(request_from(remote))
    }

    #[test]
    fn from_node_ips_rejects_invalid_entry() {
        let err = NodeAllowlistInterceptor::from_node_ips(&["not-an-ip".to_string()]).unwrap_err();
        assert!(err.contains("invalid IP in node_ips"));
    }

    #[test]
    fn allows_listed_ipv4() {
        let mut auth = interceptor(&["10.0.0.1", "10.0.0.2"]);
        assert!(call(&mut auth, Some("10.0.0.2:40000".parse().unwrap())).is_ok());
    }

    #[test]
    fn denies_unlisted_ipv4() {
        let mut auth = interceptor(&["10.0.0.1", "10.0.0.2"]);
        let status = call(&mut auth, Some("10.0.0.99:40000".parse().unwrap())).unwrap_err();
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(status.message(), REQUEST_DENIED);
        assert!(!status.message().contains("10.0.0.99"));
    }

    #[test]
    fn allows_ipv6_regardless_of_textual_spelling() {
        let mut auth = interceptor(&["2001:0db8:0000:0000:0000:0000:0000:0001"]);
        assert!(call(&mut auth, Some("[2001:db8::1]:50051".parse().unwrap())).is_ok());
    }

    #[test]
    fn allows_ipv4_mapped_peer_matching_v4_node_ip() {
        let mut auth = interceptor(&["10.0.0.5"]);
        let mapped: SocketAddr = "[::ffff:10.0.0.5]:50051".parse().unwrap();
        assert!(call(&mut auth, Some(mapped)).is_ok());
    }

    #[test]
    fn denies_when_peer_address_is_missing() {
        let mut auth = interceptor(&["10.0.0.1"]);
        let status = call(&mut auth, None).unwrap_err();
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(status.message(), REQUEST_DENIED);
    }

    #[test]
    fn denies_when_connect_info_extension_is_absent() {
        let mut auth = interceptor(&["10.0.0.1"]);
        let status = auth.call(Request::new(())).unwrap_err();
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(status.message(), REQUEST_DENIED);
    }
}
