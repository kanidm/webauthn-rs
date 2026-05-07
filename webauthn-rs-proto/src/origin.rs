//! WebAuthn Origin checks
use url::Url;

/// Check if a `request_origin` is an allowed suffix of `allowed_origin`.
///
/// If either `request_origin` or `allowed_origin` are opaque URLs, they must exactly match.
///
/// ### Arguments
///
/// * `allow_subdomains_origin`: if `true`, `request_origin` may be a subdomain of
///   `allowed_origin`.
///
///   **Note:** this *does not* verify whether `allowed_origin` (or a parent of it) is a valid
///   registerable domain.
///
/// * `allow_any_port`: if `true`, `request_origin` may be a different port to `allowed_origin`. The
///   URLs' schemes must still match.
///
/// ### References
///
/// * [HTML Standard §7.1.1.2, registerable domain suffix][0]
///
/// [0]: https://html.spec.whatwg.org/multipage/browsers.html#is-a-registrable-domain-suffix-of-or-is-equal-to
pub fn origins_match(
    allow_subdomains_origin: bool,
    allow_any_port: bool,
    request_origin: &Url,
    allowed_origin: &Url,
) -> bool {
    if allowed_origin == request_origin {
        // Exact URL match
        return true;
    }

    if allowed_origin.scheme() != request_origin.scheme() {
        // Full URL scheme mismatch
        return false;
    }

    // Check the Origin
    match (allowed_origin.origin(), request_origin.origin()) {
        (
            url::Origin::Tuple(rp_id_scheme, rp_id_host, rp_id_port),
            url::Origin::Tuple(request_scheme, request_host, request_port),
        ) => {
            if rp_id_scheme != request_scheme {
                // Origin scheme mismatch
                return false;
            }

            if !allow_any_port && rp_id_port != request_port {
                // Port mismatch
                return false;
            }

            match (rp_id_host, request_host) {
                // Both hosts are a domain
                (url::Host::Domain(rp_id_domain), url::Host::Domain(request_domain)) => {
                    if rp_id_domain == request_domain {
                        // Domains exactly match
                        return true;
                    }

                    // Ensure "badexample.com" doesn't match "example.com", but
                    // "sub.example.com" does.
                    return allow_subdomains_origin
                        && request_domain
                            .strip_suffix(&rp_id_domain)
                            .map(|prefix| prefix.ends_with('.'))
                            .unwrap_or(false);
                }

                (rp_id_host, request_host) => {
                    // At least one is a non-domain host, always require exact match.
                    return rp_id_host == request_host;
                }
            }
        }

        _ => {
            // Opaque URL which isn't equal
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test `origins_match` with simple case.
    #[test]
    fn test_origins_match_exact() {
        let request_origin = url::Url::parse("https://example.com").unwrap();
        let allowed_origin = url::Url::parse("https://example.com").unwrap();

        assert!(origins_match(
            /* subdomains */ true,
            /* any port */ true,
            &request_origin,
            &allowed_origin,
        ));

        assert!(origins_match(
            /* subdomains */ false,
            /* any port */ true,
            &request_origin,
            &allowed_origin,
        ));

        assert!(origins_match(
            /* subdomains */ true,
            /* any port */ false,
            &request_origin,
            &allowed_origin,
        ));

        assert!(origins_match(
            /* subdomains */ false,
            /* any port */ false,
            &request_origin,
            &allowed_origin,
        ));
    }

    /// Test `origins_match` with scheme changes, which should never match.
    #[test]
    fn test_origins_match_scheme() {
        let http_url = url::Url::parse("http://example.com").unwrap();
        let https_url = url::Url::parse("https://example.com").unwrap();
        let ws_url = url::Url::parse("ws://example.com").unwrap();
        let wss_url = url::Url::parse("wss://example.com").unwrap();

        for allow_subdomains_origin in [true, false] {
            for allow_any_port in [true, false] {
                for request_origin in [&http_url, &ws_url, &wss_url] {
                    assert!(
                        !origins_match(
                            allow_subdomains_origin,
                            allow_any_port,
                            request_origin,
                            &https_url,
                        ),
                        "expected {https_url} to not match {request_origin}",
                    );
                }

                for request_origin in [&https_url, &ws_url, &wss_url] {
                    assert!(
                        !origins_match(
                            allow_subdomains_origin,
                            allow_any_port,
                            request_origin,
                            &http_url,
                        ),
                        "expected {http_url} to not match {request_origin}",
                    );
                }

                for request_origin in [&http_url, &https_url, &wss_url] {
                    assert!(
                        !origins_match(
                            allow_subdomains_origin,
                            allow_any_port,
                            request_origin,
                            &ws_url,
                        ),
                        "expected {ws_url} to not match {request_origin}",
                    );
                }

                for request_origin in [&http_url, &https_url, &ws_url] {
                    assert!(
                        !origins_match(
                            allow_subdomains_origin,
                            allow_any_port,
                            request_origin,
                            &wss_url,
                        ),
                        "expected {wss_url} to not match {request_origin}",
                    );
                }
            }
        }
    }

    /// Test `origins_match` with different ports on `localhost`
    #[test]
    fn test_origins_match_localhost_port() {
        let request_origin = url::Url::parse("http://localhost:8000").unwrap();
        let allowed_origin = url::Url::parse("http://localhost:3000").unwrap();

        assert!(origins_match(
            /* subdomains */ true,
            /* any port */ true,
            &request_origin,
            &allowed_origin,
        ));

        assert!(origins_match(
            /* subdomains */ false,
            /* any port */ true,
            &request_origin,
            &allowed_origin,
        ));

        // Differing ports should fail
        assert!(!origins_match(
            /* subdomains */ true,
            /* any port */ false,
            &request_origin,
            &allowed_origin,
        ));

        assert!(!origins_match(
            /* subdomains */ false,
            /* any port */ false,
            &request_origin,
            &allowed_origin,
        ));
    }

    #[test]
    fn test_origin_ios_matches() {
        for allow_subdomains_origin in [true, false] {
            for allow_any_port in [true, false] {
                assert!(origins_match(
                    allow_subdomains_origin,
                    allow_any_port,
                    &Url::parse("ios:bundle-id:com.foo.bar").unwrap(),
                    &Url::parse("ios:bundle-id:com.foo.bar").unwrap(),
                ));

                // Different package name shouldn't match
                assert!(!origins_match(
                    allow_subdomains_origin,
                    allow_any_port,
                    &Url::parse("ios:bundle-id:com.foo.bar").unwrap(),
                    &Url::parse("ios:bundle-id:com.foo.baz").unwrap(),
                ));

                // Prefixes and suffixes shouldn't match for opaque URLs
                assert!(!origins_match(
                    allow_subdomains_origin,
                    allow_any_port,
                    &Url::parse("ios:bundle-id:com.foo.bar").unwrap(),
                    &Url::parse("ios:bundle-id:com.foo.bar.other").unwrap(),
                ));

                assert!(!origins_match(
                    allow_subdomains_origin,
                    allow_any_port,
                    &Url::parse("ios:bundle-id:com.foo.bar.other").unwrap(),
                    &Url::parse("ios:bundle-id:com.foo.bar").unwrap(),
                ));
            }
        }
    }

    #[test]
    fn test_origin_subdomain_suffix_boundary() {
        let allowed_origin = Url::parse("https://example.com").unwrap();

        // Should always be allowed
        let allowed_urls: [Url; 4] = [
            allowed_origin.clone(),
            Url::parse("https://example.com/hello").unwrap(),
            Url::parse("https://user@example.com").unwrap(),
            Url::parse("https://user@example.com/hello").unwrap(),
        ];

        // Should only be allowed when subdomains are allowed
        let allowed_subdomains: [Url; 2] = [
            Url::parse("https://sub.example.com").unwrap(),
            Url::parse("https://deep.subdomain.example.com").unwrap(),
        ];

        let denied_urls: [Url; 4] = [
            // Parent domain
            Url::parse("https://com").unwrap(),
            // Different TLD
            Url::parse("https://example.net").unwrap(),
            // Prefixed string
            Url::parse("https://otherexample.com").unwrap(),
            Url::parse("https://other-example.com").unwrap(),
        ];

        for request_origin in &allowed_urls {
            for allow_subdomains_origin in [true, false] {
                for allow_any_port in [true, false] {
                    assert!(
                        origins_match(
                            allow_subdomains_origin,
                            allow_any_port,
                            request_origin,
                            &allowed_origin,
                        ),
                        "{allowed_origin} allows {request_origin}"
                    );
                }
            }
        }

        for request_origin in &allowed_subdomains {
            // Legitimate subdomain must be accepted
            assert!(
                origins_match(true, false, request_origin, &allowed_origin),
                "{allowed_origin} allows {request_origin}",
            );

            assert!(
                origins_match(true, true, request_origin, &allowed_origin),
                "{allowed_origin} allows {request_origin}",
            );

            // ...unless subdomains are disallowed
            assert!(
                !origins_match(false, false, request_origin, &allowed_origin),
                "{allowed_origin} denies {request_origin}",
            );

            assert!(
                !origins_match(false, true, request_origin, &allowed_origin),
                "{allowed_origin} denies {request_origin}",
            );
        }

        // Denied domains should never be accepted
        for request_origin in &denied_urls {
            for allow_subdomains_origin in [true, false] {
                for allow_any_port in [true, false] {
                    assert!(
                        !origins_match(
                            allow_subdomains_origin,
                            allow_any_port,
                            request_origin,
                            &allowed_origin,
                        ),
                        "{allowed_origin} denies {request_origin}"
                    );
                }
            }
        }
    }
}
