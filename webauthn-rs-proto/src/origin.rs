//! WebAuthn Origin checks.
//!
//! These are an internal implementation detail of `webauthn-rs`, and not intended to be a public
//! API.

use serde::{Deserialize, Deserializer, Serializer};
use url::{Origin, Url};

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
                    allow_subdomains_origin
                        && request_domain
                            .strip_suffix(&rp_id_domain)
                            .map(|prefix| prefix.ends_with('.'))
                            .unwrap_or(false)
                }

                (rp_id_host, request_host) => {
                    // At least one is a non-domain host, always require exact match.
                    rp_id_host == request_host
                }
            }
        }

        _ => {
            // Opaque URL which isn't equal
            false
        }
    }
}

/// Serialise a [Url]'s [Origin] for Serde.
pub(crate) fn serialize<S>(u: &Url, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let origin = u.origin();
    match origin {
        Origin::Opaque(_) => ser.serialize_str(&u.to_string()),
        Origin::Tuple(_, _, _) => ser.serialize_str(&origin.ascii_serialization()),
    }
}

/// Deserialise a [Url]'s [Origin] for Serde.
pub(crate) fn deserialize<'de, D>(deser: D) -> Result<Url, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let s = String::deserialize(deser)?;
    let u = Url::parse(&s).map_err(Error::custom)?;

    // Turn the URL back into an Origin
    let origin = u.origin();
    match origin {
        Origin::Opaque(_) => {
            // Check that this round-trips even though opaque
            if s != u.to_string() {
                return Err(Error::custom(
                    "Input contains an opaque origin which does not round-trip identically",
                ));
            }
        }

        Origin::Tuple(_, _, _) => {
            // Check that this round-trips correctly.
            let ser_origin = origin.ascii_serialization();

            // Older versions of webauthn-authenticator-rs include a trailing slash on the origin,
            // and webauthn-rs allowed case mismatches, so we explicitly allow this.
            let sol = ser_origin.len();
            let same_origin_trailing_slash =
                s.len() == sol + 1 && s[..sol] == ser_origin && s.ends_with("/");

            if ser_origin != s && !same_origin_trailing_slash {
                return Err(Error::custom(
                    "Input does not match ASCII serialisation of the origin",
                ));
            }
        }
    }

    Ok(u)
}

/// Serde serialisation helpers for `Option` origin [Url]s.
pub(crate) mod option {
    use super::*;

    /// Serialise an [Option<Url>] origin for Serde.
    pub fn serialize<S>(origin: &Option<Url>, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match origin {
            Some(origin) => super::serialize(origin, ser),
            None => ser.serialize_none(),
        }
    }

    /// Deserialise an [Option<Url>] origin for Serde.
    pub fn deserialize<'de, D>(deser: D) -> Result<Option<Url>, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::deserialize(deser).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

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
    fn test_origin_android_matches() {
        let android1 = "android:apk-key-hash-sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
        let android2 = "android:apk-key-hash-sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuXX";
        let android1_suffix = format!("{android1}=");

        for allow_subdomains_origin in [true, false] {
            for allow_any_port in [true, false] {
                assert!(origins_match(
                    allow_subdomains_origin,
                    allow_any_port,
                    &Url::parse(android1).unwrap(),
                    &Url::parse(android1).unwrap(),
                ));

                // Different package name shouldn't match
                assert!(!origins_match(
                    allow_subdomains_origin,
                    allow_any_port,
                    &Url::parse(android1).unwrap(),
                    &Url::parse(android2).unwrap(),
                ));

                // Prefixes and suffixes shouldn't match for opaque URLs
                assert!(!origins_match(
                    allow_subdomains_origin,
                    allow_any_port,
                    &Url::parse(android1).unwrap(),
                    &Url::parse(&android1_suffix).unwrap(),
                ));

                assert!(!origins_match(
                    allow_subdomains_origin,
                    allow_any_port,
                    &Url::parse(&android1_suffix).unwrap(),
                    &Url::parse(android1).unwrap(),
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

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Origin(#[serde(with = "crate::origin")] Url);

    /// Verify serialisation round-trips.
    macro_rules! origin_serialisation_roundtrip {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, expected): (Url, &str) = $value;
                let input = Origin(input);
                let expected = format!("\"{expected}\"");
                let actual: String = serde_json::to_string(&input)
                    .expect("serialisation error");
                assert_eq!(actual, expected);

                let output: Origin = serde_json::from_str(&expected)
                    .expect("deserialising expected JSON");
                assert_eq!(input, output, "deserialised input data");

                // Can the serialised form be deserialised again into the same value?
                let output: Origin = serde_json::from_str(&actual)
                    .expect("deserialising actual JSON");
                assert_eq!(input, output, "deserialised roundtripped data");
            }
        )*
        }
    }

    /// Verify serialisation round-trips.
    macro_rules! origin_serialisation_normalise {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, expected, normalised): (Url, &str, &str) = $value;
                let input = Origin(input);
                let expected = format!("\"{expected}\"");
                let normalised = format!("\"{normalised}\"");

                let output: Origin = serde_json::from_str(&expected)
                    .expect("deserialising expected JSON");
                assert_eq!(input, output, "deserialised input data");

                // Can the deserialised form be serialised again into the same value?
                let actual: String = serde_json::to_string(&input)
                    .expect("serialisation error");
                assert_ne!(expected, actual, "Re-serialising the value should normalise it");
                assert_eq!(normalised, actual, "Normalised form should match");

                let output: Origin = serde_json::from_str(&actual)
                    .expect("deserialising actual JSON");
                assert_eq!(input, output, "deserialised roundtripped data");
            }
        )*
        }
    }

    /// Checks for invalid origins.
    macro_rules! origin_deserialisation_errors {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let input: &str = $value;
                let input = format!("\"{input}\"");
                serde_json::from_str::<Origin>(&input).expect_err("expected error");
            }
        )*
        }
    }

    origin_serialisation_roundtrip! {
        http_example: (Url::parse("http://example.com").unwrap(), "http://example.com"),
        http_example_port: (Url::parse("http://example.com:443").unwrap(), "http://example.com:443"),
        https_example: (Url::parse("https://example.com").unwrap(), "https://example.com"),
        https_example_port: (Url::parse("https://example.com:80").unwrap(), "https://example.com:80"),
        ios_bundle: (Url::parse("ios:bundle-id:com.foo.bar").unwrap(), "ios:bundle-id:com.foo.bar"),
        android_sha256: (
            Url::parse("android:apk-key-hash-sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU").unwrap(),
            "android:apk-key-hash-sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        ),
    }

    origin_serialisation_normalise! {
        http_trailing_slash: (
            Url::parse("http://example.com").unwrap(),
            "http://example.com/",
            "http://example.com"
        ),
        https_trailing_slash: (
            Url::parse("https://example.com").unwrap(),
            "https://example.com/",
            "https://example.com"
        ),
    }

    origin_deserialisation_errors! {
        http_default_port: "http://example.com:80",
        https_default_port: "https://example.com:443",

        http_caps: "HTTP://EXAMPLE.COM",
        https_caps: "HTTPS://EXAMPLE.COM",

        http_two_slashes: "http://example.com//",
        https_two_slashes: "https://example.com//",

        http_dot_slash: "http://example.com/./",
        https_dot_slash: "https://example.com/./",

        http_path: "http://example.com/example/",
        https_path: "https://example.com/example/",
    }
}
