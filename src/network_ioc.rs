//! Contains patterns to match network indicators in the input text.
//!
//! This module can be used to extract single network ioc types
//! from text, using specific methods, or extract all network
//! IOC types using `parse_network_iocs`.
//!
//! # Examples
//!
//! ## Extract all network IOCs from the input text.
//! ```
//! use ripioc::network_ioc::parse_network_iocs;
//!
//! let all_network_iocs = parse_network_iocs("The exploit used\
//!                     http://www.test.com as C2.");
//! ```
//!
//! ### Extract just the URL pattern
//! ```
//! use ripioc::network_ioc::parse_urls;
//!
//! let all_urls = parse_urls("Traffic was set to http://www.test.com ");
//! ```
#[cfg(feature = "serde_support")]
use serde::Serialize;

use regex::Regex;
use regex::RegexSet;
use regex::RegexSetBuilder;

use std::boxed::Box;

use crate::regex_builder::compile_re;

/// Different types of network types of IOC.
#[cfg_attr(feature = "serde_support", derive(Serialize))]
#[derive(Debug, PartialEq, Eq)]
pub enum NetworkIOC<'a> {
    /// URL type network ioc
    URL(&'a str),
    /// Domain type network ioc.
    DOMAIN(&'a str),
    /// Email type network ioc.
    EMAIL(&'a str),
    /// IPV4 type network ioc.
    IPV4(&'a str),
    /// IPv6 type network ioc.
    IPV6(&'a str),
    /// Hex encoded URL type network ioc.
    HexURL(&'a str),
}

/// A collection of network IOC, partioned network ioc type.
#[cfg_attr(feature = "serde_support", derive(Serialize))]
#[derive(Debug, PartialEq, Eq)]
pub struct NetworkIOCS<'a> {
    /// URL IOCs, found in the text.
    pub urls: Vec<NetworkIOC<'a>>,
    /// Domain IOCs, found in the text.
    pub domains: Vec<NetworkIOC<'a>>,
    /// Email IOCs, found in the text.
    pub emails: Vec<NetworkIOC<'a>>,
    /// IPV4 IOCs, found in the text.
    pub ipv4s: Vec<NetworkIOC<'a>>,
    /// IPv6 IOCs, found in the text.
    pub ipv6s: Vec<NetworkIOC<'a>>,
    /// HexURL IOCs, found in the text.
    pub hexurls: Vec<NetworkIOC<'a>>,
}

const URL_PATTERN: &str =
    r#"(?i)\b((http|https|ftp|sftp)://(www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(/[^\s"<]*)?\b"#;

const DOMAIN_PATTERN: &str = r#"(?i)  # Case-insensitive
    @?                                # Capture the preceding @ for further filtering
    (?:[a-z0-9-]+\.)*                 # Optional subdomains (e.g., sub.example.com)
    [a-z0-9-]+                        # Second-level domain (e.g., example)
    \.[a-z0-9-]{2,63}\b               # TLD (supports alphabetic and numeric, e.g., .com, .xn--p1ai)
"#;

const EMAIL_PATTERN: &str = r#"[A-Za-z0-9_.]+@[0-9a-z.-]+"#;

const IPV4_PATTERN: &str =
    r#"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"#;

const IPV6_PATTERN: &str = r#"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|
                             ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}
                             (:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:
                             ((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]
                                 |1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]
                                     |1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"#;

const HEX_URL_PATTERN: &str = r#"
                                            (
                                                [46][86]
                                                (?:[57]4)?
                                                [57]4[57]0
                                                (?:[57]3)?
                                                3a2f2f
                                                (?:2[356def]|3[0-9adf]|[46][0-9a-f]|[57][0-9af])+
                                            )
                                            (?:[046]0|2[0-2489a-c]|3[bce]|[57][b-e]|[8-f][0-9a-f]|0a|0d|09|[
                                                \x5b-\x5d\x7b\x7d\x0a\x0d\x20
                                            ]|$)
                                        "#;

/// Parse all network types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// A [`NetworkIOCs`](struct.NetworkIOCs.html) struct containing
/// all the network iocs found in the input text.
pub fn parse_network_iocs(input: &str) -> NetworkIOCS {
    lazy_static! {
        static ref NETWORK_IOCS_RE: RegexSet = RegexSetBuilder::new(
            vec![
                URL_PATTERN,       //0
                EMAIL_PATTERN,     //1
                DOMAIN_PATTERN,    //2
                IPV6_PATTERN,      //3
                IPV4_PATTERN,      //4
                HEX_URL_PATTERN    //5
        ]
        )
        .case_insensitive(true)
        .ignore_whitespace(true)
        .build().unwrap();
    }
    let matches = NETWORK_IOCS_RE.matches(input);
    NetworkIOCS {
        urls: if matches.matched(0) {
            parse_urls(input)
        } else {
            vec![]
        },
        emails: if matches.matched(1) {
            parse_emails(input)
        } else {
            vec![]
        },
        domains: if matches.matched(2) {
            parse_domains(input)
        } else {
            vec![]
        },
        ipv6s: if matches.matched(3) {
            parse_ipv6(input)
        } else {
            vec![]
        },
        ipv4s: if matches.matched(4) {
            parse_ipv4(input)
        } else {
            vec![]
        },
        hexurls: if matches.matched(5) {
            parse_hex_url(input)
        } else {
            vec![]
        },
    }
}

/// Parse all hex encoded URLs types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of hex encoded URLs IOCs found in the input text.
pub fn parse_hex_url(input: &str) -> Vec<NetworkIOC> {
    lazy_static! {
        static ref HEX_URL_RE: Box<Regex> = compile_re(HEX_URL_PATTERN);
    }
    HEX_URL_RE
        .find_iter(input)
        .map(|x| NetworkIOC::HexURL(x.as_str().trim_end()))
        .collect()
}

/// Parse all IPV6 types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of IPV6 IOCs found in the input text.
pub fn parse_ipv6(input: &str) -> Vec<NetworkIOC> {
    lazy_static! {
        static ref IPV6_RE: Box<Regex> = compile_re(IPV6_PATTERN);
    }
    IPV6_RE
        .find_iter(input)
        .map(|x| NetworkIOC::IPV6(x.as_str()))
        .collect()
}

/// Parse all IPV4 encoded URLs types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of IPV4 IOCs found in the input text.
pub fn parse_ipv4(input: &str) -> Vec<NetworkIOC> {
    lazy_static! {
        static ref IPV4_RE: Box<Regex> = compile_re(IPV4_PATTERN);
    }
    IPV4_RE
        .find_iter(input)
        .map(|x| NetworkIOC::IPV4(x.as_str()))
        .collect()
}

/// Parse all URLs types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of URLs IOCs found in the input text.
pub fn parse_urls(input: &str) -> Vec<NetworkIOC> {
    lazy_static! {
        static ref URL_RE: Box<Regex> = compile_re(URL_PATTERN);
    }
    URL_RE
        .find_iter(input)
        .map(|x| NetworkIOC::URL(x.as_str()))
        .collect()
}

/// Parse all domains types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of domains IOCs found in the input text.
pub fn parse_domains(input: &str) -> Vec<NetworkIOC> {
    lazy_static! {
        static ref DOMAIN_RE: Box<Regex> = compile_re(DOMAIN_PATTERN);
    }
    DOMAIN_RE
        .find_iter(input)
        .filter(|x| !x.as_str().starts_with("@"))
        .map(|x| NetworkIOC::DOMAIN(x.as_str()))
        .collect()
}

/// Parse all email types found in the input text.
/// # Arguments
/// * `input` - input text to parse
/// # Return
/// a vector of email IOCs found in the input text.
pub fn parse_emails(input: &str) -> Vec<NetworkIOC> {
    lazy_static! {
        static ref EMAIL_RE: Box<Regex> = compile_re(EMAIL_PATTERN);
    }
    EMAIL_RE
        .find_iter(input)
        .map(|x| NetworkIOC::EMAIL(x.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parase_ipv6() {
        assert_eq!(
            parse_ipv6("this has a ipv6 address 2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            vec![NetworkIOC::IPV6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")]
        )
    }

    #[test]
    fn test_parse_valid_domains() {
        assert_eq!(
            parse_domains("this has a www.test.com"),
            vec![NetworkIOC::DOMAIN("www.test.com")]
        );
        assert_eq!(
            parse_domains("visit example.co.uk now"),
            vec![NetworkIOC::DOMAIN("example.co.uk")]
        );
    }

    #[test]
    fn test_parse_invalid_domains() {
        assert_eq!(parse_domains("this is not a domain"), vec![]);
        assert_eq!(parse_domains("email me at user@example.com"), vec![]);
    }

    #[test]
    fn test_parse_urls() {
        assert_eq!(
            parse_urls("this has a http://www.test.com"),
            vec![NetworkIOC::URL("http://www.test.com")]
        );
    }

    #[test]
    fn test_parse_emails() {
        assert_eq!(
            parse_emails("this has an email test@test.com"),
            vec![NetworkIOC::EMAIL("test@test.com")]
        );
    }

    #[test]
    fn test_parse_ipv4() {
        assert_eq!(
            parse_ipv4("this has an ipv4 127.0.0.1"),
            vec![NetworkIOC::IPV4("127.0.0.1")]
        );
    }

    #[test]
    fn test_parse_hex_url() {
        assert_eq!(
            parse_hex_url("this has an hex encoded url 687474703A2F2F7777772E726970696F632E636F63"),
            vec![NetworkIOC::HexURL(
                "687474703A2F2F7777772E726970696F632E636F63"
            )]
        );
    }

    #[test]
    fn test_parse_network_iocs() {
        let results = parse_network_iocs(
            "
        127.0.0.1 www.test.com
        http://www.ripioc.com/url
        some_ioc@iocrip.com
        2001:0db8:85a3:0000:0000:8a2e:0370:7334
        687474703A2F2F7777772E726970696F632E636F63 some other text
        ",
        );
        assert_eq!(
            results,
            NetworkIOCS {
                urls: vec![NetworkIOC::URL("http://www.ripioc.com/url")],
                domains: vec![
                    NetworkIOC::DOMAIN("www.test.com"),
                    NetworkIOC::DOMAIN("www.ripioc.com"),
                ],
                emails: vec![NetworkIOC::EMAIL("some_ioc@iocrip.com")],
                ipv4s: vec![NetworkIOC::IPV4("127.0.0.1")],
                ipv6s: vec![NetworkIOC::IPV6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")],
                hexurls: vec![NetworkIOC::HexURL(
                    "687474703A2F2F7777772E726970696F632E636F63"
                )]
            }
        )
    }
}
