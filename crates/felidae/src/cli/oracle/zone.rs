//! Zone inference using the addr crate with Mozilla Public Suffix List (PSL).

use addr::parse_domain_name;
use color_eyre::eyre::Result;
use felidae_types::FQDN;

/// Infer the zone from a domain using the Mozilla Public Suffix List (PSL).
///
/// The zone is the registrable domain, which is the domain minus the public suffix.
/// For example:
/// - `test.example.com` -> `example.com` (zone)
/// - `example.com` -> `com` (zone, which becomes `.com` as an FQDN)
///
/// Returns an error if the domain cannot be parsed or if no zone can be inferred.
pub fn infer_zone(domain: &FQDN) -> Result<FQDN> {
    // First we convert the FQDN to string for parsing by removing the trailing dot
    let domain_str = domain.to_string().trim_end_matches('.').to_string();

    // Parse the domain using addr crate (which integrates the PSL)
    let parsed = parse_domain_name(&domain_str)
        .map_err(|e| color_eyre::eyre::eyre!("failed to parse domain {}: {}", domain_str, e))?;

    // Get the TLD (suffix)
    let tld = parsed.suffix();

    // Get the root (registrable domain)
    let root = parsed
        .root()
        .ok_or_else(|| color_eyre::eyre::eyre!("no root domain found for {}", domain_str))?;

    // Determine the zone:
    // - If the domain is the root itself (ie this is not a subdomain), we return just the TLD
    // - If the domain is a subdomain, we return the root (registrable domain)
    let zone_str = if domain_str == root {
        // The domain itself is the registrable domain (e.g., "example.com")
        // so we return just the TLD (e.g., "com")
        tld.to_string()
    } else {
        // The domain is a subdomain (e.g., "test.example.com")
        // so we return the root (registrable domain) (e.g., "example.com")
        root.to_string()
    };

    // Convert to FQDN format (ensure it ends with a dot)
    let fqdn_str = if zone_str.ends_with('.') {
        zone_str
    } else {
        format!("{}.", zone_str)
    };

    fqdn_str
        .parse::<FQDN>()
        .map_err(|e| color_eyre::eyre::eyre!("failed to parse zone as FQDN {}: {}", fqdn_str, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subdomain_infers_registrable_domain() {
        let domain: FQDN = "test.example.com.".parse().unwrap();
        let zone = infer_zone(&domain).unwrap();
        assert_eq!(zone.to_string(), "example.com.");
    }

    #[test]
    fn test_domain_infers_tld() {
        let domain: FQDN = "example.com.".parse().unwrap();
        let zone = infer_zone(&domain).unwrap();
        assert_eq!(zone.to_string(), "com.");
    }

    #[test]
    fn test_multiple_subdomains() {
        let domain: FQDN = "sub.test.example.com.".parse().unwrap();
        let zone = infer_zone(&domain).unwrap();
        assert_eq!(zone.to_string(), "example.com.");
    }

    #[test]
    fn test_uk_domain() {
        let domain: FQDN = "example.co.uk.".parse().unwrap();
        let zone = infer_zone(&domain).unwrap();
        assert_eq!(zone.to_string(), "co.uk.");
    }

    #[test]
    fn test_uk_subdomain() {
        let domain: FQDN = "test.example.co.uk.".parse().unwrap();
        let zone = infer_zone(&domain).unwrap();
        assert_eq!(zone.to_string(), "example.co.uk.");
    }

    #[test]
    fn test_au_domain() {
        let domain: FQDN = "example.com.au.".parse().unwrap();
        let zone = infer_zone(&domain).unwrap();
        assert_eq!(zone.to_string(), "com.au.");
    }

    #[test]
    fn test_au_subdomain() {
        let domain: FQDN = "test.example.com.au.".parse().unwrap();
        let zone = infer_zone(&domain).unwrap();
        assert_eq!(zone.to_string(), "example.com.au.");
    }

    #[test]
    fn test_nym_site_com() {
        let domain: FQDN = "element.nym.re.".parse().unwrap();
        let zone = infer_zone(&domain).unwrap();
        assert_eq!(zone.to_string(), "nym.re.");
    }
}
