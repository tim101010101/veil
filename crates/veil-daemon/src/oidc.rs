//! Verifying the OIDC token a CI job presents.

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation,
    jwk::{Jwk, JwkSet},
};
use serde::Deserialize;
use veil_proto::TrustPolicy;

/// Everything that could go wrong, without telling the client which part failed.
#[derive(Debug)]
pub struct Rejected(pub String);

#[derive(Deserialize)]
struct Discovery {
    jwks_uri: String,
}

/// Verifies a token against the trust policy.
pub fn verify(policy: &TrustPolicy, token: &str) -> Result<(), Rejected> {
    let header = jsonwebtoken::decode_header(token)
        .map_err(|error| Rejected(format!("bad header: {error}")))?;
    if header.alg != Algorithm::RS256 {
        return Err(Rejected("only RS256 is accepted".to_owned()));
    }
    let kid = header.kid.ok_or_else(|| Rejected("no key id".to_owned()))?;

    let jwks = fetch_jwks(&policy.issuer)?;
    let jwk: &Jwk = jwks
        .find(&kid)
        .ok_or_else(|| Rejected(format!("unknown key id {kid}")))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|error| Rejected(format!("bad jwk: {error}")))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[policy.issuer.as_str()]);
    validation.set_audience(&[policy.audience.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);

    let data = jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation)
        .map_err(|error| Rejected(format!("token rejected: {error}")))?;

    for (name, expected) in &policy.claims {
        let actual = data
            .claims
            .get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if actual != expected {
            return Err(Rejected(format!("claim {name} does not match")));
        }
    }
    Ok(())
}

fn fetch_jwks(issuer: &str) -> Result<JwkSet, Rejected> {
    let base = issuer.trim_end_matches('/');
    let discovery: Discovery = ureq::get(&format!("{base}/.well-known/openid-configuration"))
        .timeout(std::time::Duration::from_secs(10))
        .call()
        .map_err(|error| Rejected(format!("issuer discovery failed: {error}")))?
        .into_json()
        .map_err(|error| Rejected(format!("issuer discovery is not JSON: {error}")))?;
    ureq::get(&discovery.jwks_uri)
        .timeout(std::time::Duration::from_secs(10))
        .call()
        .map_err(|error| Rejected(format!("jwks fetch failed: {error}")))?
        .into_json()
        .map_err(|error| Rejected(format!("jwks is not JSON: {error}")))
}
