//! NoSQL injection (CWE-943) detection — MongoDB-style operator injection.
//!
//! Evidence-driven boolean differential: the parameter is rewritten as an
//! operator key in the query string — `param[$ne]=NONCE` (matches everything)
//! vs `param[$eq]=NONCE` (matches nothing, since NONCE does not exist). A
//! backend that parses the nested operators (Express/PHP → MongoDB) returns
//! materially different responses for the two; an app that treats the input as
//! a literal string returns the same. Operator tokens are stripped before
//! comparison so a mere reflection of the payload cannot false-positive.

use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use anyhow::Result;
use url::Url;

/// A confirmed NoSQL-injection vector.
#[derive(Debug, Clone)]
pub struct NoSqlVector {
    pub param: String,
    pub technique: &'static str,
    pub evidence: String,
}

/// A value that should not exist in any dataset.
const NONCE: &str = "anvilnosqli404zzz";

/// Rewrite `url` so `param` becomes the operator key `param[op]=NONCE`,
/// preserving the other query parameters.
fn with_operator(url: &Url, param: &str, op: &str) -> Url {
    let others: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != param)
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut u = url.clone();
    {
        let mut qp = u.query_pairs_mut();
        qp.clear();
        for (k, v) in &others {
            qp.append_pair(k, v);
        }
        qp.append_pair(&format!("{param}[{op}]"), NONCE);
    }
    u
}

/// Strip the operator tokens so a reflected payload doesn't drive the diff.
fn normalize(body: &str) -> String {
    body.replace("$ne", "").replace("$eq", "")
}

/// Materially different = differ after normalisation (not just by the payload).
fn differ(a: &str, b: &str) -> bool {
    normalize(a) != normalize(b)
}

/// Check a parameter for MongoDB-style operator injection.
pub async fn check_nosqli(client: &HttpClient, url: &Url, param: &str) -> Result<Option<NoSqlVector>> {
    let r_ne = client.execute(HttpRequest::get(with_operator(url, param, "$ne"))).await?;
    let r_eq = client.execute(HttpRequest::get(with_operator(url, param, "$eq"))).await?;

    if r_ne.status == r_eq.status {
        let (b_ne, b_eq) = (r_ne.body_text(), r_eq.body_text());
        if differ(&b_ne, &b_eq) {
            return Ok(Some(NoSqlVector {
                param: param.to_string(),
                technique: "MongoDB operator injection ($ne vs $eq boolean differential)",
                evidence: format!(
                    "param[$ne] and param[$eq] produced materially different responses \
                     (body lengths {} vs {}), indicating the operators were interpreted by a \
                     NoSQL backend.",
                    b_ne.len(),
                    b_eq.len()
                ),
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_key_is_built_preserving_siblings() {
        let u = Url::parse("http://h/s?q=cat&page=2").unwrap();
        let ne = with_operator(&u, "q", "$ne");
        let q = ne.query().unwrap();
        assert!(q.contains("page=2"), "sibling lost: {q}");
        // q[$ne]=NONCE, percent-encoded
        assert!(q.contains("q%5B%24ne%5D=") || q.contains("q[$ne]="), "no operator key: {q}");
        assert!(!q.contains("q=cat"), "original value not replaced: {q}");
    }

    #[test]
    fn reflection_only_difference_is_ignored() {
        // Two bodies differing solely by the operator token must not count.
        assert!(!differ("you searched for $ne", "you searched for $eq"));
    }

    #[test]
    fn real_data_difference_counts() {
        assert!(differ("results: 42 records", "results: 0 records"));
    }
}
