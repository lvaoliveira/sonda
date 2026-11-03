//! A GitHub App, which decorates pull requests (ADR-0021): a check run with
//! annotations, and one summary comment edited in place. The App's key is
//! configured like the server's other secrets and never stored; installation
//! tokens live in memory only, and neither is ever logged.
//!
//! Blocking (`ureq`): call it from `spawn_blocking`.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// GitHub's API, unless SONDA_GITHUB_API_URL names an Enterprise Server's.
pub const DEFAULT_API_URL: &str = "https://api.github.com";

/// Answers are small JSON; this bounds a hostile or broken one.
const MAX_ANSWER_BYTES: u64 = 4 << 20;

/// Comments read to find sonda's own: 10 pages of 100.
const MAX_COMMENT_PAGES: usize = 10;

pub struct App {
    id: String,
    key: RsaKeyPair,
    api: String,
    agent: ureq::Agent,
    /// Installation tokens by repository, with when they expire.
    tokens: Mutex<HashMap<String, (String, SystemTime)>>,
}

impl std::fmt::Debug for App {
    // Never the key or tokens.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App")
            .field("id", &self.id)
            .field("api", &self.api)
            .finish_non_exhaustive()
    }
}

/// A PEM private key: PKCS#1 (`BEGIN RSA PRIVATE KEY`, what GitHub
/// downloads) or PKCS#8 (`BEGIN PRIVATE KEY`).
fn parse_key(pem: &str) -> Result<RsaKeyPair> {
    let pkcs1 = pem.contains("BEGIN RSA PRIVATE KEY");
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    let der = STANDARD
        .decode(body)
        .context("the GitHub App's private key is not PEM")?;
    let key = if pkcs1 {
        RsaKeyPair::from_der(&der)
    } else {
        RsaKeyPair::from_pkcs8(&der)
    };
    key.map_err(|e| anyhow::anyhow!("the GitHub App's private key is not an RSA key: {e}"))
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_global(Some(Duration::from_secs(60)))
        // A redirect would carry the token somewhere else.
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent(concat!("sonda-server/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// A request to the API, answered as JSON; an error says what GitHub
/// answered, never the credentials sent.
fn call(
    agent: &ureq::Agent,
    api: &str,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: Option<&Value>,
) -> Result<Value> {
    let url = format!("{api}{path}");
    let mut request = ureq::http::Request::builder()
        .method(method)
        .uri(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if let Some(auth) = auth {
        request = request.header("Authorization", auth);
    }
    let mut response = match body {
        Some(b) => agent.run(
            request
                .header("Content-Type", "application/json")
                .body(b.to_string())?,
        ),
        None => agent.run(request.body(())?),
    }
    .with_context(|| format!("{method} {url}"))?;
    let status = response.status();
    let mut text = String::new();
    response
        .body_mut()
        .as_reader()
        .take(MAX_ANSWER_BYTES)
        .read_to_string(&mut text)
        .with_context(|| format!("reading {method} {url}"))?;
    if !status.is_success() {
        let message = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v["message"].as_str().map(str::to_string))
            .unwrap_or_default();
        bail!("GitHub answered {status} to {method} {path}: {message}");
    }
    Ok(if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).with_context(|| format!("{method} {url}: not JSON"))?
    })
}

/// An App GitHub created from a manifest (ADR-0024).
pub struct Created {
    pub id: u64,
    pub slug: String,
    pub html_url: String,
    pub pem: String,
}

impl std::fmt::Debug for Created {
    // Never the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Created")
            .field("id", &self.id)
            .field("slug", &self.slug)
            .finish_non_exhaustive()
    }
}

/// Exchanges the code GitHub sends back after creating an App from a
/// manifest for the App and its key: once, within the hour. Needs no
/// credentials; the code is one.
pub fn convert_manifest(api: &str, code: &str) -> Result<Created> {
    if code.is_empty() || code.len() > 100 || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
        bail!("that isn't a code GitHub sends back");
    }
    let api = api.trim_end_matches('/');
    let path = format!("/app-manifests/{code}/conversions");
    let app = call(&agent(), api, "POST", &path, None, None)?;
    let text = |field: &str| {
        app[field]
            .as_str()
            .map(str::to_string)
            .with_context(|| format!("GitHub's answer has no {field}"))
    };
    Ok(Created {
        id: app["id"].as_u64().context("GitHub's answer has no id")?,
        slug: text("slug")?,
        html_url: text("html_url")?,
        pem: text("pem")?,
    })
}

/// GitHub's web pages, for its API: `github.com` for `api.github.com`,
/// and `https://HOST` for an Enterprise Server's `https://HOST/api/v3`.
pub fn web_url(api: &str) -> String {
    let api = api.trim_end_matches('/');
    if let Some(host) = api.strip_prefix("https://api.") {
        return format!("https://{host}");
    }
    api.strip_suffix("/api/v3").unwrap_or(api).to_string()
}

impl App {
    pub fn new(id: String, private_key_pem: &str, api: String) -> Result<Self> {
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
            bail!("SONDA_GITHUB_APP_ID must be the App's numeric id");
        }
        Ok(Self {
            id,
            key: parse_key(private_key_pem)?,
            api: api.trim_end_matches('/').to_string(),
            agent: agent(),
            tokens: Mutex::new(HashMap::new()),
        })
    }

    /// The App's JWT: valid for nine minutes, from a minute ago for clock
    /// skew, as GitHub recommends.
    pub fn jwt(&self, now: u64) -> Result<String> {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD
            .encode(json!({"iat": now - 60, "exp": now + 540, "iss": self.id}).to_string());
        let message = format!("{header}.{claims}");
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message.as_bytes(),
                &mut signature,
            )
            .map_err(|_| anyhow::anyhow!("signing the GitHub App's JWT failed"))?;
        Ok(format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    /// The App's numeric id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The API it calls.
    pub fn api(&self) -> &str {
        &self.api
    }

    /// The App's public key, DER, to check its JWTs in tests.
    pub fn public_key(&self) -> Vec<u8> {
        self.key.public().as_ref().to_vec()
    }

    fn call(&self, method: &str, path: &str, auth: &str, body: Option<&Value>) -> Result<Value> {
        call(&self.agent, &self.api, method, path, Some(auth), body)
    }

    /// A token for the App's installation on `repository` (`owner/name`),
    /// limited to it, reused until five minutes before it expires.
    fn token(&self, repository: &str) -> Result<String> {
        let now = SystemTime::now();
        if let Some((token, expires)) = self.tokens.lock().unwrap().get(repository)
            && *expires > now + Duration::from_secs(300)
        {
            return Ok(token.clone());
        }
        let secs = now.duration_since(UNIX_EPOCH)?.as_secs();
        let jwt = format!("Bearer {}", self.jwt(secs)?);
        let installation = self
            .call(
                "GET",
                &format!("/repos/{repository}/installation"),
                &jwt,
                None,
            )
            .with_context(|| {
                format!("finding the App's installation on {repository} (is it installed there?)")
            })?;
        let id = installation["id"]
            .as_u64()
            .context("GitHub's installation has no id")?;
        let name = repository.split_once('/').map_or(repository, |(_, n)| n);
        let answer = self.call(
            "POST",
            &format!("/app/installations/{id}/access_tokens"),
            &jwt,
            Some(&json!({"repositories": [name]})),
        )?;
        let token = answer["token"]
            .as_str()
            .context("GitHub's answer has no token")?
            .to_string();
        // An hour, as GitHub's tokens last; its expires_at isn't needed.
        let expires = now + Duration::from_secs(3600);
        self.tokens
            .lock()
            .unwrap()
            .insert(repository.to_string(), (token.clone(), expires));
        Ok(token)
    }

    /// Creates a check run on `repository` (its `head_sha` in `body`).
    pub fn create_check_run(&self, repository: &str, body: &Value) -> Result<()> {
        let auth = format!("Bearer {}", self.token(repository)?);
        self.call(
            "POST",
            &format!("/repos/{repository}/check-runs"),
            &auth,
            Some(body),
        )?;
        Ok(())
    }

    /// Edits the pull request's comment that contains `marker`, or adds one.
    pub fn upsert_comment(
        &self,
        repository: &str,
        number: i64,
        marker: &str,
        body: &str,
    ) -> Result<()> {
        let auth = format!("Bearer {}", self.token(repository)?);
        let mut existing = None;
        for page in 1..=MAX_COMMENT_PAGES {
            let comments = self.call(
                "GET",
                &format!("/repos/{repository}/issues/{number}/comments?per_page=100&page={page}"),
                &auth,
                None,
            )?;
            let list = comments.as_array().map(Vec::as_slice).unwrap_or_default();
            existing = list
                .iter()
                .find(|c| c["body"].as_str().is_some_and(|b| b.contains(marker)))
                .and_then(|c| c["id"].as_u64());
            if existing.is_some() || list.len() < 100 {
                break;
            }
        }
        let body = json!({ "body": body });
        match existing {
            Some(id) => self.call(
                "PATCH",
                &format!("/repos/{repository}/issues/comments/{id}"),
                &auth,
                Some(&body),
            )?,
            None => self.call(
                "POST",
                &format!("/repos/{repository}/issues/{number}/comments"),
                &auth,
                Some(&body),
            )?,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_pages_are_found_from_its_api() {
        assert_eq!(web_url("https://api.github.com"), "https://github.com");
        assert_eq!(web_url("https://api.github.com/"), "https://github.com");
        assert_eq!(
            web_url("https://ghe.example.com/api/v3"),
            "https://ghe.example.com"
        );
        assert_eq!(web_url("http://127.0.0.1:4000"), "http://127.0.0.1:4000");
    }

    #[test]
    fn only_a_code_is_sent_to_be_converted() {
        for bad in ["", "../app", "a/b", "a?b=c", &"a".repeat(101)] {
            let e = convert_manifest("http://127.0.0.1:9", bad).unwrap_err();
            assert!(e.to_string().contains("isn't a code"), "{bad:?}: {e}");
        }
    }
}
