//! Server configuration. Secrets come from environment variables or files
//! (`*_FILE`, for Docker secrets), never from command-line flags, which
//! other users can read in `ps`.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgConnectOptions;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use subtle::ConstantTimeEq;

/// A token shorter than this is too guessable for a server on a network.
pub const MIN_TOKEN_LEN: usize = 32;

pub struct Config {
    pub listen: SocketAddr,
    pub database: PgConnectOptions,
    /// The shared `SONDA_TOKEN`, optional since users have their own
    /// tokens (ADR-0012).
    pub token: Option<Token>,
    /// The built web app (`web/dist`), served for every non-API path.
    pub web_dir: Option<PathBuf>,
    /// Username and password for the first admin, used only while no users
    /// exist (ADR-0006).
    pub admin: Option<(String, String)>,
    /// Where to sync advisories from daily, when SONDA_ADVISORY_SYNC=true
    /// (ADR-0009); `None` keeps the server from connecting out.
    pub advisory_sync: Option<String>,
    /// Where to serve `GET /metrics` (ADR-0019); `None`, the default, serves
    /// no metrics. Never the API's address: metrics are unauthenticated.
    pub metrics_listen: Option<SocketAddr>,
    /// The GitHub App that decorates pull requests (ADR-0021); `None` keeps
    /// the server from calling GitHub.
    pub github: Option<crate::github::App>,
    /// The server's address as people reach it (SONDA_PUBLIC_URL), for
    /// links in pull request decorations; `None` leaves them out.
    pub public_url: Option<String>,
    /// SONDA_PLAIN_HTTP: sign-in over plain HTTP on a trusted network, with
    /// a session cookie that isn't `Secure`. Off by default.
    pub plain_http: bool,
}

/// The API token, kept only as a hash.
pub struct Token([u8; 32]);

impl Token {
    pub fn new(token: &str) -> Result<Self> {
        if token.len() < MIN_TOKEN_LEN || token.chars().any(|c| c.is_control() || c == ' ') {
            bail!(
                "the API token must be at least {MIN_TOKEN_LEN} characters, without \
                 spaces or control characters (generate one with `openssl rand -hex 32`)"
            );
        }
        Ok(Self(Sha256::digest(token).into()))
    }

    /// Compares hashes in constant time, so response timing reveals nothing
    /// about the token, not even its length.
    pub fn matches(&self, presented: &str) -> bool {
        let presented: [u8; 32] = Sha256::digest(presented).into();
        self.0.ct_eq(&presented).into()
    }
}

/// Where configuration values come from; `std::env::var` in production.
pub trait Env {
    fn var(&self, name: &str) -> Option<String>;
}

pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

impl Config {
    pub fn load(listen: SocketAddr, web_dir: Option<PathBuf>, env: &dyn Env) -> Result<Self> {
        let database = database(env)?;
        let token = secret(env, "SONDA_TOKEN")?;
        let admin = match secret(env, "SONDA_ADMIN_PASSWORD")? {
            Some(password) => {
                let username = env
                    .var("SONDA_ADMIN_USERNAME")
                    .unwrap_or_else(|| "admin".into());
                crate::users::check_username(&username)
                    .map_err(|e| anyhow::anyhow!("SONDA_ADMIN_USERNAME: {e}"))?;
                crate::users::check_password(&password)
                    .map_err(|e| anyhow::anyhow!("SONDA_ADMIN_PASSWORD: {e}"))?;
                Some((username, password))
            }
            None => None,
        };
        let plain_http = plain_http(env)?;
        Ok(Self {
            listen,
            database,
            token: token.as_deref().map(Token::new).transpose()?,
            web_dir,
            admin,
            advisory_sync: advisory_sync(env)?,
            metrics_listen: None,
            github: github(env)?,
            public_url: public_url(env, plain_http)?,
            plain_http,
        })
    }
}

/// The advisory sync's base URL: off unless SONDA_ADVISORY_SYNC is `true`;
/// SONDA_ADVISORY_SYNC_URL overrides OSV's (an HTTPS mirror, say).
pub fn advisory_sync(env: &dyn Env) -> Result<Option<String>> {
    let url = || {
        let url = env
            .var("SONDA_ADVISORY_SYNC_URL")
            .unwrap_or_else(|| crate::advisory_sync::DEFAULT_BASE_URL.into());
        crate::advisory_sync::check_base_url(&url)
            .map_err(|e| anyhow::anyhow!("SONDA_ADVISORY_SYNC_URL: {e}"))
    };
    match env.var("SONDA_ADVISORY_SYNC").as_deref() {
        None | Some("" | "false") => Ok(None),
        Some("true") => url().map(Some),
        Some(other) => bail!("SONDA_ADVISORY_SYNC must be true or false, not {other:?}"),
    }
}

/// The GitHub App (ADR-0021): SONDA_GITHUB_APP_ID and its private key
/// (SONDA_GITHUB_APP_PRIVATE_KEY, or _FILE), both or neither;
/// SONDA_GITHUB_API_URL for an Enterprise Server.
pub fn github(env: &dyn Env) -> Result<Option<crate::github::App>> {
    let id = env.var("SONDA_GITHUB_APP_ID").filter(|v| !v.is_empty());
    let key = secret(env, "SONDA_GITHUB_APP_PRIVATE_KEY")?;
    let (id, key) = match (id, key) {
        (None, None) => return Ok(None),
        (Some(id), Some(key)) => (id, key),
        _ => bail!(
            "set both SONDA_GITHUB_APP_ID and SONDA_GITHUB_APP_PRIVATE_KEY (or _FILE), or neither"
        ),
    };
    let api = env
        .var("SONDA_GITHUB_API_URL")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| crate::github::DEFAULT_API_URL.into());
    let api = crate::advisory_sync::check_base_url(&api)
        .map_err(|e| anyhow::anyhow!("SONDA_GITHUB_API_URL: {e}"))?;
    crate::github::App::new(id, &key, api).map(Some)
}

/// SONDA_PUBLIC_URL, such as `https://sonda.example.com`; `http://` to
/// anywhere only with SONDA_PLAIN_HTTP.
pub fn public_url(env: &dyn Env, plain_http: bool) -> Result<Option<String>> {
    env.var("SONDA_PUBLIC_URL")
        .filter(|v| !v.is_empty())
        .map(|url| {
            if plain_http && url.starts_with("http://") {
                return Ok(url.trim_end_matches('/').to_string());
            }
            crate::advisory_sync::check_base_url(&url)
                .map_err(|e| anyhow::anyhow!("SONDA_PUBLIC_URL: {e}"))
        })
        .transpose()
}

/// SONDA_PLAIN_HTTP: `true`, or off.
pub fn plain_http(env: &dyn Env) -> Result<bool> {
    match env.var("SONDA_PLAIN_HTTP").as_deref() {
        None | Some("" | "false") => Ok(false),
        Some("true") => Ok(true),
        Some(other) => bail!("SONDA_PLAIN_HTTP must be true or false, not {other:?}"),
    }
}

/// How the server writes logs (ADR-0019).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    /// One JSON object per line, for log collectors.
    Json,
}

/// SONDA_LOG_FORMAT: `text` (the default) or `json`.
pub fn log_format(env: &dyn Env) -> Result<LogFormat> {
    match env.var("SONDA_LOG_FORMAT").as_deref() {
        None | Some("" | "text") => Ok(LogFormat::Text),
        Some("json") => Ok(LogFormat::Json),
        Some(other) => bail!("SONDA_LOG_FORMAT must be text or json, not {other:?}"),
    }
}

/// The database to connect to, from DATABASE_URL (or DATABASE_URL_FILE) and
/// optionally DATABASE_PASSWORD (or DATABASE_PASSWORD_FILE).
pub fn database(env: &dyn Env) -> Result<PgConnectOptions> {
    let url = secret(env, "DATABASE_URL")?
        .context("set DATABASE_URL or DATABASE_URL_FILE (postgres://user@host/db)")?;
    // The URL may hold a password: errors never echo it. The scheme is
    // checked here because sqlx accepts any, e.g. a mysql:// URL.
    let invalid = || anyhow::anyhow!("DATABASE_URL is not a valid postgres:// URL");
    if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
        return Err(invalid());
    }
    let mut database = PgConnectOptions::from_str(&url).map_err(|_| invalid())?;
    // Lets Docker Compose share one password file between Postgres and the
    // server, instead of repeating the password inside a URL.
    if let Some(password) = secret(env, "DATABASE_PASSWORD")? {
        database = database.password(&password);
    }
    Ok(database)
}

/// `NAME`, or the contents of the file `NAME_FILE` names (trailing newline
/// removed). Setting both is an error, so it is never ambiguous which wins.
/// A secret from `name` or the file `<name>_FILE` names. An empty variable
/// counts as unset, so a compose override can turn a secret off
/// (`SONDA_TOKEN_FILE: ""`), which compose can't do by removing it.
fn secret(env: &dyn Env, name: &str) -> Result<Option<String>> {
    let file_var = format!("{name}_FILE");
    let set = |var: &str| env.var(var).filter(|v| !v.is_empty());
    match (set(name), set(&file_var)) {
        (Some(_), Some(_)) => bail!("set {name} or {file_var}, not both"),
        (Some(value), None) => Ok(Some(value)),
        (None, Some(path)) => {
            let value = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {file_var} ({path})"))?;
            Ok(Some(value.trim_end_matches(['\r', '\n']).to_string()))
        }
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeEnv(HashMap<&'static str, String>);

    impl Env for FakeEnv {
        fn var(&self, name: &str) -> Option<String> {
            self.0.get(name).cloned()
        }
    }

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn load(vars: &[(&'static str, &str)]) -> Result<Config> {
        let env = FakeEnv(vars.iter().map(|(k, v)| (*k, v.to_string())).collect());
        Config::load("127.0.0.1:9000".parse().unwrap(), None, &env)
    }

    #[test]
    fn secrets_come_from_variables_or_files() {
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, format!("{TOKEN}\n")).unwrap();
        let password_file = dir.path().join("password");
        std::fs::write(&password_file, "pw\n").unwrap();
        let config = load(&[
            ("DATABASE_URL", "postgres://sonda@db:5432/sonda"),
            ("DATABASE_PASSWORD_FILE", password_file.to_str().unwrap()),
            ("SONDA_TOKEN_FILE", token_file.to_str().unwrap()),
        ])
        .unwrap();
        let token = config.token.as_ref().unwrap();
        assert!(token.matches(TOKEN));
        assert!(!token.matches("wrong"));
        assert_eq!(config.database.get_host(), "db");
        assert_eq!(config.database.get_database(), Some("sonda"));
    }

    #[test]
    fn missing_or_ambiguous_secrets_are_errors() {
        let url = ("DATABASE_URL", "postgres://sonda@db/sonda");
        assert!(load(&[("SONDA_TOKEN", TOKEN)]).is_err());
        // SONDA_TOKEN is optional: users have their own tokens (ADR-0012).
        assert!(load(&[url]).unwrap().token.is_none());
        assert!(load(&[url, ("SONDA_TOKEN", "short")]).is_err());
        let both = load(&[url, ("SONDA_TOKEN", TOKEN), ("SONDA_TOKEN_FILE", "/x")]);
        assert!(both.err().unwrap().to_string().contains("not both"));
        // Empty is unset: how a compose override turns the shared token off.
        assert!(
            load(&[url, ("SONDA_TOKEN_FILE", "")])
                .unwrap()
                .token
                .is_none()
        );
        assert!(load(&[url, ("SONDA_TOKEN", "")]).unwrap().token.is_none());
    }

    #[test]
    fn the_github_app_needs_its_id_and_key_together() {
        let env = |vars: &[(&'static str, &str)]| {
            FakeEnv(vars.iter().map(|(k, v)| (*k, v.to_string())).collect())
        };
        assert!(github(&env(&[])).unwrap().is_none());
        let only_id = github(&env(&[("SONDA_GITHUB_APP_ID", "123")])).unwrap_err();
        assert!(only_id.to_string().contains("both"), "{only_id}");
        let only_key = github(&env(&[("SONDA_GITHUB_APP_PRIVATE_KEY", "x")])).unwrap_err();
        assert!(only_key.to_string().contains("both"), "{only_key}");
        let plain = github(&env(&[
            ("SONDA_GITHUB_APP_ID", "123"),
            ("SONDA_GITHUB_APP_PRIVATE_KEY", "x"),
            ("SONDA_GITHUB_API_URL", "http://github.example.com"),
        ]))
        .unwrap_err();
        assert!(
            plain.to_string().contains("SONDA_GITHUB_API_URL"),
            "{plain}"
        );
        assert!(public_url(&env(&[("SONDA_PUBLIC_URL", "ftp://x")]), false).is_err());
        assert_eq!(
            public_url(
                &env(&[("SONDA_PUBLIC_URL", "https://sonda.example.com/")]),
                false
            )
            .unwrap(),
            Some("https://sonda.example.com".into())
        );
    }

    #[test]
    fn plain_http_is_off_unless_asked_and_allows_an_http_public_url() {
        let url = ("DATABASE_URL", "postgres://sonda@db/sonda");
        assert!(!load(&[url]).unwrap().plain_http);
        assert!(
            !load(&[url, ("SONDA_PLAIN_HTTP", "false")])
                .unwrap()
                .plain_http
        );
        assert!(load(&[url, ("SONDA_PLAIN_HTTP", "yes")]).is_err());
        let lan = ("SONDA_PUBLIC_URL", "http://192.168.1.10:9000");
        assert!(load(&[url, lan]).is_err());
        let config = load(&[url, lan, ("SONDA_PLAIN_HTTP", "true")]).unwrap();
        assert!(config.plain_http);
        assert_eq!(
            config.public_url.as_deref(),
            Some("http://192.168.1.10:9000")
        );
    }

    #[test]
    fn advisory_sync_is_off_unless_asked() {
        let base = [
            ("DATABASE_URL", "postgres://sonda@db/sonda"),
            ("SONDA_TOKEN", "0123456789abcdef0123456789abcdef"),
        ];
        assert_eq!(load(&base).unwrap().advisory_sync, None);
        let with = |extra: &[(&'static str, &'static str)]| {
            let mut vars = base.to_vec();
            vars.extend_from_slice(extra);
            load(&vars)
        };
        assert_eq!(
            with(&[("SONDA_ADVISORY_SYNC", "true")])
                .unwrap()
                .advisory_sync
                .as_deref(),
            Some(crate::advisory_sync::DEFAULT_BASE_URL)
        );
        assert!(with(&[("SONDA_ADVISORY_SYNC", "yes")]).is_err());
        assert!(
            with(&[
                ("SONDA_ADVISORY_SYNC", "true"),
                ("SONDA_ADVISORY_SYNC_URL", "http://mirror.example.com")
            ])
            .is_err()
        );
    }

    #[test]
    fn log_format_is_text_unless_json_and_refuses_anything_else() {
        let format = |vars: &[(&'static str, &str)]| {
            log_format(&FakeEnv(
                vars.iter().map(|(k, v)| (*k, v.to_string())).collect(),
            ))
        };
        assert_eq!(format(&[]).unwrap(), LogFormat::Text);
        assert_eq!(
            format(&[("SONDA_LOG_FORMAT", "")]).unwrap(),
            LogFormat::Text
        );
        assert_eq!(
            format(&[("SONDA_LOG_FORMAT", "text")]).unwrap(),
            LogFormat::Text
        );
        assert_eq!(
            format(&[("SONDA_LOG_FORMAT", "json")]).unwrap(),
            LogFormat::Json
        );
        let err = format(&[("SONDA_LOG_FORMAT", "JSON")]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "SONDA_LOG_FORMAT must be text or json, not \"JSON\""
        );
    }

    #[test]
    fn weak_tokens_are_refused() {
        assert!(Token::new("short").is_err());
        assert!(Token::new(&format!("{TOKEN} x")).is_err());
        assert!(Token::new(TOKEN).is_ok());
    }

    #[test]
    fn a_bad_database_url_is_refused_without_echoing_it() {
        for url in ["mysql://u:hunter2@h/d", "postgres://u:hunter2@h:notaport/d"] {
            let err = load(&[("DATABASE_URL", url), ("SONDA_TOKEN", TOKEN)])
                .err()
                .unwrap();
            assert!(!format!("{err:#}").contains("hunter2"), "{err:#}");
        }
    }
}
