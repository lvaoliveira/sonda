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
    pub token: Token,
    /// The built web app (`web/dist`), served for every non-API path.
    pub web_dir: Option<PathBuf>,
    /// Username and password for the first admin, used only while no users
    /// exist (ADR-0006).
    pub admin: Option<(String, String)>,
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
        let url = secret(env, "DATABASE_URL")?
            .context("set DATABASE_URL or DATABASE_URL_FILE (postgres://user@host/db)")?;
        // The URL may hold a password: errors never echo it. The scheme is
        // checked here because sqlx accepts any, e.g. a mysql:// URL.
        let invalid = || anyhow::anyhow!("DATABASE_URL is not a valid postgres:// URL");
        if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
            return Err(invalid());
        }
        let mut database = PgConnectOptions::from_str(&url).map_err(|_| invalid())?;
        // Lets Docker Compose share one password file between Postgres and
        // the server, instead of repeating the password inside a URL.
        if let Some(password) = secret(env, "DATABASE_PASSWORD")? {
            database = database.password(&password);
        }
        let token = secret(env, "SONDA_TOKEN")?
            .context("set SONDA_TOKEN or SONDA_TOKEN_FILE: the API token clients upload with")?;
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
        Ok(Self {
            listen,
            database,
            token: Token::new(&token)?,
            web_dir,
            admin,
        })
    }
}

/// `NAME`, or the contents of the file `NAME_FILE` names (trailing newline
/// removed). Setting both is an error, so it is never ambiguous which wins.
fn secret(env: &dyn Env, name: &str) -> Result<Option<String>> {
    let file_var = format!("{name}_FILE");
    match (env.var(name), env.var(&file_var)) {
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
        assert!(config.token.matches(TOKEN));
        assert!(!config.token.matches("wrong"));
        assert_eq!(config.database.get_host(), "db");
        assert_eq!(config.database.get_database(), Some("sonda"));
    }

    #[test]
    fn missing_or_ambiguous_secrets_are_errors() {
        let url = ("DATABASE_URL", "postgres://sonda@db/sonda");
        assert!(load(&[("SONDA_TOKEN", TOKEN)]).is_err());
        assert!(load(&[url]).is_err());
        let both = load(&[url, ("SONDA_TOKEN", TOKEN), ("SONDA_TOKEN_FILE", "/x")]);
        assert!(both.err().unwrap().to_string().contains("not both"));
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
