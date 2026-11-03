//! Which GitHub App decorates pull requests (ADR-0024): one configured
//! (SONDA_GITHUB_APP_ID, ADR-0021), which wins, or one an admin created
//! from Administration with GitHub's App manifest flow, whose key is stored
//! encrypted (`stored_secrets`). Creating or disconnecting one takes effect
//! at once: everything reads the App from here on each use.

use crate::api::{ApiError, Caller};
use crate::github::{self, App};
use crate::health::rfc3339;
use crate::http::State;
use crate::stored_secrets::{self, GITHUB_APP_KEY, SecretKey, Stored};
use axum::Json;
use axum::extract::Extension;
use axum::http::{HeaderMap, StatusCode, header};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// How long GitHub allows from posting the manifest to converting the code.
const CREATION_TIMEOUT: Duration = Duration::from_secs(3600);

/// GitHub's limit on an App's name.
const MAX_NAME_LEN: usize = 34;

/// Where GitHub sends the browser back: a web app page, since the
/// `SameSite=Strict` session cookie doesn't come along on a navigation
/// from github.com. The page posts the code with the cookie.
pub const CREATED_PATH: &str = "/admin/github/created";

#[derive(Clone)]
struct Info {
    id: String,
    slug: String,
    html_url: String,
    created_by: String,
    created_at: String,
}

#[derive(Clone)]
enum Current {
    None,
    Configured(Arc<App>),
    Stored(Arc<App>, Info),
    /// Stored, but its key doesn't open with SONDA_SECRET_KEY.
    Unreadable(Info),
}

pub struct Connection {
    current: RwLock<Current>,
    secret_key: Option<SecretKey>,
    api: String,
    public_url: Option<String>,
    /// Creations started, by `state`: who started it, and when. Each is
    /// used once.
    started: Mutex<HashMap<String, (String, Instant)>>,
}

impl Default for Connection {
    fn default() -> Self {
        Self::new(None, None, github::DEFAULT_API_URL.into(), None)
    }
}

impl Connection {
    pub fn new(
        configured: Option<Arc<App>>,
        secret_key: Option<SecretKey>,
        api: String,
        public_url: Option<String>,
    ) -> Self {
        Self {
            current: RwLock::new(configured.map_or(Current::None, Current::Configured)),
            secret_key,
            api: api.trim_end_matches('/').to_string(),
            public_url,
            started: Mutex::default(),
        }
    }

    /// The App to decorate with, if any.
    pub fn app(&self) -> Option<Arc<App>> {
        match &*self.current.read().unwrap() {
            Current::Configured(app) | Current::Stored(app, _) => Some(app.clone()),
            Current::None | Current::Unreadable(_) => None,
        }
    }

    fn set(&self, current: Current) {
        *self.current.write().unwrap() = current;
    }

    /// At startup: the stored App, unless one is configured. A key that
    /// doesn't open is reported, not fatal: the server runs without it.
    pub async fn load(&self, pool: &PgPool) -> anyhow::Result<()> {
        if matches!(&*self.current.read().unwrap(), Current::Configured(_)) {
            return Ok(());
        }
        let Some(info) = stored_info(pool).await? else {
            return Ok(());
        };
        let current =
            match stored_secrets::load(pool, self.secret_key.as_ref(), GITHUB_APP_KEY).await? {
                Stored::Value(pem) => {
                    let pem = String::from_utf8(pem).unwrap_or_default();
                    match App::new(info.id.clone(), &pem, self.api.clone()) {
                        Ok(app) => Current::Stored(Arc::new(app), info),
                        Err(e) => {
                            tracing::warn!(error = %e, "the stored GitHub App's key isn't usable");
                            Current::Unreadable(info)
                        }
                    }
                }
                Stored::Missing | Stored::Unreadable => {
                    tracing::warn!(
                        app = info.slug,
                        "the stored GitHub App's key can't be read: SONDA_SECRET_KEY is missing \
                     or isn't the one it was stored with; disconnect it under Administration"
                    );
                    Current::Unreadable(info)
                }
            };
        self.set(current);
        Ok(())
    }

    fn status(&self) -> Status {
        let current = self.current.read().unwrap().clone();
        let stored = |source, info: Info| Status {
            source: Some(source),
            install_url: Some(format!("{}/installations/new", info.html_url)),
            id: Some(info.id),
            slug: Some(info.slug),
            html_url: Some(info.html_url),
            created_by: Some(info.created_by),
            created_at: Some(info.created_at),
            secret_key: self.secret_key.is_some(),
        };
        match current {
            Current::None => Status {
                secret_key: self.secret_key.is_some(),
                ..Status::default()
            },
            Current::Configured(app) => Status {
                source: Some("config"),
                id: Some(app.id().to_string()),
                secret_key: self.secret_key.is_some(),
                ..Status::default()
            },
            Current::Stored(_, info) => stored("stored", info),
            Current::Unreadable(info) => stored("unreadable", info),
        }
    }
}

async fn stored_info(pool: &PgPool) -> sqlx::Result<Option<Info>> {
    let row: Option<(i64, String, String, String, f64)> = sqlx::query_as(
        "SELECT app_id, slug, html_url, created_by, extract(epoch FROM created_at)::float8
         FROM github_app",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id, slug, html_url, created_by, at)| Info {
        id: id.to_string(),
        slug,
        html_url,
        created_by,
        created_at: rfc3339(at),
    }))
}

/// The App, as Administration shows it. Never its key.
#[derive(Serialize, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// `config` (SONDA_GITHUB_APP_ID), `stored` (created here),
    /// `unreadable` (created here, but its key doesn't open), or null.
    source: Option<&'static str>,
    id: Option<String>,
    /// For a stored App only: GitHub tells these when it's created.
    slug: Option<String>,
    html_url: Option<String>,
    /// Where to install it on repositories.
    install_url: Option<String>,
    created_by: Option<String>,
    created_at: Option<String>,
    /// Whether SONDA_SECRET_KEY is set: creating an App needs it.
    secret_key: bool,
}

/// `GET /api/github/app`, admins only.
pub async fn get(axum::extract::State(state): axum::extract::State<State>) -> Json<Status> {
    Json(state.github.status())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewApp {
    /// An organization's login; null for the admin's own account.
    owner: Option<String>,
    name: String,
}

/// What the web app posts to GitHub as a form, which starts the creation.
#[derive(Serialize, Debug)]
pub struct ManifestForm {
    action: String,
    manifest: String,
}

fn is_login(s: &str) -> bool {
    (1..=39).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !s.starts_with('-')
}

/// Where GitHub sends the admin's browser back: the address the browser is
/// on, from the request's `Origin`, which a browser sends on every POST. A
/// server reached at several addresses (a LAN, a tailnet) brings the admin
/// back to the one they started from, which SONDA_PUBLIC_URL might not be
/// reachable from. That only without an `Origin`.
fn return_url(state: &State, headers: &HeaderMap) -> Result<String, ApiError> {
    headers
        .get(header::ORIGIN)
        .and_then(|o| o.to_str().ok())
        .filter(|o| {
            let rest = o
                .strip_prefix("https://")
                .or_else(|| o.strip_prefix("http://"));
            rest.is_some_and(|r| !r.is_empty() && !r.contains('/'))
        })
        .map(str::to_string)
        .or_else(|| state.github.public_url.clone())
        .ok_or_else(|| {
            ApiError::BadRequest(
                "set SONDA_PUBLIC_URL, the server's address, so GitHub can send you back".into(),
            )
        })
}

fn refuse_unless_creatable(connection: &Connection) -> Result<(), ApiError> {
    if !matches!(&*connection.current.read().unwrap(), Current::None) {
        return Err(ApiError::Unprocessable(
            "a GitHub App is already connected; disconnect it first".into(),
        ));
    }
    if connection.secret_key.is_none() {
        return Err(ApiError::Unprocessable(
            "set SONDA_SECRET_KEY first: it encrypts the App's key (docs/server.md)".into(),
        ));
    }
    Ok(())
}

/// `POST /api/github/app/manifest`, admins only: the manifest for GitHub's
/// "Create GitHub App" page, and a `state` that only this admin can
/// complete, within the hour.
pub async fn manifest(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Json(new): Json<NewApp>,
) -> Result<Json<ManifestForm>, ApiError> {
    refuse_unless_creatable(&state.github)?;
    let name = new.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN || name.chars().any(char::is_control)
    {
        return Err(ApiError::Unprocessable(format!(
            "the App's name is 1 to {MAX_NAME_LEN} characters"
        )));
    }
    let owner = new
        .owner
        .as_deref()
        .map(str::trim)
        .filter(|o| !o.is_empty());
    if owner.is_some_and(|o| !is_login(o)) {
        return Err(ApiError::Unprocessable(
            "that isn't an organization's name on GitHub".into(),
        ));
    }
    let back = return_url(&state, &headers)?;
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("no randomness")))?;
    let nonce: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    {
        let mut started = state.github.started.lock().unwrap();
        started.retain(|_, (_, at)| at.elapsed() < CREATION_TIMEOUT);
        started.insert(nonce.clone(), (caller.name(), Instant::now()));
    }
    let manifest = json!({
        "name": name,
        // The App's homepage, on its GitHub page: the server's address for
        // everyone, when it has one.
        "url": state.github.public_url.as_deref().unwrap_or(&back),
        "description": "Decorates pull requests with sonda's analyses.",
        "redirect_url": format!("{back}{CREATED_PATH}"),
        "public": false,
        // As ADR-0021; no webhook, so no hook_attributes or events.
        "default_permissions": {
            "checks": "write",
            "pull_requests": "write",
            "metadata": "read",
        },
    });
    let web = github::web_url(&state.github.api);
    let page = match owner {
        Some(org) => format!("{web}/organizations/{org}/settings/apps/new"),
        None => format!("{web}/settings/apps/new"),
    };
    Ok(Json(ManifestForm {
        action: format!("{page}?state={nonce}"),
        manifest: manifest.to_string(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    code: String,
    state: String,
}

/// `POST /api/github/app`, admins only: GitHub's code, from the page it
/// sent the browser back to, exchanged for the App and its key, which is
/// stored encrypted.
pub async fn create(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Json(c): Json<Completion>,
) -> Result<(StatusCode, Json<Status>), ApiError> {
    let connection = &state.github;
    let by = caller.name();
    let started = connection.started.lock().unwrap().remove(&c.state);
    if !started.is_some_and(|(who, at)| who == by && at.elapsed() < CREATION_TIMEOUT) {
        return Err(ApiError::BadRequest(
            "this App wasn't started here by you, or it took over an hour: start again".into(),
        ));
    }
    refuse_unless_creatable(connection)?;
    let (api, code) = (connection.api.clone(), c.code);
    let created = tokio::task::spawn_blocking(move || github::convert_manifest(&api, &code))
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("the conversion task failed: {e}")))?
        .map_err(|e| {
            tracing::warn!(
                error = format!("{e:#}"),
                "GitHub didn't convert the App's code"
            );
            ApiError::BadRequest(
                "GitHub didn't accept the code, which works once and within the hour: start again"
                    .into(),
            )
        })?;
    let app = App::new(created.id.to_string(), &created.pem, connection.api.clone())
        .map_err(ApiError::Internal)?;
    let key = connection.secret_key.as_ref().expect("checked above");
    let mut tx = state.pool.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO github_app (app_id, slug, html_url, created_by) VALUES ($1, $2, $3, $4)
         ON CONFLICT DO NOTHING",
    )
    .bind(created.id as i64)
    .bind(&created.slug)
    .bind(&created.html_url)
    .bind(&by)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(ApiError::Unprocessable(
            "a GitHub App is already connected; disconnect it first".into(),
        ));
    }
    stored_secrets::store(&mut *tx, key, GITHUB_APP_KEY, created.pem.as_bytes())
        .await
        .map_err(ApiError::Internal)?;
    tx.commit().await?;
    let info = stored_info(&state.pool)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("the App wasn't stored")))?;
    connection.set(Current::Stored(Arc::new(app), info));
    tracing::info!(by, app = created.slug, "connected a GitHub App");
    Ok((StatusCode::CREATED, Json(connection.status())))
}

/// `GET /api/github/app/installations`, admins only: where the App is
/// installed, asked of GitHub each time.
pub async fn installations(
    axum::extract::State(state): axum::extract::State<State>,
) -> Result<Json<Vec<github::Installation>>, ApiError> {
    let app = state
        .github
        .app()
        .ok_or_else(|| ApiError::Unprocessable("no GitHub App is connected".into()))?;
    tokio::task::spawn_blocking(move || app.installations())
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("the GitHub task failed: {e}")))?
        .map(Json)
        .map_err(|e| {
            ApiError::Unprocessable(format!(
                "GitHub didn't say where the App is installed: {e:#}"
            ))
        })
}

/// `DELETE /api/github/app`, admins only: forgets a stored App. It stays on
/// GitHub, which only its owner can delete.
pub async fn disconnect(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
) -> Result<Json<Status>, ApiError> {
    if matches!(
        &*state.github.current.read().unwrap(),
        Current::Configured(_)
    ) {
        return Err(ApiError::Unprocessable(
            "this App is configured by the server's configuration (SONDA_GITHUB_APP_ID); \
             remove it there"
                .into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM github_app")
        .execute(&mut *tx)
        .await?;
    stored_secrets::delete(&mut *tx, GITHUB_APP_KEY).await?;
    tx.commit().await?;
    state.github.set(Current::None);
    tracing::info!(by = caller.name(), "disconnected the GitHub App");
    Ok(Json(state.github.status()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organizations_are_github_logins() {
        for ok in ["acme", "acme-corp", "a1", &"a".repeat(39)] {
            assert!(is_login(ok), "{ok}");
        }
        for bad in ["", "-acme", "acme/x", "acme corp", "a?b", &"a".repeat(40)] {
            assert!(!is_login(bad), "{bad:?}");
        }
    }
}
