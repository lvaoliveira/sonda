# ADR-0024: Creating the GitHub App from the web app

- Status: **accepted; built** (2026-11-03): the encrypted store,
  `SONDA_SECRET_KEY`, the endpoints, Administration → GitHub and the page
  GitHub returns to. Next: the end-to-end check on a real server.
- Date: 2026-11-03
- Builds on ADR-0021 (pull request decoration), which left this under "Not
  now", and ADR-0023 (connecting a repository)

## Context

Decorating pull requests needs a GitHub App (ADR-0021). Today an admin
makes one by hand:

1. On GitHub, create an App: a name, a homepage URL, the webhook turned
   off, and three permissions set.
2. Generate a private key and download the `.pem`.
3. Copy the `.pem` to the server, and run
   `scripts/setup-server.sh --github-app ID KEY.pem`, which restarts it.

Each step has a way to go wrong: a webhook left on that GitHub can't
reach, a permission missed, the key downloaded on a laptop rather than the
server. Setting up the first real server showed all three.

GitHub has a flow for exactly this, the
[App manifest](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest):

1. A page posts a manifest (name, URLs, permissions) to GitHub.
2. GitHub shows its own "Create GitHub App" page, prefilled. The name can
   be edited there.
3. GitHub sends the browser back with a one-time code.
4. The server exchanges the code for the App's ID and private key. All
   three steps must happen within an hour.

The flow returns the key to the server, which has to keep it. ADR-0021
avoided storing credentials, so that's the decision here.

## Decision

### Administration → GitHub

- **A new section, for admins:** whether an App is connected, where its
  configuration comes from, and its name with a link to it on GitHub.
- **With no App connected, a "Create GitHub App" button.** Before it:
  - the owner, your account or an organization (by name), since GitHub
    has a page for each;
  - a proposed name, `sonda-<host>`. GitHub names are unique across
    GitHub, and GitHub's page lets the admin change it.
- **The manifest:**
  - `url`: the server's public URL;
  - `redirect_url`: the web app's `/admin/github/created`;
  - `public: false`, so only its owner can install it;
  - `default_permissions`: checks write, pull requests write, metadata
    read, as ADR-0021;
  - no `hook_attributes` and no `default_events`: no webhook, as today.
- **Then installing it.** Once created, the section links to the App's
  "Install" page on GitHub, where the admin picks repositories. It then
  shows where the App is installed, asked of GitHub with the App's JWT
  each time the section loads (there's no webhook to be told), and
  offers "Install" only while it's installed nowhere. The
  Connect page (ADR-0023) links there too, since sonda can't tell which
  repositories it's installed on.

### The return trip, and why it's a page

- **`state` binds the flow to the admin who started it.** The server
  makes a random `state`, keeps it in memory with that admin's username
  for an hour, and accepts it once, from that admin only. A restart in
  between loses it, and the admin starts again.
- **GitHub sends the browser to a web app page, not an API route.** The
  session cookie is `SameSite=Strict`, so a navigation from github.com
  arrives without it. The page then posts `{code, state}` to
  `POST /api/github/app`, a same-site request that carries the cookie and
  the CSRF header like every other write.
- **The server exchanges the code** with
  `POST /app-manifests/{code}/conversions`. It keeps the App's ID, slug,
  page URL and private key. It discards the client secret and webhook
  secret, which nothing uses (GitHub can make new ones later).
- **The address GitHub sends back to** is the one the admin's browser is
  on, from the `Origin` of their request, so a server reached on several
  addresses (a LAN and a tailnet, say) brings them back to the one they
  started from. `SONDA_PUBLIC_URL` is the App's homepage, and the way back
  only without an `Origin`.
- **The return works on a LAN.** It's the admin's browser that comes
  back, not GitHub's servers, so `http://192.168.1.254:9300` works, the
  same way the Connect page's links to GitHub do.

### Storing the key: encrypted, with a key the server never stores

- **A new secret, `SONDA_SECRET_KEY` (or `_FILE`):** 32 random bytes,
  base64. `scripts/setup-server.sh` creates it once, like the database
  password and the token, as `secrets/secret_key`.
- **The App's key is stored encrypted** with AES-256-GCM (`ring`, already
  a dependency): a random nonce per write, and the row's purpose as
  associated data, so a ciphertext can't be moved to another column. The
  database never holds the key in plaintext, so neither do its dumps or
  backups.
- **Without `SONDA_SECRET_KEY`**, the button is disabled, with a line that
  says why and how to set it. Configuring the App as today still works.
- **A lost or changed `SONDA_SECRET_KEY`** leaves the stored App
  unreadable. The server still starts. It logs a warning, stops
  decorating, and Administration says the App's key can't be read and
  offers to disconnect it.
- **This is the store GitLab and Bitbucket will need** (ADR-0021,
  Consequences) for their tokens, so it's a general
  `encrypted_secrets` table, not one only for GitHub.

Considered and rejected:

- **A file on a volume.** The server container keeps no state today, and
  backing up the database is enough to restore it. A key file beside it
  would split that, and would still sit in plaintext.
- **Plaintext in the database.** Every dump and backup would carry a key
  that can write checks and comments on every repository it's installed
  on.

### Effect without a restart, and which configuration wins

- **Creating or disconnecting takes effect at once.** The server's App
  becomes swappable, read on each use, and the decoration task always
  runs and skips when there's none.
- **Configuration wins.** With `SONDA_GITHUB_APP_ID` set, Administration
  shows the App as configured by the server's configuration, and offers
  neither the button nor disconnecting.
- **Disconnecting** deletes the stored App. sonda can't delete the App
  itself on GitHub, so the section links to its settings page there.
- **Enterprise Server:** the manifest page is on the web host, not the
  API host. sonda derives one from the other: `api.github.com` becomes
  `github.com`, and `https://HOST/api/v3` becomes `https://HOST`.

### The API

| Endpoint | |
|---|---|
| `GET /api/github/app` | Admins only. `{"source": "config" \| "stored" \| "unreadable" \| null, "id", "slug", "htmlUrl", "installUrl", "createdBy", "createdAt", "secretKey"}`. Never the key. |
| `POST /api/github/app/manifest` `{"owner": null \| "<org>", "name"}` | Admins only. `{"action": "<GitHub's URL with state>", "manifest": "<JSON>"}`, for the page to post as a form. `422` while an App is connected or without `SONDA_SECRET_KEY`. |
| `POST /api/github/app` `{"code", "state"}` | Admins only. Exchanges the code and stores the App; `201` with the `GET` body. `state` that's unknown, used, expired or another admin's gets `400`, as does a code GitHub refuses. |
| `DELETE /api/github/app` | Admins only. Disconnects a stored or unreadable App, and answers with the `GET` body; `422` for a configured one. |

## Consequences

- A new server connects GitHub in a few clicks on two sites: create the
  App, then install it. No file to copy, no command to run, no restart.
- The server has a second secret to keep, `SONDA_SECRET_KEY`. Restoring a
  backup on a new host needs it too, or the stored App must be created
  again. `docs/server.md` says so, next to the database password.
- `--github-app ID KEY.pem` stays, for servers that keep secrets outside
  the database, and for Apps shared between servers.
- The private key passes through the server once, in the conversion's
  answer, and is never in an API response, a log line or the web app.

## Not now

- Signing in with GitHub, which would keep the client secret this
  discards.
- Webhooks.
- Rotating the App's key from sonda: GitHub makes new keys only on its own
  page, so rotating means uploading the new `.pem`. A later "Replace key"
  field could take it.
- Re-encrypting stored secrets under a new `SONDA_SECRET_KEY`.

## Done when

- On a server set up with `scripts/setup-server.sh` and no
  `--github-app`, an admin creates the App from Administration, installs
  it on a repository, and that repository's next pull request is
  decorated, with no restart and no file edited.
- The same works on the LAN address over plain HTTP.
- A dump of the database doesn't contain the private key.
- The key is never in an API response or a log line (tested as ADR-0021's
  are).
- A `state` that's unknown, reused, expired or another admin's is
  refused, and so is a non-admin.
- With `SONDA_GITHUB_APP_ID` set, the section is read-only.
- With `SONDA_SECRET_KEY` changed, the server starts, says the App's key
  can't be read, and disconnecting it allows creating a new one.

## Building it, in this order

1. `SONDA_SECRET_KEY`, the encrypted store and its tests, and
   `setup-server.sh` creating the secret.
2. A swappable App in the server's state, with the decoration task always
   running.
3. The four endpoints, tested against a fake GitHub as ADR-0021's client
   is.
4. Administration → GitHub, the `/admin/github/created` page, and the
   Connect page's link to install.
5. `docs/server.md`, and the end-to-end check on the N100.
