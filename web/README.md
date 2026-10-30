# sonda web

The Sonda web app: React, TypeScript, Tailwind CSS v4 and Lucide, built from
the design handoff in [`../docs/designs/`](../docs/designs/).

**Status:**
- **Against `sonda server`:** sign-in, Issues (filtered and paginated by the
  server, with triage) and Rules (read-only) show real data.
- **Overview:** built from the server's analysis history. Data the server
  doesn't have is shown as missing. Examples: no "My team" scope without
  teams, and "No data" for coverage that was never uploaded. Without the
  per-metric drill-down data, a metric opens the matching issues.
- **The other six screens:** show a "not built yet" page.

```sh
pnpm install      # honors a 14-day minimum release age (pnpm-workspace.yaml)
pnpm dev          # http://localhost:5173, against the in-memory mock
pnpm dev:server   # the same, against a sonda server on 127.0.0.1:9000 (proxied)
pnpm test         # Vitest + Testing Library
pnpm typecheck && pnpm lint && pnpm build
```

A production build always talks to the server at `/api` on its own origin.
The Docker image serves it that way (see `../docs/server.md`).

## Layout

| Path | What |
|---|---|
| `src/api/types.ts` | **The API contract.** The app only talks to `SondaApi`; names follow sonda's own model. |
| `src/api/http.ts` | The contract over `sonda server`'s HTTP API. It sends the session cookie same-origin and adds `Sonda-Csrf` to changes. An expired session sends the viewer back to sign-in. |
| `src/api/mock/` | In-memory implementation for development and tests, seeded from the prototypes and converted to the server's shapes. `query.ts` does what the server does: filter, sort, page and count facets. It is imported lazily, so its sample data never ships in a production build. |
| `src/lib/` | Pure, unit-tested logic: chart geometry, waffle allocation, issue filtering and facets, drill-down params, formatting, the visual vocabulary. |
| `src/components/sonda/` | Shared components: `PipMeter`, `GateStatus`, `SeverityGlyph`, `CoverageRing`, `Sparkline`, `MetricGrid`, `DrillDrawer`, `CodeViewer`, plus controls and layout. |
| `src/components/shell/` | Sidebar, sheet, header, breadcrumbs, theme toggle. |
| `src/pages/` | One file per screen. |

## Design decisions

- **Tokens:** the design's colors live in `src/index.css` as `--sd-*`, with
  the exact values from the handoff, in dark and light themes. Tailwind
  exposes them as `bg-panel`, `text-fg-muted`, `bg-brand`, `border-line` and
  so on. shadcn's variables are derived from them. The prefix exists because
  the design's `--muted` and `--accent` mean something else in shadcn.
- **Theme:** dark by default, set as `data-theme` on `<html>` and saved in
  `localStorage['sonda-theme']`.
- **Visual language** (what sets the design apart):
  - no letter grades; ratings are 5-segment pip meters
  - gate status is a shaped dot plus a word
  - severity is always a glyph plus a label
  - borders are inset shadows (the `edge` utility)
- **Drill-down links** are query parameters, for example
  `/issues?cat=vulnerability&new`, so they work with the router and the back
  button. A rule link is `/rules#<rule-id>`.
- **Syntax highlighting:** the contract sends code tokens tagged with roles
  (`keyword`, `string`, ...). The server will tokenize with tree-sitter, which
  sonda already uses, so the browser needs no highlighter bundle.
- **Self-hosted fonts** (`@fontsource`), so there are no requests to Google.
- **shadcn/ui:** `components.json` is configured. Add components with
  `pnpm dlx shadcn add <name>`; nothing from shadcn is used yet, so its
  packages are not dependencies.
- **Supply chain:** `minimumReleaseAge` refuses any package version younger
  than 14 days. CI runs `pnpm audit`.

## Signing in

`SessionGate` asks the server whether a session exists, and whether reads
need one:
- **Reads need sign-in** (the Docker setup): it shows the sign-in page first.
- **Reads are open** (a server on localhost): the viewer may continue
  read-only.

Signing in sends the API token once. The server answers with an `HttpOnly`
session cookie, so page scripts, and anything injected into them, never see
a credential. There are no user accounts yet: "Assign to me" uses a name the
viewer types at sign-in, kept in `localStorage`.

## Deliberately not faked

- ⌘K search is shown but disabled ("not built yet").
- The empty state's quickstart uses commands sonda actually has.
- The error state's "Show cached" button is omitted, because there is no
  cache.
- The org switcher chevron and notifications bell from the Overview
  prototype are omitted; nothing backs them.
- **Issues:**
  - No "Resolve as fixed": analyses decide that.
  - No "Open in editor": it only showed a toast.
  - No "Related issues": nothing computes them.
  - No made-up headline: the count is the server's.
- **Rules:** no on/off switches or parameters. Rules are configured in each
  repository's `sonda.toml`, and the page shows how.
- **Counts the server doesn't have yet** (projects, components) are left out
  of the navigation rather than shown as numbers.
- **Overview:** no "Live" badge, since the page doesn't refresh itself, and
  no "vs N days ago" without a comparison to show.
