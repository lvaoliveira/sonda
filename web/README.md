# sonda web

The Sonda web app: React, TypeScript, Tailwind CSS v4 and Lucide, built from
the design handoff in [`../docs/designs/`](../docs/designs/).

**Status:** first increment. Overview, Issues and Rules are built, along with
the app shell and shared components. The other seven screens show a "not
built yet" page. All data comes from a mock API until `sonda server` exists.

```sh
pnpm install      # honors a 14-day minimum release age (pnpm-workspace.yaml)
pnpm dev          # http://localhost:5173
pnpm test         # Vitest + Testing Library
pnpm typecheck && pnpm lint && pnpm build
```

## Layout

| Path | What |
|---|---|
| `src/api/types.ts` | **The API contract.** The app only talks to `SondaApi`; names follow sonda's own model. |
| `src/api/mock/` | In-memory implementation seeded from the prototypes. `issues.json` and `rules.json` were converted from `docs/designs/` (categories renamed, code tokens mapped to highlight roles). |
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

## Deliberately not faked

- ⌘K search is shown but disabled ("not built yet").
- The empty state's quickstart uses commands sonda actually has.
- The error state's "Show cached" button is omitted, because there is no
  cache.
- The org switcher chevron and notifications bell from the Overview
  prototype are omitted; nothing backs them.
