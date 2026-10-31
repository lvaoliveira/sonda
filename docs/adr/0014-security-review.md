# ADR-0014: Security review of issues

- Status: **proposed**
- Date: 2026-10-31
- Replaces the roadmap's "hotspots" item

## Context

The roadmap planned security hotspots: a fourth kind of finding, for
security-sensitive code a person reviews, with its own statuses and a
"hotspots reviewed" gate, as SonarQube had.

SonarQube no longer works that way. The server sonda's rule parity is
measured against (SonarQube 26.7) has no hotspot rules in JavaScript,
TypeScript, Python or Java. The rules that used to be hotspots, such as
weak hashing (S4790), cookies without `Secure` (S2092), permissive CORS
(S5122), commands found through `PATH` (S4036) and debug mode (S4507), are
now vulnerabilities with a security impact, reviewed with the ordinary
issue statuses. sonda already classifies them that way.

What remains useful is the review itself: a place where someone works
through security findings and decides on each. Two things stop sonda's
issues from serving that today:

- **A decision doesn't clear the gate.** On the server, accepted issues
  still count in `new_vulnerabilities` and the other new-code measures, so
  accepting a finding leaves the gate failing. In SonarQube, accepted and
  false-positive issues don't count.
- **Decisions have no reason.** sonda's statuses are open, confirmed and
  accepted. There's no "false positive" (it isn't a problem) separate from
  "accepted" (it is, and we take the risk). The history records that the
  status changed, but not why, unlike dependency reviews, which require a
  reason (ADR-0009).

## Decision

### Statuses, as in SonarQube

| Status | Means | Reason |
|---|---|---|
| **Open** | not reviewed yet | — |
| **Confirmed** | a real problem, to fix | optional |
| **Accepted** | a real problem whose risk is accepted | required |
| **False positive** | not a problem, the rule is wrong here | required, new |
| **Fixed** | gone from the latest analysis (set by analyses) | — |

- **False positive is new** (migration: the `issue_status` type gains
  `false_positive`). Dependency findings keep open, confirmed and accepted:
  a version range doesn't misfire the way a code rule can.
- **Reasons** go in the issue's history (`issue_events` gains `reason`),
  and the issue shows the latest one. They're 1-500 characters, required
  for accepted and false positive, as for dependency reviews.
- **Who:** any signed-in user, or a user token (ADR-0012), as for the
  current triage. The history records who.
- **A re-detected issue keeps its decision,** as it does today: a false
  positive stays a false positive when its code moves.

### Decided issues stop counting

Accepted and false-positive issues, of every category, no longer count in
the server's issue measures, new code included, nor in ratings or the
Security screen's open counts. They're decisions, not fixes, so they stay
listed under their status.

- **The main branch:** the new code period's refresh (ADR-0011) counts only
  issues that are neither accepted nor false positive.
- **Other branches:** their latest analysis gets the same recount, on the
  scan's own new code.
- **The stored gate is re-evaluated** when an issue's status changes, as
  for dependency reviews.
- **The CLI's gate in CI doesn't know** about reviews, which live on the
  server. As before, a finding that is never a problem can be suppressed in
  code (`sonda-ignore`), and the server's gate is the one that reflects
  reviews.

### The review queue

The Security screen gets a **To review** queue: open security findings
(vulnerabilities) on each project's main branch, and on a branch when one
is selected.

- **Order:** blockers first, then critical, major and minor; new code
  before older code; then the oldest first.
- **Each row:** the rule, its CWE ids and OWASP categories, the file and
  line, how old it is, and whether it's on new code.
- **Actions in place:** Confirm, Accept, False positive (the last two ask
  for a reason), Assign to me, and open the issue.
- **Filters:** project, branch, severity, OWASP category, assignee, new
  code only.
- **Progress:** how many findings are open, confirmed, accepted and false
  positives, on new code and overall, and the reviewed share (anything not
  open).

### Not now

- **A security review rating or a "reviewed" gate metric.** SonarQube's
  were for hotspots. With decided issues leaving the counts, the gate
  already fails until each new vulnerability is fixed, accepted or ruled a
  false positive, so another metric would add nothing.
- **Hotspots as a fourth category,** unless SonarQube brings them back.
- **Bulk review** of many findings with one reason. A filter and one action
  per row cover the first use; bulk can follow.

## Consequences

- **Reviews change the gate:** marking a new vulnerability as accepted or a
  false positive, with a reason, lets the gate pass on the server, as in
  SonarQube.
- **Counts drop on upgrade** for issues already accepted, which no longer
  count. That's the point, but dashboards will show it.
- **Rules and reports don't change.** The work is in the server and the web
  app, so it doesn't overlap with the rule-parity work.
- **The roadmap's hotspot item is replaced** by this one, and reachability
  stays as the last security item.
