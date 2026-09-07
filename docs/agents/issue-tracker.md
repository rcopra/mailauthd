# Issue Tracker

Issues for this repo live in **Linear** (https://linear.app), accessed through
the Linear MCP server (`https://mcp.linear.app/mcp`, configured in this repo's
`.mcp.json`). This is a solo project; there is one workspace and no team
workflow beyond the conventions below.

## Reading and writing issues

- Create one issue per ticket, in dependency order (blockers first), so
  blocking edges can reference real issue identifiers (e.g. `MAIL-12`).
- Blocking edges: use Linear's issue **relations** of type `blocks` /
  `blocked by` where the MCP tooling supports it; otherwise list the blocking
  issue identifiers in a "Blocked by" section at the end of the issue body.
- Each issue body follows the `to-tickets` issue template: "What to build"
  (end-to-end behaviour, not layer-by-layer lists), "Acceptance criteria" as
  checkboxes, and "Blocked by".
- Triage labels follow `docs/agents/triage-labels.md`. New agent-grabbable
  tickets get the `ready-for-agent` label.
- Do not close or modify parent/planning issues when publishing tickets.

## Workflow

- Work the **frontier**: any ticket whose blockers are all done.
- The project for this work is `mailauthd`; group tickets under it when a
  project exists in the workspace.
