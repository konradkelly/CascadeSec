# Machine access and project scoping — spec

How something that is not a person in a browser authenticates to
CascadeSec: the CLI on a laptop, a CI job, an HCP Terraform run task. It
also covers how access is scoped to a project, which the API has never
needed until now.

Written before building, 2026-09-25. Part of integrations-spec, phase B.
Not started. The security-sensitive part of the integrations work. It gets
its own review (`/security-review`) before deploy.

## 1. What exists

- One Cognito user pool with admin-created users only (cognito.tf). The
  dashboard's public PKCE client, and a test-only `cli` client for
  `admin-initiate-auth` smoke tests.
- An HTTP API whose routes each carry a **JWT authorizer** that accepts
  **ID tokens** from those two clients (api_gateway.tf).
- **No tenancy.** Every signed-in reviewer can read every PR. That's right
  for one person reviewing their own scans. It's wrong the moment a token
  sits in a CI system, because a leaked CI token would read every
  repository's unfixed vulnerabilities.

## 2. One Lambda authorizer for `/v1`

The new `/v1` routes (cli-spec §4.1) use a **Lambda REQUEST authorizer**,
`api-authorizer`, with the simple-response format and a 300s cache keyed on
the `Authorization` header **(verify: HTTP API caches Lambda authorizer
results by identity source)**. The dashboard's routes keep the Cognito JWT
authorizer, unchanged.

The reason is that an HTTP API route has exactly one authorizer, and `/v1`
has three kinds of caller (§3). A JWT authorizer can't validate an opaque
token, and can't apply a per-project scope to a Cognito user. It could
validate one OIDC issuer, but not several with different trust rules. One
Lambda can handle all three and return the same context shape:

```json
{ "isAuthorized": true,
  "context": { "identity_type": "user" | "token" | "oidc",
               "principal": "<sub, token id, or OIDC sub>",
               "projects": "proj-a,proj-b",
               "permissions": "read,scan,remediate" } }
```

`scan-api` trusts only this context, never a header or body field. That's
the same rule as review-api's `_actor_from_claims`. It also checks
`project` against `projects` on every route, and `scan_id` against its
stored project (cli-spec §4.1).

## 3. Three kinds of caller

### 3.1 Humans: `cascadesec login`

Authorization code plus PKCE against the existing Hosted UI, with a
**loopback redirect**. The CLI listens on `http://localhost:<port>/callback`,
opens the browser, and exchanges the code. That needs a new public client,
`cli-interactive`, with a fixed set of localhost callback URLs (cli-spec
§11.1). Cognito allows plain `http` only for `http://localhost`, and
documents no port wildcard. There's no device-code flow: user pools offer
only the authorization code, implicit and client-credentials grants. AWS's
own workaround builds one from Lambda and DynamoDB, which would be more
auth code to own. Loopback, with a paste-back fallback for SSH, is the
standard CLI pattern.

The refresh token (1 day, as the dashboard) is stored in the OS keyring
(`keyring` package), never in a dotfile. On the `/v1` routes, the authorizer
verifies the **ID token** against the pool's JWKS, and reads the user's
projects from a `USER#<sub>` item (§4).

The existing `cli` client stays test-only and unchanged.

### 3.2 CI with a stored secret: project tokens

`csk_<22 random base62 chars>`. Opaque, shown once at creation, and stored
as `sha256(token)` in a `TOKEN#<hash>` item with project, permissions,
creator, `created_at`, `expires_at` (at most 1 year) and `last_used_at`.
Revoking one deletes the item. Because of the authorizer cache, revocation
takes effect within 300s, and the dashboard says so.

The `csk_` prefix is there for secret scanning: GitHub's push protection
and scanners like gitleaks can be taught to match it. Registering it with
GitHub's secret-scanning partner program is deferred.

Tokens are created in the dashboard, by a user with `admin` on the project,
through new review-api routes. They are **not** created by other tokens. A
leaked token can't mint a longer-lived one.

**Why not Cognito's client-credentials flow**, which the JWT authorizer
could validate natively? Three reasons. First, one app client per
integration is the only way to revoke one CI system and not the others.
Second, M2M clients are billed per client and per token request since 2024
**(verify current pricing)**. Third, a client's scopes are fixed in
Terraform, so they can't express "project A only" without one resource
server scope per project. Hashed tokens in a table are a few dozen lines,
and they're the common pattern.

### 3.3 CI without a stored secret: OIDC federation

GitHub Actions, GitLab CI, Bitbucket Pipelines and HCP Terraform (workload
identity) each issue a short-lived, signed OIDC token that names the
repository, branch and pipeline **(verify each)**. A trust rule maps claims
to a project:

```json
{ "issuer": "https://token.actions.githubusercontent.com",
  "audience": "cascadesec",
  "claims": { "repository": "konradkelly/cascadesec-testbed" },
  "project": "testbed", "permissions": ["read", "scan"] }
```

The authorizer verifies the signature against the issuer's JWKS (cached),
checks `exp`, `aud` and every listed claim for exact equality, and grants
the rule's project and permissions. Only exact matches are allowed, with
no wildcards. A pattern on `repository` is the classic OIDC mistake that
lets any repository in the organisation, or a fork, in.

**There's no secret to leak**, so this is the recommended path for every
platform that supports it. Project tokens are the fallback (Azure Pipelines
has no general-purpose OIDC token for third parties **(verify)**).

Fork PRs: GitHub doesn't issue OIDC tokens to workflows triggered from
forks without `pull_request_target` **(verify)**. The recipe in
ci-platforms-spec uses `pull_request`, so a fork PR gets local-mode
detection only, which needs no token. That matches ci-integration-spec
§6.1's line: an outsider's PR costs no model calls.

## 4. Projects and permissions

A **project** is a name (`[a-z0-9-]{1,32}`) that owns a set of `pr_id`s
(integrations §3.1). Ownership is a `PRPROJECT#<pr_id>` item written with a
condition (`attribute_not_exists`) the first time a `pr_id` is scanned
through `/v1` or a run task. A second project can't claim an existing
`pr_id`, and a guessed id can't be read across projects. Items:

```
PROJECT#<name>            owner, created_at
PRPROJECT#<pr_id>         project
PROJECT#<name> / USER#<sub>        role: reader | reviewer | admin
TOKEN#<sha256>            project, permissions, creator, expires_at, last_used_at
OIDC#<issuer>#<n>         the trust rule above
```

| Permission | Allows | Given to |
|---|---|---|
| `read` | scans, findings, baseline | everyone with access |
| `scan` | start a scan (detection and mapping) | tokens by default, reviewers |
| `remediate` | `remediate: true` | explicit only; model calls cost money |
| `review` | approve, edit, reject | **humans only** (§5) |
| `admin` | manage members, tokens, trust rules | project owner |

Existing `manual-` and `gh-` PRs belong to no project. They stay visible to
every dashboard user, as today. GitHub PRs get a project when D3 decides
how installations map to projects.

## 5. Machines never review

The review route stays on the Cognito JWT authorizer. It is **not** added
to `/v1`, and `api-authorizer` never returns `review` for a `token` or
`oidc` identity, even if an item claims it. This holds at two layers on
purpose. The route not existing on `/v1` is the structural guarantee, and
the authorizer check covers any future route that forgets.

This is spec §1's principle ("the agent proposes, it never decides") applied
to automation. An approval's actor must be a verified person, or the audit
log records a claim rather than a fact.

## 6. Risks

- **Authorizer bug means auth bypass.** Tests cover the expired token, the
  wrong audience, an unknown issuer, the `alg: none` token, a token for
  project A on a project B route, a `review` grant on a token item, and a
  revoked token past the cache TTL.
- **Cache staleness.** A revoked token or removed member keeps access for
  up to 300s. The trade is stated in the dashboard. A lower TTL costs one
  authorizer invoke per request, which is cheap at this scale. D2.
- **Token in logs.** API Gateway's access log format (api_gateway.tf) logs
  no headers. The CLI redacts `CASCADESEC_TOKEN` from its own debug output.

## 7. Decisions

| # | Decision | Outcome |
|---|---|---|
| D1 | Lambda authorizer for `/v1` rather than Cognito M2M (§2, §3.2) | Proposed |
| D2 | Authorizer cache TTL | Proposed: 300s, revisit if revocation latency matters |
| D3 | How GitHub App installations map to projects | **Open** |
| D4 | OIDC first, tokens as fallback (§3.3) | Proposed |
| D5 | Existing unscoped PRs stay visible to all (§4) | Proposed |

## 8. Build order

1. DynamoDB items and the `api-authorizer` with project tokens only, with
   the §6 tests.
2. Token management routes and a dashboard page (in `frontend/`).
3. Accept `cli-interactive` ID tokens in `api-authorizer`. The client and
   `cascadesec login` already exist by then: they ship earlier, on the
   Cognito JWT authorizer (cli-spec §11.1, phase H).
4. OIDC trust rules: GitHub Actions first (the testbed), then GitLab.
