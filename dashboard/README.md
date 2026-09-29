# IaCPosture Review Dashboard

React + Vite + TypeScript frontend for human review of scan findings and proposed fixes.

The dashboard talks to the `review-api` Lambda via API Gateway HTTP API. It does not call the scanner, mapping, or remediation Lambdas directly.

## Setup

```bash
cd dashboard
npm install
cp .env.example .env
# Edit .env — VITE_API_BASE_URL, VITE_COGNITO_DOMAIN, VITE_COGNITO_CLIENT_ID,
# all printed by:
#   terraform output
npm run dev
```

Open http://localhost:5173. You'll be redirected to the Cognito Hosted UI to
sign in — reviewer accounts are created out of band, there is no
self-registration:

```bash
aws cognito-idp admin-create-user \
  --user-pool-id "$(terraform output -raw cognito_user_pool_id)" \
  --username you@example.com \
  --user-attributes Name=email,Value=you@example.com Name=email_verified,Value=true
```

Cognito emails a temporary password; the Hosted UI prompts for a permanent one
on first sign-in. After that, enter a PR ID (e.g. `manual-test-1`) and review
findings.

Committing approved fixes to a GitHub PR's branch (v4,
[`docs/write-back-spec.md`](../docs/write-back-spec.md)) needs membership of
the `committers` group; approving does not. The group claim is issued at
sign-in, so sign in again afterwards:

```bash
aws cognito-idp admin-add-user-to-group \
  --user-pool-id "$(terraform output -raw cognito_user_pool_id)" \
  --username you@example.com --group-name committers
```

## API routes consumed

| Method | Path | Use |
|--------|------|-----|
| GET | `/prs/{pr_id}/findings` | List all findings for a PR |
| GET | `/prs/{pr_id}/findings/{finding_id}` | Finding detail + proposed diff |
| GET | `/prs/{pr_id}/findings/{finding_id}/events` | Audit trail |
| POST | `/prs/{pr_id}/findings/{finding_id}/review` | Approve / edit / reject |
| GET | `/prs/{pr_id}/commit-plan` | What committing a GitHub PR's approved fixes would do, per file |
| POST | `/prs/{pr_id}/commits` | Ask for that commit (`committers` group only) |
| GET | `/prs/{pr_id}/commits/{request_id}` | A commit request's status |

## Build for static hosting

```bash
npm run build
```

Output goes to `dist/` — ready for S3 + CloudFront when infra is added.

## Auth

Every API route sits behind a Cognito JWT authorizer (see `terraform/cognito.tf`
and `terraform/api_gateway.tf`). The dashboard signs in through the Hosted UI
with authorization-code + PKCE (`src/auth/`) and sends the ID token as a bearer
token on every request. The reviewer attributed in the audit trail comes from
the token's verified claims, not from anything the browser sends in the request
body -- see `_actor_from_claims` in `lambda/review-api/handler.py`.

CORS and the Hosted UI's callback/logout URLs both derive from
`dashboard_extra_origins` plus the CloudFront domain (`terraform/cognito.tf`
locals); they can't drift apart.

## Project structure

```
src/
├── api/client.ts          # Typed fetch wrapper, attaches the bearer token
├── auth/                  # Cognito Hosted UI login (PKCE), token storage
├── types/finding.ts       # FindingRecord + ReviewEvent types
├── components/            # UI pieces (table, diff, review form, audit)
└── pages/                 # Home, PR list, finding detail
```
