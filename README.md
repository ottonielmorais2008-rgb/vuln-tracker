# Vulnerability Tracker

[![CI](https://github.com/ottonielmorais2008-rgb/vuln-tracker/actions/workflows/ci.yml/badge.svg)](https://github.com/ottonielmorais2008-rgb/vuln-tracker/actions/workflows/ci.yml)

A small web app for tracking vulnerabilities in a home lab. Record a finding, see counts by severity and status, highlight overdue work, and export a CSV.

**Live demo:** [https://LIVE_URL_PLACEHOLDER](https://LIVE_URL_PLACEHOLDER)

## What it does

- Add a finding with a title, asset or host, optional CVE id, CVSS score, status, owner, due date and notes.
- Severity (Critical, High, Medium, Low) is derived automatically from the CVSS score.
- The dashboard shows counts by severity and status, and highlights overdue items.
- Search, filter and sort the list, then export the visible rows as CSV.
- The public demo starts with fictional lab hosts such as `nas-01`, `router` and `pi-hole`. Demo data stays in the browser until you sign in.
- Sign in with email, or continue as a guest when anonymous sign-in is enabled, to store findings in Supabase. Each signed-in user only sees their own rows.

## Data model

Each vulnerability has:

- `title`, `asset`, optional `cve_id`, `cvss`, derived `severity`
- `status`: Open, In progress, Mitigated, or Accepted risk
- `owner`, optional `due_date`, `notes`
- `created_at` and `updated_at`

A finding is overdue when its due date is in the past and its status is still Open or In progress.

CVSS mapping: 0.0–3.9 Low, 4.0–6.9 Medium, 7.0–8.9 High, 9.0–10.0 Critical. A CVE id, when present, must match `CVE-YYYY-NNNN` (at least four digits at the end).

## Security notes

The `vulnerabilities` table has Row Level Security enabled. Policies allow the `authenticated` role to read and change a row only when `user_id` matches the current user. The `anon` role has no table grants.

The browser only uses the public Supabase URL and the publishable (anon) key. No service-role key is included in the app or this repository.

Hosted Supabase projects confirm emails by default, and this project has no custom SMTP. A database trigger auto-confirms new users so sign-up works without waiting for a confirmation email. This is fine for a public demo, but it means email addresses are not verified.

If Supabase is not configured, the app falls back to a `localStorage` repository behind the same storage interface.

## Stack

- React, TypeScript, and Vite
- Supabase Auth and Postgres, with a `localStorage` fallback
- Vitest, with GitHub Actions running typecheck, tests, and the production build
- Deployed on Vercel

## Tests and CI

GitHub Actions runs typechecking, the Vitest suite, and the production build on every push and pull request. The tests cover:

- CVSS to severity mapping and score parsing
- CVE id validation and normalisation
- Overdue logic, including mitigated and accepted items
- Search, filters, sorting and dashboard counts
- CSV export, including escaped commas, quotes and newlines
- The local storage layer: seeding, create, update, delete and validation

## Run locally

```bash
cp .env.example .env.local
# set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY
npm ci
npm test
npm run dev
```

The dev server listens on `http://127.0.0.1:5173/`. Use that address only when running the app on your own machine; the public demo is the live link above.

## License

MIT
