# POS & Customer Loyalty — Render + PostgreSQL

This deployment package keeps the existing Flask POS screens and application features, while switching persistence to PostgreSQL. No UI redesign is included.

## Deploy to Render

1. Upload this folder to a GitHub repository.
2. In Render, choose **New → Blueprint** and connect the repository containing `render.yaml`.
3. Render creates the web service and PostgreSQL database. Confirm the database and service are in the same Render workspace/region.
4. After deployment, open the service URL. `/health` should return `{"status":"ok","database":"postgresql"}`.
5. Set a strong `INITIAL_SUPERADMIN_PASSWORD` (at least 12 characters) in the Render service environment before first startup. The initial username is `superadmin`; there is no hard-coded default password.

## Manual deployment

- Build: `pip install -r requirements.txt`
- Start: `gunicorn POS:app --workers 1 --threads 4 --timeout 120`
- Set `DATABASE_URL`, `POS_SECRET_KEY`, and `INITIAL_SUPERADMIN_PASSWORD` (at least 12 characters) before the first startup. Keep these secrets out of source control.

## Notes

- The app initializes its tables on startup. PostgreSQL must be reachable before the service starts.
- This package does not migrate records from the previous SQLite `.db` file. Export/import business data separately before switching a live installation.
- Keep `DATABASE_URL` and `POS_SECRET_KEY` private. Never commit a real `.env` file.

## Security hardening included

- Removes the hard-coded default superadmin password; requires a separately configured initial password when creating the first superadmin.
- Adds CSRF tokens to existing HTML forms without redesigning the screens, and rejects POST requests without a valid token.
- Adds process-local login throttling (8 attempts per IP per 15 minutes); the current Render configuration intentionally uses one Gunicorn worker for this limiter.
- Enables HttpOnly/SameSite cookies, Secure cookies on Render/HTTPS deployments, an 8-hour session lifetime, request-size/form limits, security response headers, CSP, and no-store caching for HTML.
- Converts logout to a CSRF-protected POST request.

## CSV import/export hardening

- Uploads remain limited to 10 MiB and are parsed in memory without saving untrusted files to disk.
- Import requires the exact four expected columns, rejects duplicate/blank headers and malformed rows, and uses strict UTF-8/CSV parsing.
- Caps field sizes, product/category text lengths, numeric input lengths, price and stock ranges, and imports at 5,000 data rows.
- Rejects duplicate product names within the same import file and validates every row before inserting any rows (all-or-nothing import behavior).
- Uses parameterized database inserts; uploaded values are never interpreted as SQL.
- Sales and loyalty CSV exports neutralize spreadsheet formula-leading text in customer/product/date fields to reduce CSV formula injection risk.

## Important limitations

Security cannot be guaranteed by code alone. Use HTTPS, strong unique secrets, restricted PostgreSQL credentials/network access, regular dependency updates, database backups, and least-privilege access. The login limiter is in-memory and resets on restart; for multiple workers/instances, replace it with a shared Redis-backed limiter. Test all workflows in staging before production. This package has passed Python syntax and targeted CSV-safety checks, but a live hostile-input/security penetration test and full PostgreSQL end-to-end test have not been performed.
