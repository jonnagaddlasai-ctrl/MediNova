# Health Hub — Email and Password Login

## Important architecture note
GitHub Pages only hosts static files and cannot run this Node.js backend. Deploy this project as a Node.js web service (or deploy `server.js` and `package.json` to a compatible backend host), and point GitHub Pages to that backend using `public/hh-config.js`.

## Run locally
1. Install Node.js 20+.
2. Copy `.env.example` to `.env`.
3. Set `SESSION_SECRET` to a long random secret (at least 32 characters).
4. Run `npm install` then `npm start`.
5. Open `http://localhost:3000`.

## Use GitHub Pages frontend with a separately hosted backend
1. Deploy this Node.js project as a web service. Set environment variables on the host: `NODE_ENV=production`, `SESSION_SECRET` (32+ random characters), and `FRONTEND_ORIGIN` (the exact origin of your GitHub Pages site, e.g. `https://username.github.io`).
2. In `public/hh-config.js`, set `window.HH_API_BASE = 'https://YOUR-BACKEND-HOST';` (no trailing slash). Commit and push the updated `public` files to GitHub Pages.
3. Make sure your host supports HTTPS and persistent storage for `data/users.sqlite` and `data/sessions.sqlite`. Ephemeral storage may erase accounts/sessions on redeploy or restart; use a persistent disk or managed database for production.
4. Test `/api/health` on the backend host; it should return JSON with `ok: true`.

## Account behavior
- New users must select “Create an account” and register first. Existing users select “Sign in”.
- Passwords must be 12–128 characters and include at least one uppercase letter, one lowercase letter, and one number.
- Passwords are hashed with bcrypt. Login is not possible until the backend is deployed and reachable.
- Password reset and email verification are not implemented in this starter.

## Security reminders
Never put backend secrets in frontend JavaScript or GitHub. Use HTTPS. Configure `FRONTEND_ORIGIN` to one exact trusted origin. This is a starter, not a substitute for a security review before storing sensitive health data.
