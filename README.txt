PUREHAI — Water Supplier Management (Express + MongoDB)

Requirements:
- Node.js 18+ and npm
- MongoDB Community Server running locally, or a MongoDB Atlas connection string

First-time setup:
1. Copy .env.example to .env.
2. SESSION_SECRET is optional. Set it to a private random value at least 32
   characters long to keep login sessions active across server restarts.
3. Optionally set LOGIN_RESET_KEY to a different private random value at least
   32 characters long. This enables the Forgot ID/password option.
4. Keep .env private; do not commit or share it.

Run in VS Code terminal:
1. Open the PUREHAI folder in VS Code.
2. Make sure MongoDB is running on your computer.
3. Install backend packages:
   npm install
4. Start the app:
   npm start
5. Open this URL in your browser:
   http://localhost:5000
6. On first use, create a username and password on the setup screen. The
   password is stored as a salted hash in MongoDB; later logins use that ID and
   password.

Important:
- Do not use Live Server for this version. Express serves the frontend and API together.
- Default database: purehai
- MongoDB local URI: mongodb://127.0.0.1:27017/purehai
- API health check: http://localhost:5000/api/health
- API data endpoint: http://localhost:5000/api/data (login required)
- Use the Logout button to end a session. Sessions expire after 12 hours by
  default, or after 30 days when “remember this device” is selected.
- The login screen's “remember this device” option keeps the signed-in session
  active for 30 days and remembers only the username on that device. The app
  never stores the password in browser storage; use your browser's password
  manager if you want it to fill the password for you.
- Without SESSION_SECRET, active sessions end whenever the server restarts.
- Forgot ID/password requires the LOGIN_RESET_KEY configured by the server
  administrator. Without this key, the administrator must reset the login
  credentials directly in MongoDB.
- Saving new credentials invalidates previous login sessions.
- For public production deployment, use HTTPS and configure NODE_ENV=production
  so the login cookie is Secure.
- The current save endpoint replaces the whole data snapshot and is suitable
  for a single owner using one browser at a time.
