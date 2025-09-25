OAuth2 single-account setup for Gmail (one-time steps)

1. In Google Cloud Console, create OAuth 2.0 credentials (Web application).
   - Set an authorized redirect URI to: http://localhost:5000/oauth2/callback (or your dev server URL)
   - Note the Client ID and Client Secret.

2. Set environment variables (locally in .env):
   GMAIL_OAUTH_CLIENT_ID=<your-client-id>
   GMAIL_OAUTH_CLIENT_SECRET=<your-client-secret>
   FROM_EMAIL=<the "from" email; must match the account you authorize>

3. Start the Flask app.

4. In your browser, visit: http://127.0.0.1:5000/oauth2/start
   - Sign in with the Gmail account you want to send from and grant Gmail Send scope.
   - After consent, the callback will store a refresh token in `gmail_oauth_token.json` in the app directory.

5. Optionally copy the refresh token into your environment as GMAIL_OAUTH_REFRESH_TOKEN or keep the token file.

Notes:
- This flow uses a single Gmail account (no domain-wide delegation). Keep the refresh token and client secret safe.
- The server exchanges the refresh token for short-lived access tokens when sending email.
- For production, store tokens securely (encrypted store or secrets manager) instead of a local file.
