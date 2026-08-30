SATYAM WITH ME - LIVE DEPLOYMENT

1. Upload this project to a Node.js hosting service that supports persistent storage.
2. Build command: npm install
3. Start command: npm start
4. Add the variables from .env.example in the hosting service's Environment Variables.
5. Do NOT upload or share your real Gmail password or App Password.
6. After deployment, the hosting service gives you a public HTTPS URL.

IMPORTANT:
For real public cloud storage, local uploads/SQLite may be temporary on some hosts.
Use a persistent disk and database, or move uploads to object storage before production use.

6. Recommended OTP setup on Render: create a Resend account, create an API key, then add
   RESEND_API_KEY and RESEND_FROM as Render Environment Variables. RESEND_FROM must be a
   sender address/domain allowed by your Resend account. Keep the API key secret.
7. After adding the variables, deploy the latest commit and test Registration -> Send OTP.
