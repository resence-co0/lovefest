# Love Feast Secret Santa

Full-stack registration and private assignment app for the ECWA Goodnews Dawaki Youth Fellowship Love Feast exchange.

## Local setup

1. Copy `.env.example` to `.env.local` and provide the Neon Postgres and S3-compatible storage variables.
2. Install dependencies:

```bash
npm install
```

3. Create the database schema and fictional roster:

```bash
npm run db:setup
npm run db:seed
```

4. Start the app:

```bash
npm start
```

Open http://localhost:4173. The organizer workspace is available at http://localhost:4173/organizer and requires the password configured in `ORGANIZER_PASSWORD`.

## Demo flow

1. Sign in to **Organizer** and review the eligible roster.
2. From **Participant view**, register three fictional members. Nigerian phone formats are normalized server-side. Members can leave an optional gift hint (up to 280 characters), which only their Secret Santa sees on the reveal.
3. Return to **Organizer**, close registration, and run the draw.
4. Send each private reveal link with its **WhatsApp** button (or copy it) and open it in another browser tab. Links can be recovered after a refresh, revoked, or replaced without changing the assignment.
5. If someone drops out, remove them from the participant list. Before the draw they simply leave the list. After the draw, the person who was buying for them takes over their recipient, so only that one giver's match changes; their existing link shows the new match and is marked unopened again.

Opening a reveal link while signed in as the organizer shows an "Organizer preview" banner and does not count as the participant opening it.

Registration dates are entered and shown in Africa/Lagos time. Sign-ups stop automatically at the cutoff, even before you close registration.

To return the database to a clean fictional state:

```bash
npm run db:reset-demo
```

## Backend

The Express API is in `server.js`. Postgres schema and setup scripts are in `schema.sql` and `scripts/`. The API enforces roster eligibility, commitment acceptance, duplicate prevention, cutoff status, transactional one-time draw creation, encrypted recoverable reveal tokens, expiry, revocation, and participant-specific reveals, and participant removal that repairs the gift ring. The organizer uses an eight-hour HttpOnly server session. Assignment pairs are never returned by organizer-state endpoints, although the organizer can open any participant's private link.

Private tokens stay in the URL fragment, so they are not sent in ordinary page requests or referrer headers. The browser submits a token to the reveal API only when the participant opens the link.

The S3-compatible Neon Object Storage bucket is checked at `/api/storage/health`. The app does not currently need file uploads, so storage is wired as a health-checked service and is ready for an event banner or logo upload later.

No WhatsApp, SMS, or email API calls are made.
# lovefest
