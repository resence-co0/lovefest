# Love Feast Secret Santa

Full-stack demo for the ECWA Goodnews Dawaki Youth Fellowship Love Feast exchange.

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

Open http://localhost:4173.

The local demo organizer key is `lovefeast-demo-organizer`. The browser uses it only for this local prototype. A production deployment must replace it with real organizer authentication.

## Demo flow

1. Open **Organizer** and review the fictional eligible roster.
2. From **Participant view**, register three fictional members. Nigerian phone formats are normalized server-side.
3. Return to **Organizer**, close registration, and run the draw.
4. Copy an individual private reveal link and open it in another browser tab.

To return the database to a clean fictional state:

```bash
npm run db:reset-demo
```

## Backend

The Express API is in `server.js`. Postgres schema and setup scripts are in `schema.sql` and `scripts/`. The API enforces roster eligibility, commitment acceptance, duplicate prevention, cutoff status, one-time draw creation, hashed reveal tokens, and participant-specific reveals. The organizer state never returns assignment pairs.

The S3-compatible Neon Object Storage bucket is checked at `/api/storage/health`. The app does not currently need file uploads, so storage is wired as a health-checked service and is ready for an event banner or logo upload later.

No WhatsApp, SMS, or email API calls are made.
