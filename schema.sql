CREATE TABLE IF NOT EXISTS exchanges (
  id UUID PRIMARY KEY,
  title TEXT NOT NULL,
  fellowship TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  guidance TEXT NOT NULL DEFAULT '',
  cutoff_at TIMESTAMPTZ NOT NULL,
  exchange_at DATE NOT NULL,
  is_open BOOLEAN NOT NULL DEFAULT FALSE,
  is_closed BOOLEAN NOT NULL DEFAULT FALSE,
  is_drawn BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS eligible_members (
  id UUID PRIMARY KEY,
  exchange_id UUID NOT NULL REFERENCES exchanges(id) ON DELETE CASCADE,
  normalized_phone TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT 'Unnamed member',
  imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(exchange_id, normalized_phone)
);

CREATE TABLE IF NOT EXISTS participants (
  id UUID PRIMARY KEY,
  exchange_id UUID NOT NULL REFERENCES exchanges(id) ON DELETE CASCADE,
  eligible_member_id UUID NOT NULL REFERENCES eligible_members(id),
  display_name TEXT NOT NULL,
  normalized_phone TEXT NOT NULL,
  commitment_accepted_at TIMESTAMPTZ NOT NULL,
  registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(exchange_id, normalized_phone)
);

CREATE TABLE IF NOT EXISTS assignments (
  id UUID PRIMARY KEY,
  exchange_id UUID NOT NULL REFERENCES exchanges(id) ON DELETE CASCADE,
  giver_participant_id UUID NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
  recipient_participant_id UUID NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(exchange_id, giver_participant_id),
  UNIQUE(exchange_id, recipient_participant_id)
);

CREATE TABLE IF NOT EXISTS reveal_tokens (
  id UUID PRIMARY KEY,
  exchange_id UUID NOT NULL REFERENCES exchanges(id) ON DELETE CASCADE,
  participant_id UUID NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  token_ciphertext TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  viewed_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);

ALTER TABLE reveal_tokens ADD COLUMN IF NOT EXISTS token_ciphertext TEXT;
ALTER TABLE reveal_tokens ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE participants ADD COLUMN IF NOT EXISTS gift_hint TEXT NOT NULL DEFAULT '';
-- Anyone can register. People not on the pre-approved roster wait as 'pending' until the organizer approves them.
ALTER TABLE participants ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'approved';
ALTER TABLE participants ALTER COLUMN eligible_member_id DROP NOT NULL;

CREATE TABLE IF NOT EXISTS organizer_sessions (
  id UUID PRIMARY KEY,
  exchange_id UUID NOT NULL REFERENCES exchanges(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS organizer_login_attempts (
  id UUID PRIMARY KEY,
  ip_hash TEXT NOT NULL,
  attempted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  succeeded BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY,
  exchange_id UUID NOT NULL REFERENCES exchanges(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS eligible_members_exchange_idx ON eligible_members(exchange_id);
CREATE INDEX IF NOT EXISTS participants_exchange_idx ON participants(exchange_id);
CREATE INDEX IF NOT EXISTS reveal_tokens_hash_idx ON reveal_tokens(token_hash);
CREATE INDEX IF NOT EXISTS organizer_sessions_token_idx ON organizer_sessions(token_hash);
CREATE INDEX IF NOT EXISTS organizer_login_attempts_ip_idx ON organizer_login_attempts(ip_hash, attempted_at DESC);
