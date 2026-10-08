PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  prf_salt BLOB NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  burn INTEGER NOT NULL DEFAULT 0,
  consumed_at INTEGER,
  owner_account_id TEXT,
  pass_salt BLOB,
  pass_verifier TEXT
);

CREATE TABLE IF NOT EXISTS reverse_shares (
  id TEXT PRIMARY KEY,
  lsug TEXT NOT NULL UNIQUE,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS reverse_wraps (
  reverse_share_id TEXT NOT NULL REFERENCES reverse_shares(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
  nonce BLOB NOT NULL,
  wrapped BLOB NOT NULL,
  PRIMARY KEY (reverse_share_id, credential_id)
);

CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  share_id TEXT REFERENCES shares(id) ON DELETE CASCADE,
  reverse_share_id TEXT REFERENCES reverse_shares(id) ON DELETE CASCADE,
  idx INTEGER NOT NULL DEFAULT 0,
  name TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  blob TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_shares_owner ON shares(owner_account_id);
CREATE INDEX IF NOT EXISTS idx_shares_expiry ON shares(expires_at);
CREATE INDEX IF NOT EXISTS idx_files_share ON files(share_id);
CREATE INDEX IF NOT EXISTS idx_files_reverse ON files(reverse_share_id);
