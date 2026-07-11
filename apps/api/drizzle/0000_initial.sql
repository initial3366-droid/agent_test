BEGIN;

DO $$ BEGIN CREATE TYPE role AS ENUM ('user', 'admin'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE user_status AS ENUM ('active', 'disabled'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE device_platform AS ENUM ('windows', 'macos'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE provider_kind AS ENUM ('openai', 'anthropic', 'openai-compatible'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE task_status AS ENUM ('running', 'completed', 'failed', 'cancelled'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL UNIQUE,
  role role NOT NULL DEFAULT 'user',
  status user_status NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz
);
CREATE INDEX IF NOT EXISTS users_created_at_idx ON users (created_at);

CREATE TABLE IF NOT EXISTS login_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,
  code_hash text NOT NULL,
  request_ip_hash text NOT NULL,
  registration_allowed boolean NOT NULL DEFAULT false,
  attempts integer NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT login_codes_attempts_nonnegative CHECK (attempts >= 0)
);
CREATE INDEX IF NOT EXISTS login_codes_email_created_idx ON login_codes (email, created_at);
CREATE INDEX IF NOT EXISTS login_codes_ip_created_idx ON login_codes (request_ip_hash, created_at);
CREATE INDEX IF NOT EXISTS login_codes_expires_at_idx ON login_codes (expires_at);

CREATE TABLE IF NOT EXISTS devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  platform device_platform NOT NULL,
  version text NOT NULL,
  key_configured boolean NOT NULL DEFAULT false,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS devices_user_id_id_unique ON devices (user_id, id);
CREATE INDEX IF NOT EXISTS devices_user_last_seen_idx ON devices (user_id, last_seen_at);

CREATE TABLE IF NOT EXISTS model_configs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id uuid NOT NULL,
  name text NOT NULL,
  kind provider_kind NOT NULL,
  base_url text NOT NULL,
  model text NOT NULL,
  context_window integer NOT NULL,
  is_default boolean NOT NULL DEFAULT false,
  key_last_four text,
  key_fingerprint text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT model_configs_owned_device_fk FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, id) ON DELETE CASCADE,
  CONSTRAINT model_configs_context_window_positive CHECK (context_window > 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS model_configs_one_default_per_user ON model_configs (user_id) WHERE is_default = true;
CREATE INDEX IF NOT EXISTS model_configs_user_created_idx ON model_configs (user_id, created_at);

CREATE TABLE IF NOT EXISTS tasks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id uuid NOT NULL,
  idempotency_key text,
  workspace_name text NOT NULL,
  status task_status NOT NULL,
  model text NOT NULL,
  input_tokens integer NOT NULL DEFAULT 0,
  output_tokens integer NOT NULL DEFAULT 0,
  duration_ms integer,
  error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  CONSTRAINT tasks_owned_device_fk FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, id),
  CONSTRAINT tasks_input_tokens_nonnegative CHECK (input_tokens >= 0),
  CONSTRAINT tasks_output_tokens_nonnegative CHECK (output_tokens >= 0),
  CONSTRAINT tasks_duration_nonnegative CHECK (duration_ms IS NULL OR duration_ms >= 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS tasks_user_idempotency_unique ON tasks (user_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS tasks_user_created_idx ON tasks (user_id, created_at);

CREATE TABLE IF NOT EXISTS audits (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
  device_id uuid REFERENCES devices(id) ON DELETE SET NULL,
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audits_created_at_idx ON audits (created_at);
CREATE INDEX IF NOT EXISTS audits_user_created_idx ON audits (user_id, created_at);
CREATE INDEX IF NOT EXISTS audits_actor_created_idx ON audits (actor_id, created_at);

CREATE TABLE IF NOT EXISTS settings (
  key text PRIMARY KEY,
  value jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

COMMIT;
