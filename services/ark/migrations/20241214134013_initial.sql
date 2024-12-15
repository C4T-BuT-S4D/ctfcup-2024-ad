-- Add migration script here

DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS files CASCADE;

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    quota_used INTEGER DEFAULT 0 NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS users_created_at_idx ON users (created_at DESC);

CREATE TABLE IF NOT EXISTS files (
    id SERIAL PRIMARY KEY,
    owner_id INTEGER REFERENCES users(id) NOT NULL,
    quota_id INTEGER REFERENCES users(id) NOT NULL,
    path VARCHAR(1024) UNIQUE NOT NULL,
    size INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS files_owner_id_idx ON files (owner_id, created_at);
CREATE INDEX IF NOT EXISTS files_quota_id_idx ON files (quota_id, created_at);
CREATE INDEX IF NOT EXISTS files_created_at_idx ON files (created_at DESC);