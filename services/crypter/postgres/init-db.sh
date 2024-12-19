#!/bin/sh

psql --username crypter --dbname crypter  <<-EOSQL
        CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(64) PRIMARY KEY,
		username VARCHAR(64) UNIQUE NOT NULL,
		token VARCHAR(64) UNIQUE NOT NULL,
		n VARCHAR NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
		id VARCHAR(64) PRIMARY KEY,
		username VARCHAR(64) NOT NULL,
		from_username VARCHAR(64) NOT NULL,
		encrypted VARCHAR NOT NULL
        );
EOSQL
