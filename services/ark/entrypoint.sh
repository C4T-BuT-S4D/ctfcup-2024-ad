#!/bin/sh

# Ensure files directory is owned by nobody
chown -R nobody:nogroup /files

cargo sqlx migrate run

# Run ark via socat as nobody
exec su -s /bin/sh nobody -c "socat TCP-LISTEN:13345,reuseaddr,fork EXEC:/ark"
