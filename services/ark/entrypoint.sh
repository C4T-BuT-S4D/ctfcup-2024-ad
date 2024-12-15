#!/bin/sh

# Add ark user and group
addgroup ark
adduser --no-create-home --disabled-password --gecos '' --ingroup ark ark

# Create and set permissions on files directory
chown -R ark:ark /files
chmod 700 /files

cargo sqlx migrate run

su ark -c "/ark"
