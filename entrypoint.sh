#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Create group if it doesn't exist
if ! getent group ${PGID} > /dev/null 2>&1; then
    groupadd -g ${PGID} appgroup
fi

# Create user if it doesn't exist
if ! id -u ${PUID} > /dev/null 2>&1; then
    useradd -u ${PUID} -g ${PGID} -m appuser
fi

# Change ownership of the application directory
chown -R ${PUID}:${PGID} /data /home/bun/app

# Switch to the new user, cd to app directory, and execute the command
cd /home/bun/app
exec gosu ${PUID}:${PGID} "$@"
