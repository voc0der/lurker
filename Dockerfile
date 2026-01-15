FROM oven/bun:latest

# Set working directory for app files
WORKDIR /home/bun/app

# Copy application files
COPY ./ ./

# Create a directory for data
RUN mkdir -p /data

# Set default PUID and PGID
ENV PUID=1000
ENV PGID=1000

# Install gosu for privilege switching
RUN apt-get update && apt-get install -y gosu && rm -rf /var/lib/apt/lists/*

# Add entrypoint script for handling dynamic PUID/PGID
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set working directory for runtime
WORKDIR /data

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Default command
CMD ["bun", "run", "/home/bun/app/src/index.js"]
