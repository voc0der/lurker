FROM oven/bun:latest

# Copy application files (default WORKDIR in oven/bun is /home/bun/app)
ADD ./ ./

# Install dependencies
RUN bun install

# Create a directory for data
RUN mkdir -p /data

# Set default PUID and PGID
ENV PUID=1000
ENV PGID=1000

# Install gosu for privilege switching
RUN apt-get update && apt-get install -y gosu && rm -rf /var/lib/apt/lists/*

# Add entrypoint script for handling dynamic PUID/PGID
ADD entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Keep working directory as /home/bun/app so bun can find modules
# The entrypoint will cd to /data if needed
WORKDIR /home/bun/app

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Default command
CMD ["bun", "run", "src/index.js"]
