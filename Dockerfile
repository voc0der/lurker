FROM oven/bun:latest

# Copy application files
ADD ./ ./

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

# Set working directory
WORKDIR /data

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Default command
CMD ["bun", "run", "/home/bun/app/src/index.js"]
