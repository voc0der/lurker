FROM oven/bun:latest
ADD ./ ./
CMD ["bun", "run", "src/index.js"]