const LOG_LEVEL = process.env.LOG_LEVEL || 'info';

const LEVELS = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3
};

function shouldLog(level) {
  return LEVELS[level] >= LEVELS[LOG_LEVEL];
}

function debug(...args) {
  if (shouldLog('debug')) {
    console.log('[DEBUG]', ...args);
  }
}

function info(...args) {
  if (shouldLog('info')) {
    console.log('[INFO]', ...args);
  }
}

function warn(...args) {
  if (shouldLog('warn')) {
    console.warn('[WARN]', ...args);
  }
}

function error(...args) {
  if (shouldLog('error')) {
    console.error('[ERROR]', ...args);
  }
}

module.exports = { debug, info, warn, error };
