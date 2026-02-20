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

function sanitizeControlChars(value) {
  return String(value).replace(/[\r\n\t]/g, (ch) => {
    if (ch === '\r') return '\\r';
    if (ch === '\n') return '\\n';
    return '\\t';
  });
}

function serializeArg(arg) {
  if (arg instanceof Error) {
    return sanitizeControlChars(
      JSON.stringify({
        name: arg.name,
        message: arg.message,
        stack: arg.stack,
      }),
    );
  }

  if (typeof arg === 'string') {
    return sanitizeControlChars(arg);
  }

  if (arg === undefined) {
    return 'undefined';
  }

  if (arg === null) {
    return 'null';
  }

  if (typeof arg === 'number' || typeof arg === 'boolean' || typeof arg === 'bigint') {
    return String(arg);
  }

  try {
    return sanitizeControlChars(JSON.stringify(arg));
  } catch {
    return '[unserializable]';
  }
}

function writeLog(level, consoleMethod, args) {
  if (!shouldLog(level)) return;
  const message = args.map((arg) => serializeArg(arg)).join(' ');
  console[consoleMethod](`[${level.toUpperCase()}] ${message}`);
}

function debug(...args) {
  writeLog('debug', 'log', args);
}

function info(...args) {
  writeLog('info', 'log', args);
}

function warn(...args) {
  writeLog('warn', 'warn', args);
}

function error(...args) {
  writeLog('error', 'error', args);
}

module.exports = { debug, info, warn, error };
