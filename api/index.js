
'use strict';

const { Pool } = require('pg');
const crypto = require('crypto');

const connectionString =
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL ||
  process.env.POSTGRES_PRISMA_URL ||
  process.env.POSTGRES_URL_NON_POOLING;

const SECRET = process.env.JWT_SECRET;
const MAX_BODY = 1000000;
const MAX_DATA = 800000;
const TOKEN_SECONDS = 30 * 24 * 60 * 60;
const MAX_ATTEMPTS = 10;
const LOCK_MINUTES = 15;

const EMPTY = {
  goods: [],
  sales: [],
  buys: [],
  costs: [],
  payments: []
};

const allowedOrigins = new Set([
  'https://yazdanmadadiafghanicoin.github.io'
]);

const pool = connectionString
  ? new Pool({
      connectionString,
      ssl: { rejectUnauthorized: false },
      max: 3,
      idleTimeoutMillis: 10000,
      connectionTimeoutMillis: 10000
    })
  : null;

let schemaReady;

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

function b64url(value) {
  return Buffer.from(value)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function sign(payload) {
  const head = b64url(JSON.stringify({
    alg: 'HS256',
    typ: 'JWT'
  }));

  const body = b64url(JSON.stringify(payload));
  const data = `${head}.${body}`;

  const signature = crypto
    .createHmac('sha256', SECRET)
    .update(data)
    .digest();

  return `${data}.${signature.toString('base64url')}`;
}

function verify(token) {
  if (!token || !SECRET || typeof token !== 'string') return null;

  const parts = token.split('.');
  if (parts.length !== 3) return null;

  let header;
  let payload;

  try {
    header = JSON.parse(
      Buffer.from(parts[0], 'base64url').toString('utf8')
    );

    payload = JSON.parse(
      Buffer.from(parts[1], 'base64url').toString('utf8')
    );
  } catch {
    return null;
  }

  if (header.alg !== 'HS256' || header.typ !== 'JWT') return null;

  const data = `${parts[0]}.${parts[1]}`;
  const expected = crypto
    .createHmac('sha256', SECRET)
    .update(data)
    .digest();

  let actual;

  try {
    actual = Buffer.from(parts[2], 'base64url');
  } catch {
    return null;
  }

  if (
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  if (
    typeof payload.sub !== 'string' ||
    !/^[1-9]\d*$/.test(payload.sub) ||
    !Number.isSafeInteger(payload.exp) ||
    payload.exp <= now
  ) {
    return null;
  }

  return payload;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function passwordMatches(password, salt, hash) {
  try {
    const actual = crypto.scryptSync(password, salt, 64);
    const expected = Buffer.from(hash, 'hex');

    return actual.length === expected.length &&
      crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

async function ensureSchema() {
  if (!pool) {
    throw new Error('اتصال دیتابیس تنظیم نشده است.');
  }

  if (!schemaReady) {
    schemaReady = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS hy_users (
          id BIGSERIAL PRIMARY KEY,
          username TEXT NOT NULL,
          username_lower TEXT NOT NULL UNIQUE,
          password_salt TEXT NOT NULL,
          password_hash TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS hy_user_data (
          user_id BIGINT PRIMARY KEY
            REFERENCES hy_users(id) ON DELETE CASCADE,
          data JSONB NOT NULL DEFAULT
            '{"goods":[],"sales":[],"buys":[],"costs":[],"payments":[]}'::jsonb,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS hy_login_limits (
          username_lower TEXT PRIMARY KEY,
          window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          attempts INTEGER NOT NULL DEFAULT 0,
          locked_until TIMESTAMPTZ
        )
      `);
    })().catch(err => {
      schemaReady = null;
      throw err;
    });
  }

  await schemaReady;
}

function getRoute(req) {
  const url = new URL(req.url, 'http://localhost');
  const queryPath = url.searchParams.get('path');

  if (queryPath) {
    return '/' + queryPath.split('/').filter(Boolean).join('/');
  }

  const pathname = url.pathname.replace(/\/$/, '');

  if (pathname === '/api' || pathname === '/api/index') return '/';
  if (pathname.startsWith('/api/')) return pathname.slice(4);

  return pathname || '/';
}

async function readBody(req) {
  if (req.body && typeof req.body === 'object') {
    const size = Buffer.byteLength(JSON.stringify(req.body));
    if (size > MAX_BODY) throw new Error('درخواست بسیار بزرگ است.');
    return req.body;
  }

  let raw = '';

  for await (const chunk of req) {
    raw += chunk;

    if (Buffer.byteLength(raw) > MAX_BODY) {
      throw new Error('درخواست بسیار بزرگ است.');
    }
  }

  if (!raw) return {};

  try {
    return JSON.parse(raw);
  } catch {
    throw new Error('دادهٔ ارسالی JSON معتبر نیست.');
  }
}

function getToken(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return '';
  return header.slice(7);
}

function validData(data) {
  if (
    !data ||
    typeof data !== 'object' ||
    Array.isArray(data)
  ) {
    return false;
  }

  const keys = ['goods', 'sales', 'buys', 'costs', 'payments'];

  if (!keys.every(key => Array.isArray(data[key]))) return false;

  try {
    return Buffer.byteLength(JSON.stringify(data)) <= MAX_DATA;
  } catch {
    return false;
  }
}

async function isLoginLocked(usernameLower) {
  const result = await pool.query(
    `SELECT locked_until
     FROM hy_login_limits
     WHERE username_lower = $1`,
    [usernameLower]
  );

  const until = result.rows[0]?.locked_until;

  return Boolean(until && new Date(until).getTime() > Date.now());
}

async function recordFailedLogin(usernameLower) {
  const result = await pool.query(
    `INSERT INTO hy_login_limits
       (username_lower, window_started_at, attempts, locked_until)
     VALUES ($1, NOW(), 1, NULL)
     ON CONFLICT (username_lower)
     DO UPDATE SET
       attempts = CASE
         WHEN hy_login_limits.window_started_at
              < NOW() - INTERVAL '15 minutes'
         THEN 1
         ELSE hy_login_limits.attempts + 1
       END,
       window_started_at = CASE
         WHEN hy_login_limits.window_started_at
              < NOW() - INTERVAL '15 minutes'
         THEN NOW()
         ELSE hy_login_limits.window_started_at
       END,
       locked_until = CASE
         WHEN hy_login_limits.window_started_at
              < NOW() - INTERVAL '15 minutes'
         THEN NULL
         WHEN hy_login_limits.attempts + 1 >= $2
         THEN NOW() + INTERVAL '15 minutes'
         ELSE hy_login_limits.locked_until
       END
     RETURNING attempts, locked_until`,
    [usernameLower, MAX_ATTEMPTS]
  );

  return result.rows[0];
}

async function clearLoginFailures(usernameLower) {
  await pool.query(
    'DELETE FROM hy_login_limits WHERE username_lower = $1',
    [usernameLower]
  );
}

async function createUser(username, password) {
  const { salt, hash } = hashPassword(password);
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const result = await client.query(
      `INSERT INTO hy_users
         (username, username_lower, password_salt, password_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username`,
      [username, username.toLowerCase(), salt, hash]
    );

    const user = result.rows[0];

    await client.query(
      `INSERT INTO hy_user_data(user_id, data)
       VALUES ($1, $2::jsonb)`,
      [user.id, JSON.stringify(EMPTY)]
    );

    await client.query('COMMIT');
    return user;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

function createToken(user) {
  const now = Math.floor(Date.now() / 1000);

  return sign({
    sub: String(user.id),
    iat: now,
    exp: now + TOKEN_SECONDS
  });
}

module.exports = async (req, res) => {
  const origin = req.headers.origin;

  if (origin && allowedOrigins.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization'
  );

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  const route = getRoute(req);

  if (route === '/' && req.method === 'GET') {
    return send(res, 200, {
      success: true,
      service: 'Hesabyar Dokan API',
      message: 'API حساب‌یار دوکان فعال است.'
    });
  }

  if (origin && !allowedOrigins.has(origin)) {
    return send(res, 403, {
      error: 'این مبدأ اجازهٔ دسترسی ندارد.'
    });
  }

  if (!pool) {
    return send(res, 500, {
      error: 'متغیر اتصال دیتابیس در Vercel تنظیم نشده است.'
    });
  }

  if (!SECRET || SECRET.length < 32) {
    return send(res, 500, {
      error: 'JWT_SECRET باید حداقل ۳۲ حرف تصادفی داشته باشد.'
    });
  }

  try {
    await ensureSchema();

    if (route === '/register' && req.method === 'POST') {
      const body = await readBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');

      if (!/^[A-Za-z0-9_]{3,40}$/.test(username)) {
        return send(res, 400, {
          error: 'نام کاربری باید ۳ تا ۴۰ حرف انگلیسی، عدد یا _ باشد.'
        });
      }

      if (password.length < 8 || password.length > 200) {
        return send(res, 400, {
          error: 'رمز عبور باید بین ۸ تا ۲۰۰ حرف باشد.'
        });
      }

      let user;

      try {
        user = await createUser(username, password);
      } catch (err) {
        if (err.code === '23505') {
          return send(res, 409, {
            error: 'این نام کاربری قبلاً ثبت شده است.'
          });
        }

        throw err;
      }

      return send(res, 201, {
        token: createToken(user),
        user: { username: user.username }
      });
    }

    if (route === '/login' && req.method === 'POST') {
      const body = await readBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');

      if (
        !/^[A-Za-z0-9_]{3,40}$/.test(username) ||
        !password ||
        password.length > 200
      ) {
        return send(res, 400, {
          error: 'نام کاربری یا رمز عبور معتبر نیست.'
        });
      }

      const usernameLower = username.toLowerCase();

      if (await isLoginLocked(usernameLower)) {
        return send(res, 429, {
          error: 'تلاش‌های ورود زیاد است. ۱۵ دقیقه بعد دوباره امتحان کن.'
        });
      }

      const result = await pool.query(
        `SELECT id, username, password_salt, password_hash
         FROM hy_users
         WHERE username_lower = $1`,
        [usernameLower]
      );

      const user = result.rows[0];

      const matches = user
        ? passwordMatches(password, user.password_salt, user.password_hash)
        : false;

      if (!matches) {
        const failure = await recordFailedLogin(usernameLower);

        if (
          failure.locked_until &&
          new Date(failure.locked_until).getTime() > Date.now()
        ) {
          return send(res, 429, {
            error: 'تلاش‌های ناموفق زیاد شد. ۱۵ دقیقه بعد دوباره امتحان کن.'
          });
        }

        return send(res, 401, {
          error: 'نام کاربری یا رمز عبور نادرست است.'
        });
      }

      await clearLoginFailures(usernameLower);

      return send(res, 200, {
        token: createToken(user),
        user: { username: user.username }
      });
    }

    if (route === '/me' || route === '/data') {
      if (!['GET', 'PUT'].includes(req.method)) {
        return send(res, 405, {
          error: 'روش درخواست پشتیبانی نمی‌شود.'
        });
      }

      if (route === '/me' && req.method !== 'GET') {
        return send(res, 405, {
          error: 'روش درخواست پشتیبانی نمی‌شود.'
        });
      }

      const payload = verify(getToken(req));

      if (!payload) {
        return send(res, 401, {
          error: 'نشست ورود معتبر نیست؛ دوباره وارد شو.'
        });
      }

      const userResult = await pool.query(
        'SELECT id, username FROM hy_users WHERE id = $1',
        [payload.sub]
      );

      const user = userResult.rows[0];

      if (!user) {
        return send(res, 401, {
          error: 'حساب یافت نشد؛ دوباره وارد شو.'
        });
      }

      if (route === '/me') {
        return send(res, 200, {
          user: { username: user.username }
        });
      }

      if (req.method === 'GET') {
        const result = await pool.query(
          'SELECT data FROM hy_user_data WHERE user_id = $1',
          [user.id]
        );

        return send(res, 200, {
          data: result.rows[0]?.data || EMPTY
        });
      }

      const body = await readBody(req);

      if (!validData(body.data)) {
        return send(res, 400, {
          error: 'ساختار اطلاعات معتبر نیست یا حجم آن زیاد است.'
        });
      }

      await pool.query(
        `INSERT INTO hy_user_data(user_id, data, updated_at)
         VALUES ($1, $2::jsonb, NOW())
         ON CONFLICT (user_id)
         DO UPDATE SET
           data = EXCLUDED.data,
           updated_at = NOW()`,
        [user.id, JSON.stringify(body.data)]
      );

      return send(res, 200, {
        success: true,
        message: 'اطلاعات ذخیره شد.'
      });
    }

    return send(res, 404, {
      error: 'مسیر API پیدا نشد.'
    });
  } catch (err) {
    console.error('Hesabyar API error:', err);

    return send(res, 500, {
      error: 'خطای داخلی سرور. تنظیمات دیتابیس و گزارش‌های Vercel را بررسی کن.'
    });
  }
};
