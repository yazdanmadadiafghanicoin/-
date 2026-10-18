
const { Pool } = require('pg');
const crypto = require('crypto');

const connectionString =
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL ||
  process.env.POSTGRES_PRISMA_URL ||
  process.env.POSTGRES_URL_NON_POOLING;

const pool = connectionString
  ? new Pool({
      connectionString,
      ssl: { rejectUnauthorized: false },
      max: 3,
      idleTimeoutMillis: 10000,
      connectionTimeoutMillis: 10000
    })
  : null;

const SECRET = process.env.JWT_SECRET;
const EMPTY = {
  goods: [],
  sales: [],
  buys: [],
  costs: [],
  payments: []
};

let schemaReady;

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

function b64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function sign(payload) {
  const head = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const data = `${head}.${body}`;

  const sig = crypto
    .createHmac('sha256', SECRET)
    .update(data)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${data}.${sig}`;
}

function verify(token) {
  if (!token || !SECRET) return null;

  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const data = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac('sha256', SECRET).update(data).digest();

  let actual;

  try {
    actual = Buffer.from(
      parts[2].replace(/-/g, '+').replace(/_/g, '/') +
      '='.repeat((4 - parts[2].length % 4) % 4),
      'base64'
    );
  } catch {
    return null;
  }

  if (
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(
        parts[1].replace(/-/g, '+').replace(/_/g, '/') +
        '='.repeat((4 - parts[1].length % 4) % 4),
        'base64'
      ).toString()
    );

    if (
      !payload.sub ||
      !payload.exp ||
      payload.exp < Math.floor(Date.now() / 1000)
    ) return null;

    return payload;
  } catch {
    return null;
  }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function passwordMatches(password, salt, hash) {
  const actual = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, 'hex');

  return actual.length === expected.length &&
    crypto.timingSafeEqual(actual, expected);
}

async function ensureSchema() {
  if (!pool) {
    throw new Error('متغیر DATABASE_URL در Vercel تنظیم نشده است.');
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
    })().catch(err => {
      schemaReady = null;
      throw err;
    });
  }

  await schemaReady;
}

function getRoute(req) {
  const url = new URL(req.url, 'http://localhost');
  const fromQuery = url.searchParams.get('path');

  if (fromQuery) {
    return '/' + fromQuery.split('/').filter(Boolean).join('/');
  }

  const pathname = url.pathname.replace(/\/$/, '');

  if (pathname === '/api' || pathname === '/api/index') return '/';
  if (pathname.startsWith('/api/')) return pathname.slice(4);

  return pathname;
}

async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;

  let raw = '';

  for await (const chunk of req) {
    raw += chunk;

    if (raw.length > 1_000_000) {
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
  const header = req.headers.authorization || req.headers.Authorization || '';
  return header.startsWith('Bearer ') ? header.slice(7) : '';
}

function validData(d) {
  return d &&
    typeof d === 'object' &&
    !Array.isArray(d) &&
    ['goods', 'sales', 'buys', 'costs', 'payments']
      .every(k => Array.isArray(d[k])) &&
    JSON.stringify(d).length <= 800000;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') return send(res, 204, {});

  const route = getRoute(req);

  if (route === '/' && req.method === 'GET') {
    return send(res, 200, {
      success: true,
      service: 'Hesabyar Dokan API',
      message: 'API حساب‌یار دوکان فعال است.'
    });
  }

  if (!pool) {
    return send(res, 500, {
      error: 'اتصال دیتابیس تنظیم نشده است. متغیر DATABASE_URL را در Vercel اضافه کن.'
    });
  }

  if (!SECRET || SECRET.length < 32) {
    return send(res, 500, {
      error: 'متغیر JWT_SECRET در Vercel باید حداقل ۳۲ حرف تصادفی داشته باشد.'
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
          error: 'رمز عبور باید حداقل ۸ حرف باشد.'
        });
      }

      const { salt, hash } = hashPassword(password);
      let result;

      try {
        result = await pool.query(
          `INSERT INTO hy_users
           (username, username_lower, password_salt, password_hash)
           VALUES($1,$2,$3,$4)
           RETURNING id, username`,
          [username, username.toLowerCase(), salt, hash]
        );
      } catch (e) {
        if (e.code === '23505') {
          return send(res, 409, {
            error: 'این نام کاربری قبلاً ثبت شده است. نام دیگری انتخاب کن.'
          });
        }
        throw e;
      }

      const user = result.rows[0];

      await pool.query(
        'INSERT INTO hy_user_data(user_id, data) VALUES($1,$2::jsonb)',
        [user.id, JSON.stringify(EMPTY)]
      );

      const token = sign({
        sub: String(user.id),
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30
      });

      return send(res, 201, {
        token,
        user: { username: user.username }
      });
    }

    if (route === '/login' && req.method === 'POST') {
      const body = await readBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');

      if (!username || !password) {
        return send(res, 400, {
          error: 'نام کاربری و رمز عبور را وارد کن.'
        });
      }

      const result = await pool.query(
        `SELECT id, username, password_salt, password_hash
         FROM hy_users WHERE username_lower=$1`,
        [username.toLowerCase()]
      );

      const user = result.rows[0];

      if (!user || !passwordMatches(
        password,
        user.password_salt,
        user.password_hash
      )) {
        return send(res, 401, {
          error: 'نام کاربری یا رمز عبور نادرست است.'
        });
      }

      const token = sign({
        sub: String(user.id),
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30
      });

      return send(res, 200, {
        token,
        user: { username: user.username }
      });
    }

    if (['/me', '/data'].includes(route)) {
      const payload = verify(getToken(req));

      if (!payload) {
        return send(res, 401, {
          error: 'ابتدا وارد حساب شوید.'
        });
      }

      const userResult = await pool.query(
        'SELECT id, username FROM hy_users WHERE id=$1',
        [payload.sub]
      );

      const user = userResult.rows[0];

      if (!user) {
        return send(res, 401, {
          error: 'حساب یافت نشد؛ دوباره وارد شو.'
        });
      }

      if (route === '/me' && req.method === 'GET') {
        return send(res, 200, {
          user: { username: user.username }
        });
      }

      if (route === '/data' && req.method === 'GET') {
        const result = await pool.query(
          'SELECT data FROM hy_user_data WHERE user_id=$1',
          [user.id]
        );

        return send(res, 200, {
          data: result.rows[0]?.data || EMPTY
        });
      }

      if (route === '/data' && req.method === 'PUT') {
        const body = await readBody(req);

        if (!validData(body.data)) {
          return send(res, 400, {
            error: 'ساختار اطلاعات معتبر نیست یا حجم آن زیاد است.'
          });
        }

        await pool.query(
          `INSERT INTO hy_user_data(user_id, data, updated_at)
           VALUES($1,$2::jsonb,NOW())
           ON CONFLICT(user_id)
           DO UPDATE SET data=EXCLUDED.data, updated_at=NOW()`,
          [user.id, JSON.stringify(body.data)]
        );

        return send(res, 200, {
          success: true,
          message: 'اطلاعات ذخیره شد.'
        });
      }

      return send(res, 405, {
        error: 'روش درخواست پشتیبانی نمی‌شود.'
      });
    }

    return send(res, 404, {
      error: 'مسیر API پیدا نشد.'
    });
  } catch (err) {
    console.error('Hesabyar API error:', err);

    return send(res, 500, {
      error: err.message || 'خطای داخلی سرور.'
    });
  }
};
