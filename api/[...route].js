
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 3,
});

const SECRET = process.env.JWT_SECRET;

function send(res, status, data) {
  return res.status(status).json(data);
}

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS hy_users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(40) NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS hy_users_username_lower_idx
    ON hy_users (LOWER(username))
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS hy_shop_data (
      user_id BIGINT PRIMARY KEY REFERENCES hy_users(id)
        ON DELETE CASCADE,
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

function getToken(req) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return null;
  return header.slice(7);
}

function validUsername(username) {
  return (
    typeof username === "string" &&
    /^[a-zA-Z0-9_]{3,40}$/.test(username)
  );
}

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (!SECRET || !process.env.DATABASE_URL) {
    return send(res, 500, {
      error: "تنظیمات دیتابیس یا JWT_SECRET در Vercel کامل نیست.",
    });
  }

  try {
    await setupDatabase();

    const path = new URL(
      req.url,
      "https://api.example.com"
    ).pathname.replace(/\/+$/, "");

    // ثبت‌نام
    if (path.endsWith("/register") && req.method === "POST") {
      const { username, password } = req.body || {};

      if (!validUsername(username)) {
        return send(res, 400, {
          error: "نام کاربری باید ۳ تا ۴۰ حرف انگلیسی، عدد یا _ باشد.",
        });
      }

      if (
        typeof password !== "string" ||
        password.length < 8 ||
        password.length > 128
      ) {
        return send(res, 400, {
          error: "رمز عبور باید حداقل ۸ و حداکثر ۱۲۸ حرف باشد.",
        });
      }

      const hash = await bcrypt.hash(password, 12);

      let result;
      try {
        result = await pool.query(
          `INSERT INTO hy_users (username, password_hash)
           VALUES ($1, $2)
           RETURNING id, username`,
          [username, hash]
        );
      } catch (err) {
        if (err.code === "23505") {
          return send(res, 409, {
            error: "این نام کاربری قبلاً ثبت شده است.",
          });
        }
        throw err;
      }

      const user = result.rows[0];

      await pool.query(
        `INSERT INTO hy_shop_data (user_id, data)
         VALUES ($1, $2::jsonb)
         ON CONFLICT (user_id) DO NOTHING`,
        [user.id, JSON.stringify({})]
      );

      const token = jwt.sign(
        { sub: String(user.id), username: user.username },
        SECRET,
        { expiresIn: "7d" }
      );

      return send(res, 201, {
        message: "ثبت‌نام موفق بود.",
        token,
        user: {
          id: String(user.id),
          username: user.username,
        },
      });
    }

    // ورود
    if (path.endsWith("/login") && req.method === "POST") {
      const { username, password } = req.body || {};

      if (
        typeof username !== "string" ||
        typeof password !== "string"
      ) {
        return send(res, 400, {
          error: "نام کاربری و رمز عبور را وارد کنید.",
        });
      }

      const result = await pool.query(
        `SELECT id, username, password_hash
         FROM hy_users
         WHERE LOWER(username) = LOWER($1)
         LIMIT 1`,
        [username]
      );

      if (
        !result.rows.length ||
        !(await bcrypt.compare(password, result.rows[0].password_hash))
      ) {
        return send(res, 401, {
          error: "نام کاربری یا رمز عبور نادرست است.",
        });
      }

      const user = result.rows[0];

      const token = jwt.sign(
        { sub: String(user.id), username: user.username },
        SECRET,
        { expiresIn: "7d" }
      );

      return send(res, 200, {
        message: "ورود موفق بود.",
        token,
        user: {
          id: String(user.id),
          username: user.username,
        },
      });
    }

    // بررسی حساب واردشده
    if (path.endsWith("/me") && req.method === "GET") {
      const token = getToken(req);
      if (!token) {
        return send(res, 401, { error: "ابتدا وارد حساب شوید." });
      }

      let payload;
      try {
        payload = jwt.verify(token, SECRET);
      } catch {
        return send(res, 401, {
          error: "نشست شما منقضی شده است؛ دوباره وارد شوید.",
        });
      }

      const result = await pool.query(
        `SELECT id, username FROM hy_users WHERE id = $1`,
        [payload.sub]
      );

      if (!result.rows.length) {
        return send(res, 401, { error: "حساب پیدا نشد." });
      }

      return send(res, 200, {
        user: {
          id: String(result.rows[0].id),
          username: result.rows[0].username,
        },
      });
    }

    // دریافت اطلاعات حساب خود کاربر
    if (path.endsWith("/data") && req.method === "GET") {
      const token = getToken(req);
      if (!token) {
        return send(res, 401, { error: "ابتدا وارد حساب شوید." });
      }

      let payload;
      try {
        payload = jwt.verify(token, SECRET);
      } catch {
        return send(res, 401, { error: "نشست منقضی شده است." });
      }

      const result = await pool.query(
        `SELECT data, updated_at
         FROM hy_shop_data
         WHERE user_id = $1`,
        [payload.sub]
      );

      return send(res, 200, {
        data: result.rows[0]?.data || {},
        updatedAt: result.rows[0]?.updated_at || null,
      });
    }

    // ذخیره اطلاعات فقط برای حساب خود کاربر
    if (path.endsWith("/data") && req.method === "PUT") {
      const token = getToken(req);
      if (!token) {
        return send(res, 401, { error: "ابتدا وارد حساب شوید." });
      }

      let payload;
      try {
        payload = jwt.verify(token, SECRET);
      } catch {
        return send(res, 401, { error: "نشست منقضی شده است." });
      }

      const data = req.body?.data;

      if (
        data === null ||
        typeof data !== "object" ||
        Array.isArray(data)
      ) {
        return send(res, 400, {
          error: "ساختار اطلاعات ارسالی معتبر نیست.",
        });
      }

      const serialized = JSON.stringify(data);
      if (Buffer.byteLength(serialized, "utf8") > 1_000_000) {
        return send(res, 413, {
          error: "حجم اطلاعات بیش از حد مجاز است.",
        });
      }

      const result = await pool.query(
        `INSERT INTO hy_shop_data (user_id, data, updated_at)
         VALUES ($1, $2::jsonb, NOW())
         ON CONFLICT (user_id)
         DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
         RETURNING updated_at`,
        [payload.sub, serialized]
      );

      return send(res, 200, {
        message: "اطلاعات آنلاین ذخیره شد.",
        updatedAt: result.rows[0].updated_at,
      });
    }

    return send(res, 404, { error: "این مسیر API وجود ندارد." });
  } catch (err) {
    console.error("API error:", err);
    return send(res, 500, {
      error: "خطای سرور رخ داد. تنظیمات دیتابیس را بررسی کنید.",
    });
  }
};
