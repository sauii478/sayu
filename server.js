"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "127.0.0.1";
const SECURE = process.env.SECURE === "1";
const DATABASE_URL = String(process.env.DATABASE_URL || "").trim();
const DB_PATH = path.join(__dirname, "data.db");
const HTML_PATH = path.join(__dirname, "index.html");

const USE_PG = Boolean(DATABASE_URL);

let sqliteDb = null;
let pgPool = null;

function toPgSql(sql) {
  let idx = 0;
  return sql.replace(/\?/g, () => `$${++idx}`);
}

function withPgReturningId(sql) {
  const trimmed = sql.trim().replace(/;+\s*$/, "");
  if (/^\s*INSERT\s+INTO\s+/i.test(trimmed) && !/\bRETURNING\b/i.test(trimmed)) {
    return `${trimmed} RETURNING id`;
  }
  return trimmed;
}

function makeSqliteDb(db) {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'gv', 'sv')),
      ref_id INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS classes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT DEFAULT '',
      name TEXT NOT NULL UNIQUE,
      course_year TEXT DEFAULT '',
      notes TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS students (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_code TEXT NOT NULL UNIQUE,
      full_name TEXT NOT NULL,
      gender TEXT NOT NULL DEFAULT 'Nam',
      dob TEXT DEFAULT '',
      province TEXT DEFAULT '',
      class_id INTEGER NOT NULL,
      notes TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(class_id) REFERENCES classes(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS lecturers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      lecturer_code TEXT NOT NULL UNIQUE,
      full_name TEXT NOT NULL,
      gender TEXT NOT NULL DEFAULT 'Nam',
      birth_year TEXT DEFAULT '',
      department TEXT DEFAULT '',
      degree TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS courses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      course_code TEXT NOT NULL UNIQUE,
      course_name TEXT NOT NULL,
      credits INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS rooms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      building TEXT NOT NULL,
      room_name TEXT NOT NULL,
      capacity INTEGER NOT NULL DEFAULT 40,
      has_projector INTEGER NOT NULL DEFAULT 0,
      projector_ready INTEGER NOT NULL DEFAULT 0,
      has_tv INTEGER NOT NULL DEFAULT 0,
      tv_ready INTEGER NOT NULL DEFAULT 0,
      equipment_note TEXT DEFAULT '',
      UNIQUE(building, room_name)
    );

    CREATE TABLE IF NOT EXISTS schedules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      semester TEXT NOT NULL,
      class_id INTEGER NOT NULL,
      lecturer_id INTEGER NOT NULL,
      course_id INTEGER NOT NULL,
      room_id INTEGER NOT NULL,
      day_of_week TEXT NOT NULL,
      session TEXT NOT NULL CHECK(session IN ('Sáng (07:00-11:00)', 'Chiều (13:00-17:00)')),
      time_range TEXT NOT NULL,
      weeks_note TEXT DEFAULT 'Cả kỳ',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(class_id) REFERENCES classes(id) ON DELETE CASCADE,
      FOREIGN KEY(lecturer_id) REFERENCES lecturers(id) ON DELETE CASCADE,
      FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE,
      FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE
    );
  `);

  return {
    async get(sql, params = []) {
      return db.prepare(sql).get(...params) || null;
    },
    async all(sql, params = []) {
      return db.prepare(sql).all(...params);
    },
    async run(sql, params = []) {
      const info = db.prepare(sql).run(...params);
      return {
        changes: Number(info.changes || 0),
        lastInsertRowid: info.lastInsertRowid != null ? Number(info.lastInsertRowid) : null
      };
    }
  };
}

async function initDb() {
  if (USE_PG) {
    const { Pool } = require("pg");
    pgPool = new Pool({
      connectionString: DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    });

    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'gv', 'sv')),
        ref_id INTEGER,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP::text
      );

      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at BIGINT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS classes (
        id SERIAL PRIMARY KEY,
        code TEXT DEFAULT '',
        name TEXT NOT NULL UNIQUE,
        course_year TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP::text
      );

      CREATE TABLE IF NOT EXISTS students (
        id SERIAL PRIMARY KEY,
        student_code TEXT NOT NULL UNIQUE,
        full_name TEXT NOT NULL,
        gender TEXT NOT NULL DEFAULT 'Nam',
        dob TEXT DEFAULT '',
        province TEXT DEFAULT '',
        class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
        notes TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP::text
      );

      CREATE TABLE IF NOT EXISTS lecturers (
        id SERIAL PRIMARY KEY,
        lecturer_code TEXT NOT NULL UNIQUE,
        full_name TEXT NOT NULL,
        gender TEXT NOT NULL DEFAULT 'Nam',
        birth_year TEXT DEFAULT '',
        department TEXT DEFAULT '',
        degree TEXT DEFAULT '',
        phone TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP::text
      );

      CREATE TABLE IF NOT EXISTS courses (
        id SERIAL PRIMARY KEY,
        course_code TEXT NOT NULL UNIQUE,
        course_name TEXT NOT NULL,
        credits INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP::text
      );

      CREATE TABLE IF NOT EXISTS rooms (
        id SERIAL PRIMARY KEY,
        building TEXT NOT NULL,
        room_name TEXT NOT NULL,
        capacity INTEGER NOT NULL DEFAULT 40,
        has_projector INTEGER NOT NULL DEFAULT 0,
        projector_ready INTEGER NOT NULL DEFAULT 0,
        has_tv INTEGER NOT NULL DEFAULT 0,
        tv_ready INTEGER NOT NULL DEFAULT 0,
        equipment_note TEXT DEFAULT '',
        UNIQUE(building, room_name)
      );

      CREATE TABLE IF NOT EXISTS schedules (
        id SERIAL PRIMARY KEY,
        semester TEXT NOT NULL,
        class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
        lecturer_id INTEGER NOT NULL REFERENCES lecturers(id) ON DELETE CASCADE,
        course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
        room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
        day_of_week TEXT NOT NULL,
        session TEXT NOT NULL CHECK(session IN ('Sáng (07:00-11:00)', 'Chiều (13:00-17:00)')),
        time_range TEXT NOT NULL,
        weeks_note TEXT DEFAULT 'Cả kỳ',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP::text
      );
    `);

    return {
      async get(sql, params = []) {
        const res = await pgPool.query(toPgSql(sql), params);
        return res.rows[0] || null;
      },
      async all(sql, params = []) {
        const res = await pgPool.query(toPgSql(sql), params);
        return res.rows;
      },
      async run(sql, params = []) {
        const pgSql = toPgSql(withPgReturningId(sql));
        const res = await pgPool.query(pgSql, params);
        const insertedId = res.rows && res.rows[0] && res.rows[0].id != null ? Number(res.rows[0].id) : null;
        return {
          changes: Number(res.rowCount || 0),
          lastInsertRowid: insertedId
        };
      }
    };
  }

  const { DatabaseSync } = require("node:sqlite");
  sqliteDb = new DatabaseSync(DB_PATH);
  return makeSqliteDb(sqliteDb);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derived}`;
}

function verifyPassword(password, stored) {
  const parts = String(stored || "").split(":");
  if (parts.length !== 2) return false;
  const [salt, keyHex] = parts;
  const derived = crypto.scryptSync(password, salt, 64);
  const keyBuf = Buffer.from(keyHex, "hex");
  if (derived.length !== keyBuf.length) return false;
  return crypto.timingSafeEqual(derived, keyBuf);
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const map = {};
  for (const pair of header.split(";")) {
    const idx = pair.indexOf("=");
    if (idx > 0) {
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      map[k] = decodeURIComponent(v);
    }
  }
  return map;
}

function sendJson(res, status, data, extraHeaders = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...extraHeaders
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 2_000_000) {
        reject(new Error("Payload too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

function setSessionCookie(res, token, maxAgeSec = 86400) {
  const parts = [
    `sid=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAgeSec}`
  ];
  if (SECURE) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearSessionCookie(res) {
  const parts = ["sid=", "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"];
  if (SECURE) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function formatDbError(err) {
  const msg = String((err && err.message) || err || "");
  const code = String((err && err.code) || "");
  if (code === "23505" || msg.includes("UNIQUE") || msg.includes("duplicate key")) {
    let detail = "Dữ liệu đã tồn tại trong hệ thống";
    if (msg.includes("classes_name") || msg.includes("classes.name")) detail = "Tên lớp đã tồn tại trong hệ thống";
    else if (msg.includes("students_student_code") || msg.includes("students.student_code")) detail = "Mã sinh viên đã tồn tại trong hệ thống";
    else if (msg.includes("lecturers_lecturer_code") || msg.includes("lecturers.lecturer_code")) detail = "Mã giảng viên đã tồn tại trong hệ thống";
    else if (msg.includes("courses_course_code") || msg.includes("courses.course_code")) detail = "Mã môn học đã tồn tại trong hệ thống";
    else if (msg.includes("rooms")) detail = "Phòng học này trong tòa nhà đã tồn tại";
    else if (msg.includes("users_username") || msg.includes("users.username")) detail = "Tên đăng nhập đã tồn tại trong hệ thống";
    return { status: 409, error: detail };
  }
  return { status: 500, error: msg };
}

async function startServer() {
  const db = await initDb();

  const userCountRow = await db.get("SELECT COUNT(*) AS cnt FROM users");
  if (Number((userCountRow && userCountRow.cnt) || 0) === 0) {
    await db.run(
      "INSERT INTO users (username, password_hash, role, ref_id) VALUES (?, ?, 'admin', NULL)",
      ["admin", hashPassword("admin12345")]
    );
  }

  async function getSessionUser(req) {
    const cookies = parseCookies(req);
    const token = cookies.sid;
    if (!token) return null;
    const now = Date.now();
    await db.run("DELETE FROM sessions WHERE expires_at <= ?", [now]);
    const row = await db.get(
      `
      SELECT s.token, s.expires_at, u.id, u.username, u.role, u.ref_id
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token = ? AND s.expires_at > ?
    `,
      [token, now]
    );
    return row || null;
  }

  async function getUserProfile(user) {
    if (!user || !user.ref_id) return null;
    if (user.role === "sv") {
      return (
        (await db.get(
          `
          SELECT st.*, c.name AS class_name
          FROM students st
          LEFT JOIN classes c ON c.id = st.class_id
          WHERE st.id = ?
        `,
          [user.ref_id]
        )) || null
      );
    }
    if (user.role === "gv") {
      return (await db.get("SELECT * FROM lecturers WHERE id = ?", [user.ref_id])) || null;
    }
    return null;
  }

  async function getFullState() {
    const classes = await db.all("SELECT * FROM classes ORDER BY id DESC");
    const students = await db.all(`
      SELECT st.*, c.name AS class_name
      FROM students st
      LEFT JOIN classes c ON c.id = st.class_id
      ORDER BY st.id DESC
    `);
    const lecturers = await db.all("SELECT * FROM lecturers ORDER BY id DESC");
    const courses = await db.all("SELECT * FROM courses ORDER BY id DESC");
    const rooms = await db.all("SELECT * FROM rooms ORDER BY id DESC");
    const schedules = await db.all(`
      SELECT sc.*,
             c.name AS class_name,
             l.lecturer_code, l.full_name AS lecturer_name,
             co.course_code, co.course_name, co.credits,
             r.building, r.room_name, r.has_projector, r.projector_ready, r.has_tv, r.tv_ready
      FROM schedules sc
      JOIN classes c ON c.id = sc.class_id
      JOIN lecturers l ON l.id = sc.lecturer_id
      JOIN courses co ON co.id = sc.course_id
      JOIN rooms r ON r.id = sc.room_id
      ORDER BY sc.id DESC
    `);
    const users = await db.all("SELECT id, username, role, ref_id, created_at FROM users ORDER BY id DESC");

    return { classes, students, lecturers, courses, rooms, schedules, users };
  }

  const server = http.createServer(async (req, res) => {
    const urlObj = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const pathname = urlObj.pathname;
    const method = req.method || "GET";

    try {
      if (pathname === "/" && method === "GET") {
        const html = fs.readFileSync(HTML_PATH, "utf8");
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        return res.end(html);
      }

      if (pathname === "/api/me" && method === "GET") {
        const sess = await getSessionUser(req);
        if (!sess) return sendJson(res, 401, { error: "Chưa đăng nhập" });
        return sendJson(res, 200, {
          user: {
            id: sess.id,
            username: sess.username,
            role: sess.role,
            ref_id: sess.ref_id,
            profile: await getUserProfile(sess)
          }
        });
      }

      if (pathname === "/api/login" && method === "POST") {
        const body = await readBody(req);
        const username = String(body.username || "").trim();
        const password = String(body.password || "");
        const role = String(body.role || "");

        const user = await db.get("SELECT * FROM users WHERE username = ?", [username]);
        if (!user || !verifyPassword(password, user.password_hash)) {
          return sendJson(res, 401, { error: "Sai tên đăng nhập hoặc mật khẩu" });
        }
        if (role && user.role !== role) {
          return sendJson(res, 403, { error: "Vai trò đăng nhập không khớp với tài khoản" });
        }

        const token = crypto.randomBytes(32).toString("hex");
        const expiresAt = Date.now() + 86400 * 1000;
        await db.run("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)", [
          token,
          user.id,
          expiresAt
        ]);
        setSessionCookie(res, token, 86400);
        return sendJson(res, 200, {
          user: {
            id: user.id,
            username: user.username,
            role: user.role,
            ref_id: user.ref_id,
            profile: await getUserProfile(user)
          }
        });
      }

      if (pathname === "/api/logout" && method === "POST") {
        const cookies = parseCookies(req);
        if (cookies.sid) {
          await db.run("DELETE FROM sessions WHERE token = ?", [cookies.sid]);
        }
        clearSessionCookie(res);
        return sendJson(res, 200, { ok: true });
      }

      const sess = await getSessionUser(req);
      if (!sess) {
        return sendJson(res, 401, { error: "Phiên đăng nhập hết hạn hoặc chưa đăng nhập" });
      }

      if (pathname === "/api/state" && method === "GET") {
        const state = await getFullState();
        if (sess.role !== "admin") {
          state.users = [];
        }
        return sendJson(res, 200, state);
      }

      const requireAdmin = () => {
        if (sess.role !== "admin") {
          sendJson(res, 403, { error: "Chỉ quản trị viên mới có quyền thực hiện thao tác này" });
          return false;
        }
        return true;
      };

      if (pathname === "/api/classes" && method === "POST") {
        if (!requireAdmin()) return;
        const body = await readBody(req);
        const name = String(body.name || "").trim();
        const course_year = String(body.course_year || "").trim();
        const notes = String(body.notes || "").trim();
        if (!name) return sendJson(res, 400, { error: "Vui lòng nhập Tên lớp" });
        const info = await db.run("INSERT INTO classes (code, name, course_year, notes) VALUES ('', ?, ?, ?)", [
          name,
          course_year,
          notes
        ]);
        return sendJson(res, 201, { id: info.lastInsertRowid });
      }

      if (pathname.startsWith("/api/classes/") && method === "DELETE") {
        if (!requireAdmin()) return;
        const id = Number(pathname.split("/").pop());
        await db.run("DELETE FROM classes WHERE id = ?", [id]);
        return sendJson(res, 200, { ok: true });
      }

      if (pathname === "/api/students/bulk" && method === "POST") {
        if (!requireAdmin()) return;
        const body = await readBody(req);
        const class_id = Number(body.class_id || 0);
        const items = Array.isArray(body.students) ? body.students : [];
        if (!class_id) return sendJson(res, 400, { error: "Chưa chọn lớp để thêm hàng loạt" });
        const cls = await db.get("SELECT id FROM classes WHERE id = ?", [class_id]);
        if (!cls) return sendJson(res, 404, { error: "Lớp không tồn tại" });
        if (!items.length) return sendJson(res, 400, { error: "Không có dòng sinh viên hợp lệ nào" });

        let added = 0;
        const errors = [];
        for (let idx = 0; idx < items.length; idx++) {
          const item = items[idx] || {};
          const student_code = String(item.student_code || "").trim();
          const full_name = String(item.full_name || "").trim();
          const gender = ["Nam", "Nữ", "Khác"].includes(item.gender) ? item.gender : "Nam";
          const dob = String(item.dob || "").trim();
          const province = String(item.province || "").trim();
          const notes = String(item.notes || "").trim();
          if (!student_code || !full_name) {
            errors.push(`Dòng ${idx + 1}: thiếu Mã SV hoặc Họ tên`);
            continue;
          }
          try {
            await db.run(
              `
              INSERT INTO students (student_code, full_name, gender, dob, province, class_id, notes)
              VALUES (?, ?, ?, ?, ?, ?, ?)
            `,
              [student_code, full_name, gender, dob, province, class_id, notes]
            );
            added++;
          } catch (err) {
            const formatted = formatDbError(err);
            errors.push(`Dòng ${idx + 1} (${student_code}): ${formatted.error}`);
          }
        }

        return sendJson(res, 200, { added, total: items.length, errors });
      }

      if (pathname === "/api/students" && method === "POST") {
        if (!requireAdmin()) return;
        const body = await readBody(req);
        const student_code = String(body.student_code || "").trim();
        const full_name = String(body.full_name || "").trim();
        const gender = ["Nam", "Nữ", "Khác"].includes(body.gender) ? body.gender : "Nam";
        const dob = String(body.dob || "").trim();
        const province = String(body.province || "").trim();
        const class_id = Number(body.class_id || 0);
        const notes = String(body.notes || "").trim();
        if (!student_code || !full_name || !class_id) {
          return sendJson(res, 400, { error: "Cần nhập Mã SV, Họ tên và chọn Lớp" });
        }
        const info = await db.run(
          `
          INSERT INTO students (student_code, full_name, gender, dob, province, class_id, notes)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `,
          [student_code, full_name, gender, dob, province, class_id, notes]
        );
        return sendJson(res, 201, { id: info.lastInsertRowid });
      }

      if (pathname.startsWith("/api/students/") && !pathname.startsWith("/api/students/bulk") && method === "DELETE") {
        if (!requireAdmin()) return;
        const id = Number(pathname.split("/").pop());
        await db.run("DELETE FROM students WHERE id = ?", [id]);
        return sendJson(res, 200, { ok: true });
      }

      if (pathname === "/api/lecturers" && method === "POST") {
        if (!requireAdmin()) return;
        const body = await readBody(req);
        const lecturer_code = String(body.lecturer_code || "").trim();
        const full_name = String(body.full_name || "").trim();
        const gender = ["Nam", "Nữ", "Khác"].includes(body.gender) ? body.gender : "Nam";
        const birth_year = String(body.birth_year || "").trim();
        const department = String(body.department || "").trim();
        const degree = String(body.degree || "").trim();
        const phone = String(body.phone || "").trim();
        if (!lecturer_code || !full_name) {
          return sendJson(res, 400, { error: "Cần nhập Mã GV và Họ tên giảng viên" });
        }
        const info = await db.run(
          `
          INSERT INTO lecturers (lecturer_code, full_name, gender, birth_year, department, degree, phone)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `,
          [lecturer_code, full_name, gender, birth_year, department, degree, phone]
        );
        return sendJson(res, 201, { id: info.lastInsertRowid });
      }

      if (pathname.startsWith("/api/lecturers/") && method === "DELETE") {
        if (!requireAdmin()) return;
        const id = Number(pathname.split("/").pop());
        await db.run("DELETE FROM lecturers WHERE id = ?", [id]);
        return sendJson(res, 200, { ok: true });
      }

      if (pathname === "/api/courses" && method === "POST") {
        if (!requireAdmin()) return;
        const body = await readBody(req);
        const course_code = String(body.course_code || "").trim();
        const course_name = String(body.course_name || "").trim();
        const credits = Number(body.credits || 0);
        if (!course_code || !course_name || credits < 1) {
          return sendJson(res, 400, { error: "Cần nhập Mã môn, Tên môn và Số tín chỉ (>= 1)" });
        }
        const info = await db.run("INSERT INTO courses (course_code, course_name, credits) VALUES (?, ?, ?)", [
          course_code,
          course_name,
          credits
        ]);
        return sendJson(res, 201, { id: info.lastInsertRowid });
      }

      if (pathname.startsWith("/api/courses/") && method === "DELETE") {
        if (!requireAdmin()) return;
        const id = Number(pathname.split("/").pop());
        await db.run("DELETE FROM courses WHERE id = ?", [id]);
        return sendJson(res, 200, { ok: true });
      }

      if (pathname === "/api/rooms" && method === "POST") {
        if (!requireAdmin()) return;
        const body = await readBody(req);
        const building = String(body.building || "").trim();
        const room_name = String(body.room_name || "").trim();
        const capacity = Number(body.capacity || 40);
        const has_projector = body.has_projector ? 1 : 0;
        const projector_ready = has_projector && body.projector_ready ? 1 : 0;
        const has_tv = body.has_tv ? 1 : 0;
        const tv_ready = has_tv && body.tv_ready ? 1 : 0;
        const equipment_note = String(body.equipment_note || "").trim();
        if (!building || !room_name) {
          return sendJson(res, 400, { error: "Cần nhập Tòa nhà và Tên/Số phòng" });
        }
        const info = await db.run(
          `
          INSERT INTO rooms (building, room_name, capacity, has_projector, projector_ready, has_tv, tv_ready, equipment_note)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `,
          [building, room_name, capacity, has_projector, projector_ready, has_tv, tv_ready, equipment_note]
        );
        return sendJson(res, 201, { id: info.lastInsertRowid });
      }

      if (pathname.startsWith("/api/rooms/") && method === "DELETE") {
        if (!requireAdmin()) return;
        const id = Number(pathname.split("/").pop());
        await db.run("DELETE FROM rooms WHERE id = ?", [id]);
        return sendJson(res, 200, { ok: true });
      }

      if (pathname === "/api/schedules" && method === "POST") {
        if (!requireAdmin()) return;
        const body = await readBody(req);
        const semester = String(body.semester || "").trim();
        const class_id = Number(body.class_id || 0);
        const lecturer_id = Number(body.lecturer_id || 0);
        const course_id = Number(body.course_id || 0);
        const room_id = Number(body.room_id || 0);
        const day_of_week = String(body.day_of_week || "").trim();
        const session = String(body.session || "").trim();
        const time_range = String(body.time_range || "").trim();
        const weeks_note = String(body.weeks_note || "Cả kỳ").trim();

        if (!semester || !class_id || !lecturer_id || !course_id || !room_id || !day_of_week || !session || !time_range) {
          return sendJson(res, 400, { error: "Vui lòng chọn đầy đủ Học kỳ, Lớp, Giảng viên, Môn học, Phòng, Thứ, Ca và Khung giờ" });
        }
        if (!["Sáng (07:00-11:00)", "Chiều (13:00-17:00)"].includes(session)) {
          return sendJson(res, 400, { error: "Ca học chỉ nhận Sáng (07:00-11:00) hoặc Chiều (13:00-17:00)" });
        }

        const conflictRoom = await db.get(
          `
          SELECT id FROM schedules WHERE semester = ? AND day_of_week = ? AND session = ? AND room_id = ?
        `,
          [semester, day_of_week, session, room_id]
        );
        if (conflictRoom) {
          return sendJson(res, 409, { error: "Phòng này đã được xếp lịch trong cùng Học kỳ, Thứ và Ca" });
        }

        const conflictClass = await db.get(
          `
          SELECT id FROM schedules WHERE semester = ? AND day_of_week = ? AND session = ? AND class_id = ?
        `,
          [semester, day_of_week, session, class_id]
        );
        if (conflictClass) {
          return sendJson(res, 409, { error: "Lớp này đã có lịch học trong cùng Học kỳ, Thứ và Ca" });
        }

        const conflictLecturer = await db.get(
          `
          SELECT id FROM schedules WHERE semester = ? AND day_of_week = ? AND session = ? AND lecturer_id = ?
        `,
          [semester, day_of_week, session, lecturer_id]
        );
        if (conflictLecturer) {
          return sendJson(res, 409, { error: "Giảng viên này đã có lịch dạy trong cùng Học kỳ, Thứ và Ca" });
        }

        const info = await db.run(
          `
          INSERT INTO schedules (semester, class_id, lecturer_id, course_id, room_id, day_of_week, session, time_range, weeks_note)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
          [semester, class_id, lecturer_id, course_id, room_id, day_of_week, session, time_range, weeks_note]
        );
        return sendJson(res, 201, { id: info.lastInsertRowid });
      }

      if (pathname.startsWith("/api/schedules/") && method === "DELETE") {
        if (!requireAdmin()) return;
        const id = Number(pathname.split("/").pop());
        await db.run("DELETE FROM schedules WHERE id = ?", [id]);
        return sendJson(res, 200, { ok: true });
      }

      if (pathname === "/api/users" && method === "POST") {
        if (!requireAdmin()) return;
        const body = await readBody(req);
        const username = String(body.username || "").trim();
        const password = String(body.password || "");
        const role = String(body.role || "sv");
        const ref_id = body.ref_id ? Number(body.ref_id) : null;
        if (username.length < 3 || password.length < 8 || !["admin", "gv", "sv"].includes(role)) {
          return sendJson(res, 400, { error: "Tên đăng nhập >= 3 ký tự, mật khẩu >= 8 ký tự và vai trò hợp lệ" });
        }
        const info = await db.run("INSERT INTO users (username, password_hash, role, ref_id) VALUES (?, ?, ?, ?)", [
          username,
          hashPassword(password),
          role,
          ref_id
        ]);
        return sendJson(res, 201, { id: info.lastInsertRowid });
      }

      if (pathname.startsWith("/api/users/") && method === "DELETE") {
        if (!requireAdmin()) return;
        const id = Number(pathname.split("/").pop());
        if (id === sess.id) {
          return sendJson(res, 400, { error: "Không thể tự xóa tài khoản đang đăng nhập" });
        }
        await db.run("DELETE FROM users WHERE id = ?", [id]);
        return sendJson(res, 200, { ok: true });
      }

      return sendJson(res, 404, { error: "Không tìm thấy đường dẫn API" });
    } catch (err) {
      const formatted = formatDbError(err);
      return sendJson(res, formatted.status, { error: formatted.error });
    }
  });

  server.listen(PORT, HOST, () => {
    console.log(`http://localhost:${PORT} (${USE_PG ? "PostgreSQL" : "SQLite"})`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
