require("dotenv").config();

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const rateLimit = require("express-rate-limit");

const app = express();
const port = 3000;

const db = new sqlite3.Database("./app_full.db", (err) => {
  if (err) {
    console.error("Error connecting to the database:", err.message);
  } else {
    console.log("Connected to the SQLite database.");
  }
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "please-change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    },
  })
);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message:
    "Too many login attempts from this IP, please try again after 15 minutes",
});

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = path.join(__dirname, "uploads");
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    const paymentId = req.body.paymentId || "unknown";
    const ext = path.extname(file.originalname || "").toLowerCase();
    const base = path.basename(file.originalname || "slip", ext).replace(/[^\w.-]/g, "_");
    cb(null, `${Date.now()}_${paymentId}_${base}${ext}`);
  }
});

function fileFilter(req, file, cb) {
  const ok = ["image/jpeg", "image/png", "application/pdf"];
  if (!ok.includes(file.mimetype)) return cb(new Error("Only JPG/PNG/PDF allowed"), false);
  cb(null, true);
}

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter
});

function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hashSync(password, saltRounds);
}

function comparePassword(password, hash) {
  return bcrypt.compareSync(password, hash);
}

function requireLogin(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).send("You must be logged in to access this resource.");
}

app.get("/", (req, res) => {
  res.redirect("/login.html");
});

app.post("/login", loginLimiter, (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM users WHERE email = ?";

  db.get(sql, [email], (err, user) => {
    if (err) return res.status(500).send("Server error");

    if (user && comparePassword(password, user.password)) {
      // หลีกเลี่ยงชนชื่อกับ password จาก req.body
      const { password: _hash, ...userData } = user;
      userData.role = user.role ? user.role.toLowerCase() : "";
      req.session.user = userData;

      if (userData.role === "owner") return res.redirect("/owner");
      return res.redirect("/tenant");
    } else {
      return res.redirect("/login.html?error=1");
    }
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.redirect("/");
    // ให้ตรงกับชื่อคุกกี้ที่ตั้งไว้ (sid)
    res.clearCookie("sid");
    res.redirect("/login.html");
  });
});

app.get("/owner", requireLogin, (req, res) => {
  if (req.session.user && req.session.user.role === "owner") {
    res.sendFile(path.join(__dirname, "public", "owner.html"));
  } else {
    res.redirect("/login.html");
  }
});

app.get("/tenant", requireLogin, (req, res) => {
  if (req.session.user && req.session.user.role === "tenant") {
    res.sendFile(path.join(__dirname, "public", "tenant.html"));
  } else {
    res.redirect("/login.html");
  }
});

app.get("/api/userinfo", (req, res) => {
  if (req.session.user) return res.json({ user: req.session.user });
  return res.status(401).json({ error: "Not authenticated" });
});

app.get("/api/tenant/profile", requireLogin, (req, res) => {
  if (req.session.user.role !== "tenant") {
    return res.status(403).json({ success: false, error: "Forbidden" });
  }
  const tenantId = req.session.user.id;
  const sql = `
    SELECT
      u.name,
      u.email,
      u.phone,
      r.room_number,
      u.emergency_name AS emergency_contact_name,
      u.emergency_phone AS emergency_contact_phone
    FROM users u
    LEFT JOIN rooms r ON u.room_id = r.id
    WHERE u.id = ?
  `;

  db.get(sql, [tenantId], (err, row) => {
    if (err) {
      console.error("Database error fetching profile:", err.message);
      return res
        .status(500)
        .json({ success: false, error: "เกิดข้อผิดพลาดในการดึงข้อมูล" });
    }
    if (row) return res.json({ success: true, data: row });
    return res.status(404).json({ success: false, error: "ไม่พบข้อมูลผู้ใช้" });
  });
});

app.get("/api/tenant/dashboard", requireLogin, (req, res) => {
  if (req.session.user.role !== "tenant") {
    return res.status(403).json({ error: "Forbidden" });
  }

  const tenantId = req.session.user.id;
  const dashboardData = { userInfo: req.session.user };
  const dbPromises = [];

  dbPromises.push(
    new Promise((resolve, reject) => {
      const paymentSql = `
          SELECT id, amount, due_date, status, note
          FROM payments
          WHERE tenant_id = ? AND status IN ('unpaid','pending','overdue')
          ORDER BY due_date DESC LIMIT 1`;
      db.get(paymentSql, [tenantId], (err, row) => {
        if (err) return reject(err);
        dashboardData.payment = row || null;
        resolve();
      });
    })
  );

  dbPromises.push(
    new Promise((resolve, reject) => {
      const maintenanceSql = `
        SELECT issue_type, status, COUNT(*) as count
        FROM maintenance_requests
        WHERE tenant_id = ? AND status != 'completed'`;
      db.get(maintenanceSql, [tenantId], (err, row) => {
        if (err) return reject(err);
        dashboardData.maintenance = row || null;
        resolve();
      });
    })
  );

  dbPromises.push(
    new Promise((resolve, reject) => {
      const announcementSql = `
        SELECT title FROM announcements ORDER BY created_at DESC LIMIT 1`;
      db.get(announcementSql, [], (err, row) => {
        if (err) return reject(err);
        dashboardData.announcement = row || null;
        resolve();
      });
    })
  );

  dbPromises.push(
    new Promise((resolve, reject) => {
      // --- แทนที่บล็อค roomSql + utilitiesSql เดิมทั้งหมดใน /api/tenant/dashboard ---
const roomSql = `SELECT r.rent FROM rooms r JOIN users u ON u.room_id = r.id WHERE u.id = ?`;
db.get(roomSql, [tenantId], (err, roomRow) => {
  if (err) return reject(err);
  const room_rent = roomRow ? roomRow.rent : 0;

  // เดิมเราเคยคูณ 4.1 แล้วเขียนทับ amount ตรงนี้ → เลิกทำ
  // ถ้าต้องมี fallback ให้ดึง utilities มาใช้ประกอบ “แสดงผล” ได้ แต่ไม่ทับ amount
  const utilitiesSql = `SELECT water_fee, elec_usage FROM utilities WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1`;
  db.get(utilitiesSql, [tenantId], (err2, utilRow) => {
    if (err2) return reject(err2);

    // แตก note จาก payment (ถ้ามี) เพื่อโชว์ breakdown
    let note = {};
    try { note = JSON.parse(dashboardData.payment?.note || "{}"); } catch {}

    if (dashboardData.payment) {
      // ใช้ยอดสุดท้ายจาก payments.amount อย่างเดียว ไม่คำนวณใหม่/ไม่เขียนทับ
      dashboardData.payment = {
        id: dashboardData.payment.id,
        status: dashboardData.payment.status,
        due_date: dashboardData.payment.due_date,
        amount: dashboardData.payment.amount,  // ← ยอดตรงกับ owner
        breakdown: {
          rent: room_rent,
          water_total: note.water_total ?? (utilRow?.water_fee ?? 0),
          elec_total:  note.elec_total  ?? 0,     // ไม่คูณ 4.1 อีก
          others:      note.others      ?? 0
        }
      };
    } else {
      // fallback: ยังไม่มีแถว payment เดือนนี้ → คำนวณประมาณการเพื่อแสดงคร่าว ๆ เท่านั้น
      const water_bill = utilRow?.water_fee ?? 0;
      const electricity_bill = 0; // เลิกคูณ 4.1 ที่นี่
      const estimated = room_rent + water_bill + electricity_bill;

      dashboardData.payment = {
        id: null,
        status: "unpaid (est.)",
        due_date: null,
        amount: estimated,
        breakdown: {
          rent: room_rent,
          water_total: water_bill,
          elec_total: electricity_bill,
          others: 0
        }
      };
    }
    resolve();
  });
});

    })
  );

  Promise.all(dbPromises)
    .then(() => res.json(dashboardData))
    .catch((err) => {
      console.error("Error fetching dashboard data:", err);
      res.status(500).json({ error: "Failed to fetch dashboard data" });
    });
});

app.use('/contracts', express.static(path.join(__dirname, 'contracts')));


app.get("/api/contract-details", requireLogin, (req, res) => {
  if (req.session.user.role !== "tenant") {
    return res.status(403).json({ error: "Forbidden" });
  }
  const tenantId = req.session.user.id;
  const sql = `
    SELECT
      u.name AS tenant_name,
      r.room_number,
      r.rent AS rent_rate,
      l.start_date,
      l.end_date,
      l.contract_file AS contract_url
    FROM leases l
    JOIN users u ON l.tenant_id = u.id
    JOIN rooms r ON l.room_id = r.id
    WHERE l.tenant_id = ? AND l.status = 'active'
    ORDER BY date(l.start_date) DESC
    LIMIT 1
  `;
  db.get(sql, [tenantId], (err, row) => {
    if (err) return res.status(500).json({ error: "เกิดข้อผิดพลาดในการดึงข้อมูลสัญญา" });
    if (!row) return res.status(404).json({ error: "ไม่พบข้อมูลสัญญาเช่า" });
    res.json(row);
  });
});

app.get("/api/billing-details", requireLogin, (req, res) => {
  if (req.session.user.role !== "tenant") {
    return res.status(403).json({ error: "Forbidden" });
  }
  const tenantId = req.session.user.id;

  // 1) เอาบิลล่าสุด (unpaid/pending/overdue)
  const paySql = `
    SELECT id, amount, status, note
    FROM payments
    WHERE tenant_id = ? AND status IN ('unpaid','pending','overdue')
    ORDER BY due_date DESC LIMIT 1`;

  db.get(paySql, [tenantId], (err, payRow) => {
    if (err) return res.status(500).json({ error: "Failed to fetch billing details" });

    // 2) ดึงค่าเช่า เพื่อโชว์ breakdown
    const roomSql = `SELECT r.rent FROM rooms r JOIN users u ON u.room_id = r.id WHERE u.id = ?`;
    db.get(roomSql, [tenantId], (err2, roomRow) => {
      if (err2) return res.status(500).json({ error: "Failed to fetch billing details" });
      const rent = roomRow?.rent || 0;

      if (payRow) {
  let note = {};
  try { note = JSON.parse(payRow?.note || "{}"); } catch {}
  return res.json({
    room_rent: rent,
    water_bill: note.water_total ?? 0,
    electricity_bill: note.elec_total ?? 0,
    others: note.others ?? 0,
    total_amount: payRow.amount,
    status: payRow.status,
    payment_id: payRow.id
  });
}

      // 3) fallback: ไม่มี payments → คำนวณคร่าว ๆ จาก utilities แบบไม่คูณ 4.1 อีก
      const utilitiesSql = `SELECT water_fee, elec_usage FROM utilities WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1`;
db.get(utilitiesSql, [tenantId], (err3, utilRow) => {
  if (err3) return res.status(500).json({ error: "Failed to fetch billing details" });
  const water_bill = utilRow?.water_fee || 0;
  const elec_usage = utilRow?.elec_usage || 0;
  const electricity_bill = elec_usage * BILL_ELEC_RATE; // เดิมเป็น 0
  const total_amount = rent + water_bill + electricity_bill;
  res.json({
    room_rent: rent,
    water_bill,
    electricity_bill,
    others: 0,
    total_amount,
    status: "unpaid (est.)",
    payment_id: null
  });
});
    });
  });
});

/* ====== Upload Slip (tenant) ====== */
app.post(
  "/api/upload-slip",
  requireLogin,
  upload.single("paymentSlip"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: "Please upload a file." });
    }
    const { paymentId } = req.body;
    if (!paymentId) {
      return res.status(400).json({ error: "Payment ID is missing." });
    }
    const slipFilename = req.file.filename;

    // Mark as 'pending' until owner approves
    const sql = `
      UPDATE payments 
      SET status = 'pending', 
          slip_filename = ? 
      WHERE id = ? AND tenant_id = ?`;

    db.run(sql, [slipFilename, paymentId, req.session.user.id], function (err) {
      if (err) {
        console.error("Database error during slip upload:", err);
        return res.status(500).json({ error: "Database error." });
      }
      if (this.changes === 0) {
        return res.status(404).json({
          error: "Payment not found or you do not have permission to update it.",
        });
      }
      res.json({
        success: true,
        message: "Slip uploaded successfully! Awaiting owner approval.",
        filename: slipFilename,
      });
    });
  }
);

const BILL_WATER_RATE = 18; // อัตราค่าน้ำ/หน่วย (บาท)  [ต้องตรงกับหน้าเว็บ]
const BILL_ELEC_RATE  = 8;  // 

/* ====== Owner: Accounting & Dashboard ====== */
const requireOwner = (req, res, next) => {
  if (req.session.user && req.session.user.role === "owner") return next();
  return res.status(403).json({ error: "Forbidden: Access is denied." });
};

// ---- Fixed room types (2 แบบ) ----
const ROOM_TYPES = {
  air:         { key: "air",         label: "ห้องแอร์",        rent: 3500 },
  air_built_in:{ key: "air_built_in",label: "ห้องแอร์บิ้วอิน", rent: 4500 },
};

function resolveRoomType(input) {
  if (!input) return null;
  const s = String(input).trim().toLowerCase();
  // รับได้ทั้ง key (air, air_built_in) และ label ไทย
  for (const t of Object.values(ROOM_TYPES)) {
    if (s === t.key || s === t.label.toLowerCase()) return t;
  }
  return null;
}


app.get("/api/owner/dashboard", requireOwner, (req, res) => {
  const queries = {
  vacantRooms: `
    SELECT COUNT(*) AS count
    FROM rooms r
    LEFT JOIN users u ON u.room_id = r.id AND u.role = 'tenant'
    WHERE u.id IS NULL
  `,
  overduePayments: `
  SELECT COUNT(*) AS count
  FROM (
    SELECT p.*
    FROM payments p
    JOIN (
      SELECT tenant_id, MAX(id) AS last_id
      FROM payments
      GROUP BY tenant_id
    ) t ON p.id = t.last_id
    WHERE p.status = 'overdue'
  ) x
`,

  pendingMaintenance:
    "SELECT COUNT(*) as count FROM maintenance_requests WHERE status = 'pending'",
  monthlyIncome:
    "SELECT SUM(amount) as total FROM payments WHERE status = 'paid' AND strftime('%Y-%m', paid_date) = strftime('%Y-%m', 'now')",
};


  const results = {};
  let completed = 0;
  const totalQueries = Object.keys(queries).length;

  for (const [key, sql] of Object.entries(queries)) {
    db.get(sql, [], (err, row) => {
      if (err) {
        console.error(`Database error on ${key}:`, err.message);
        if (!res.headersSent) {
          return res
            .status(500)
            .json({ error: `Failed to fetch dashboard data on query: ${key}` });
        }
        return;
      }
      results[key] = (row && (row.count ?? row.total)) || 0;
      completed++;

      if (completed === totalQueries) {
        const alertSql = `
          SELECT u.name as tenant_name, r.room_number, mr.issue_type 
          FROM maintenance_requests mr
          JOIN users u ON mr.tenant_id = u.id
          JOIN rooms r ON u.room_id = r.id
          WHERE mr.status = 'pending' 
          ORDER BY mr.created_at DESC LIMIT 5`;
        db.all(alertSql, [], (err, alerts) => {
          if (err) {
            console.error("Database error on alerts:", err.message);
            if (!res.headersSent) {
              return res.status(500).json({ error: "Failed to fetch alerts." });
            }
            return;
          }

          const formattedAlerts = alerts.map((a) => ({
            message: `ห้อง ${a.room_number} (${a.tenant_name}) แจ้งซ่อม: ${a.issue_type}`,
          }));

          if (!res.headersSent) {
            res.json({
              vacantRooms: results.vacantRooms,
              overduePayments: results.overduePayments,
              pendingMaintenance: results.pendingMaintenance,
              monthlyIncome: results.monthlyIncome,
              alerts: formattedAlerts,
            });
          }
        });
      }
    });
  }
});

app.get("/api/owner/tenants", requireOwner, (req, res) => {
  const { q } = req.query || {};
  const where = ["u.role = 'tenant'"];
  const params = [];

  if (q) {
    where.push("(LOWER(u.name) LIKE LOWER(?) OR LOWER(COALESCE(r.room_number,'')) LIKE LOWER(?))");
    params.push(`%${q}%`, `%${q}%`);
  }

  const sql = `
    SELECT
      u.id AS id,
      r.id AS roomId,
      r.room_number AS roomNumber,
      u.name,
      u.phone
    FROM users u
    LEFT JOIN rooms r ON u.room_id = r.id
    WHERE ${where.join(" AND ")}
    ORDER BY CAST(r.room_number AS INTEGER) ASC, r.room_number ASC, u.name ASC
  `;

  db.all(sql, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: "Failed to fetch tenants" });
    }
    res.json({ tenants: rows || [] });
  });
});

app.get("/api/owner/accounting", requireOwner, (req, res) => {
  const { month, year } = req.query;
  const now = new Date();
  const mm = String(month ?? now.getMonth() + 1).padStart(2, "0");
  const yyyy = String(year ?? now.getFullYear());
  const ym = `${yyyy}-${mm}`; // YYYY-MM

  const sql = `
    WITH latest AS (
      SELECT tenant_id, MAX(id) AS last_id
      FROM payments
      WHERE due_date IS NOT NULL
        AND substr(due_date, 1, 7) = ?
      GROUP BY tenant_id
    )
    SELECT
      p.id            AS paymentId,
      r.room_number   AS roomNumber,
      u.name          AS tenantName,
      p.amount,
      p.status,
      p.slip_filename AS slipFilename
    FROM payments p
    JOIN latest l ON p.id = l.last_id
    JOIN users  u ON p.tenant_id = u.id
    JOIN rooms  r ON u.room_id   = r.id
    ORDER BY
      CASE p.status
        WHEN 'pending' THEN 1
        WHEN 'overdue' THEN 2
        WHEN 'paid'    THEN 3
        ELSE 4
      END,
      r.room_number ASC
  `;

  db.all(sql, [ym], (err, rows) => {
    if (err) {
      console.error("Database error fetching accounting data:", err.message);
      return res.status(500).json({ error: "Failed to fetch accounting data." });
    }
    res.json({ accountingData: rows, month: mm, year: yyyy });
  });
});


// List available room types for owner (fixed)
app.get("/api/owner/room-types", requireOwner, (req, res) => {
  // Prefer DB-backed room types if table exists and has rows; otherwise fallback to constants
  db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='room_types'", [], (e, tbl) => {
    if (e) return res.status(500).json({ error: "DB error" });
    if (!tbl) {
      // Fallback to in-memory constants
      return res.json({ types: Object.values(ROOM_TYPES) });
    }
    db.all("SELECT key, label, base_rent as rent, is_active FROM room_types WHERE ifnull(is_active,1)=1 ORDER BY id ASC", [], (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      if (!rows || rows.length === 0) return res.json({ types: Object.values(ROOM_TYPES) });
      // Normalize shape to match prior API
      const types = rows.map(r => ({ key: r.key, label: r.label, rent: r.rent }));
      res.json({ types });
    });
  });
});

// ✅ เพิ่มห้องใหม่ (ตั้งค่าเช่าตามประเภทอัตโนมัติ)
app.post("/api/owner/rooms", requireOwner, (req, res) => {
  const { room_number, type } = req.body || {};
  if (!room_number || !type) {
    return res.status(400).json({ error: "ต้องมี room_number และ type" });
  }

  // Try to resolve type from DB first
  function fallbackToConstAndInsert() {
    const tp = resolveRoomType(type);
    if (!tp) return res.status(400).json({ error: "ประเภทห้องไม่ถูกต้อง" });
    const sql = `INSERT INTO rooms (room_number, type, rent) VALUES (?,?,?)`;
    db.run(sql, [room_number, tp.label, tp.rent], function(err){
      if (err) return res.status(500).json({ error: "DB error" });
      res.status(201).json({ id: this.lastID, room_number, type: tp.label, rent: tp.rent });
    });
  }

  db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='room_types'", [], (e, tbl) => {
    if (e || !tbl) return fallbackToConstAndInsert();

    const s = String(type).trim().toLowerCase();
    db.get(`SELECT label, base_rent FROM room_types WHERE ifnull(is_active,1)=1 AND (lower(key)=? OR lower(label)=?) ORDER BY id LIMIT 1`,
      [s, s], (err, row) => {
        if (err) return res.status(500).json({ error: "DB error" });
        if (!row) return fallbackToConstAndInsert();

        const sql = `INSERT INTO rooms (room_number, type, rent) VALUES (?,?,?)`;
        db.run(sql, [room_number, row.label, row.base_rent], function(err){
          if (err) return res.status(500).json({ error: "DB error" });
          res.status(201).json({ id: this.lastID, room_number, type: row.label, rent: row.base_rent });
        });
      });
  });
});

// Create new room (auto set rent by type)
// Update room (change number and/or type; rent auto-updated when type changes)
// Delete room (only if no current tenant)
app.delete("/api/owner/rooms/:id", requireOwner, (req, res) => {
  const id = req.params.id;
  db.get(`SELECT 1 FROM users WHERE role='tenant' AND room_id = ?`, [id], (e, row) => {
    if (e) return res.status(500).json({ error: "DB error" });
    if (row) return res.status(409).json({ error: "ห้องนี้มีผู้เช่าอยู่ ลบไม่ได้" });
    db.run(`DELETE FROM rooms WHERE id = ?`, [id], function(err){
      if (err) return res.status(500).json({ error: "ลบไม่สำเร็จ" });
      if (this.changes === 0) return res.status(404).json({ error: "ไม่พบห้อง" });
      res.json({ success: true });
    });
  });
});
app.put("/api/owner/rooms/:id", requireOwner, (req, res) => {
  const id = req.params.id;
  const { room_number, type } = req.body || {};
  const sets = [];
  const params = [];

  if (room_number) { sets.push("room_number = ?"); params.push(room_number); }
  if (type) {
    const tp = resolveRoomType(type);
    if (!tp) return res.status(400).json({ error: "ประเภทห้องไม่ถูกต้อง" });
    sets.push("type = ?", "rent = ?"); params.push(tp.label, tp.rent);
  }
  if (sets.length === 0) return res.json({ success: true, message: "ไม่มีการเปลี่ยนแปลง" });

  // กันเลขห้องซ้ำกรณีมีการแก้ไข
  const runUpdate = () => {
    params.push(id);
    db.run(`UPDATE rooms SET ${sets.join(", ")} WHERE id = ?`, params, function(err){
      if (err) return res.status(500).json({ error: "อัปเดตไม่สำเร็จ" });
      if (this.changes === 0) return res.status(404).json({ error: "ไม่พบห้อง" });
      res.json({ success: true });
    });
  };

  if (room_number) {
    db.get(`SELECT id FROM rooms WHERE room_number = ? AND id <> ?`, [room_number, id], (e, row) => {
      if (e)   return res.status(500).json({ error: "DB error" });
      if (row) return res.status(409).json({ error: "เลขห้องนี้ถูกใช้แล้ว" });
      runUpdate();
    });
  } else {
    runUpdate();
  }
});

// Simple rooms list for select controls (all rooms)
app.get("/api/owner/rooms/simple", requireOwner, (req, res) => {
  const sql = `
    SELECT r.id, r.room_number
    FROM rooms r
    JOIN users u ON u.room_id = r.id AND u.role = 'tenant'
    ORDER BY CAST(r.room_number AS INTEGER) ASC, r.room_number ASC
  `;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});

app.get("/api/owner/rooms", requireOwner, (req, res) => {
  const sql = `
    SELECT
  r.id,
  r.room_number,
  r.type,
  r.rent,
  CASE WHEN u.id IS NOT NULL THEN 'occupied' ELSE 'vacant' END AS status,
  u.name AS tenant_name
FROM rooms r
LEFT JOIN users u ON r.id = u.room_id AND u.role = 'tenant';
  `;

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error("Database error fetching rooms:", err.message);
      return res.status(500).json({ error: "Failed to fetch room data." });
    }

    const formattedRooms = rows.map((row) => ({
      id: row.id,
      roomNumber: row.room_number,
      type: row.type,
      rent: row.rent,
      // ส่งค่าให้สอดคล้องกับ frontend badge ('occupied' | 'vacant')
      status: row.status === "occupied" ? "occupied" : "vacant",
      tenant: row.tenant_name || "-",
    }));

    res.json({ rooms: formattedRooms });
  });
});

app.get("/api/owner/repairs", requireOwner, (req, res) => {
  const sql = `
    SELECT
      m.id,
      m.issue_type AS category,
      m.details AS description,
      m.status,
      u.name as tenant_name,
      r.room_number AS roomNumber,
      m.created_at AS dateReported
    FROM maintenance_requests m
    JOIN users u ON m.tenant_id = u.id
    JOIN rooms r ON u.room_id = r.id
    ORDER BY m.created_at DESC
  `;

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error("Database error fetching repairs:", err.message);
      return res.status(500).json({ error: "Failed to fetch repairs." });
    }
    res.json({ repairs: rows });
  });
});

app.post("/api/owner/approve-payment", requireOwner, (req, res) => {
  const { paymentId } = req.body;
  if (!paymentId) return res.status(400).json({ error: "Missing paymentId." });

  const sql = `
    UPDATE payments 
    SET status = 'paid', 
        paid_date = CURRENT_TIMESTAMP 
    WHERE id = ?`;

  db.run(sql, [paymentId], function (err) {
    if (err) {
      console.error("Database error updating payment status:", err.message);
      return res.status(500).json({ error: "Failed to update payment status." });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: "Payment not found." });
    }
    res.json({ success: true, message: "Payment approved successfully." });
  });
});

/* ====== Leases (Owner) ====== */
app.get("/api/owner/leases", requireOwner, (req, res) => {
  const sql = `
    SELECT 
      l.id,
      r.room_number,
      u.name AS tenant_name,
      l.start_date,
      l.end_date,
      l.status
    FROM leases l
    JOIN users u ON l.tenant_id = u.id
    JOIN rooms r ON l.room_id = r.id
    ORDER BY date(l.end_date) ASC
  `;
  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error("Database error fetching leases:", err.message);
      return res.status(500).json({ error: "Failed to fetch leases" });
    }
    // คำนวณสถานะ expiring_soon (หมดอายุใน 30 วัน) เฉพาะสัญญา active
    const now = new Date();
    const mapped = (rows || []).map((x) => {
      let status = (x.status || "").toLowerCase();
      if (status === "active") {
        const end = new Date(x.end_date);
        const diffDays = Math.ceil((end - now) / (1000 * 60 * 60 * 24));
        if (diffDays >= 0 && diffDays <= 30) status = "expiring_soon";
      }
      return {
        id: x.id,
        room_number: x.room_number,
        tenant_name: x.tenant_name,
        start_date: x.start_date,
        end_date: x.end_date,
        status,
      };
    });
    res.json(mapped);
  });
});

app.post("/api/owner/leases", requireOwner, (req, res) => {
  const { room_id, tenant_id, start_date, end_date } = req.body;
  if (!room_id || !tenant_id || !start_date || !end_date) {
    return res.status(400).json({ error: "Please provide all required fields." });
  }

  const sql = `INSERT INTO leases (room_id, tenant_id, start_date, end_date, status) VALUES (?, ?, ?, ?, 'active')`;
  db.run(sql, [room_id, tenant_id, start_date, end_date], function (err) {
    if (err) {
      console.error("Database error creating lease:", err.message);
      return res.status(500).json({ error: "Failed to create new lease." });
    }
    res
      .status(201)
      .json({ success: true, message: "Lease created successfully.", leaseId: this.lastID });
  });
});

app.delete("/api/owner/leases/:id", requireOwner, (req, res) => {
  const { id } = req.params;
  const sql = `DELETE FROM leases WHERE id = ?`;
  db.run(sql, id, function (err) {
    if (err) {
      console.error("Database error deleting lease:", err.message);
      return res.status(500).json({ error: "Failed to delete lease." });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: "Lease not found." });
    }
    res.json({ success: true, message: "Lease deleted successfully." });
  });
});

/* ====== Owner: helpers ====== */
app.get("/api/owner/available-rooms", requireOwner, (req, res) => {
  // ใช้เกณฑ์ "ห้องที่ไม่มีผู้เช่าอยู่" เพื่อลดความคลาดเคลื่อนจากคอลัมน์ status
  const sql = `
    SELECT r.id, r.room_number
    FROM rooms r
    LEFT JOIN users u ON u.room_id = r.id AND u.role = 'tenant'
    WHERE u.id IS NULL
    ORDER BY CAST(r.room_number AS INTEGER) ASC, r.room_number ASC`;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});
app.get("/api/owner/available-tenants", requireOwner, (req, res) => {
  const sql = `
    SELECT u.id, u.name 
    FROM users u 
    WHERE u.role = 'tenant' AND u.id NOT IN (SELECT tenant_id FROM leases WHERE status = 'active')
  `;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post("/api/owner/repairs/update-status", requireOwner, (req, res) => {
  const { repairId, status } = req.body;
  if (!repairId || !status) {
    return res.status(400).json({ error: "Missing repairId or status." });
  }

  const statusMap = {
    pending: "pending",
    inprogress: "in-progress",
    done: "completed",
  };

  const dbStatus = statusMap[(status || "").toLowerCase()];
  if (!dbStatus) return res.status(400).json({ error: "Invalid status value." });

  const sql = `UPDATE maintenance_requests SET status = ? WHERE id = ?`;
  db.run(sql, [dbStatus, repairId], function (err) {
    if (err) {
      console.error("Database error updating repair status:", err.message);
      return res.status(500).json({ error: "Failed to update repair status." });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: "Repair request not found." });
    }
    res.json({ success: true, message: `Status updated to ${dbStatus}` });
  });
});


// === Announcements APIs (fixed & deduped) ===
app.get("/api/announcements", requireLogin, (req, res) => {
  const role = String(req.session?.user?.role || "").toLowerCase();

  if (role === "tenant") {
    const roomId = Number(req.session?.user?.room_id || 0);
    const sql = `
      SELECT a.id, a.title, a.content, a.target, a.created_at
      FROM announcements a
      WHERE a.target IN ('all','tenant')
         OR EXISTS (
            SELECT 1 FROM announcement_audience aa 
            WHERE aa.announcement_id = a.id AND aa.room_id = ?
         )
      ORDER BY a.created_at DESC`;
    return db.all(sql, [roomId], (err, rows) => {
      if (err) {
        console.error("Error fetching tenant announcements:", err);
        return res.status(500).json({ error: "Failed to fetch announcements" });
      }
      res.json(rows || []);
    });
  }

  // Owners/admins: show everything
  const sql = `SELECT id, title, content, target, created_at FROM announcements ORDER BY created_at DESC`;
  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error("Error fetching announcements:", err);
      return res.status(500).json({ error: "Failed to fetch announcements" });
    }
    res.json(rows || []);
  });
});

app.post("/api/announcements", requireLogin, (req, res) => {
  const role = String(req.session?.user?.role || "").toLowerCase();
  if (role !== "owner") {
    return res.status(403).json({ error: "Forbidden" });
  }
  const { title, content, target, roomIds } = req.body || {};
  if (!title || !content) {
    return res.status(400).json({ error: "Title and content are required." });
  }

  // If specific rooms are selected, force target = "room"
  const rooms = Array.isArray(roomIds) ? roomIds.map(n => Number(n)).filter(Number.isFinite) : [];
  const finalTarget = rooms.length > 0 ? "room" : (target ? String(target).toLowerCase() : "all");

  db.run(
    `INSERT INTO announcements (title, content, target) VALUES (?,?,?)`,
    [title, content, finalTarget],
    function (err) {
      if (err) {
        console.error("Error inserting announcement:", err);
        return res.status(500).json({ error: "Failed to create announcement" });
      }
      const annId = this.lastID;
      if (rooms.length === 0) {
        return res.json({ success: true, id: annId });
      }
      // Insert audience rows
      const stmt = db.prepare(`INSERT INTO announcement_audience (announcement_id, room_id) VALUES (?, ?)`);
      for (const rid of rooms) stmt.run([annId, rid]);
      stmt.finalize((e) => {
        if (e) {
          console.error("Audience insert error:", e);
          return res.status(500).json({ error: "Failed to set audience" });
        }
        res.json({ success: true, id: annId, audience_count: rooms.length });
      });
    }
  );
});


app.get("/api/maintenance-requests", requireLogin, (req, res) => {
  if (req.session.user.role !== "tenant") {
    return res.status(403).json({ error: "Forbidden" });
  }

  const tenantId = req.session.user.id;
  const sql = `
    SELECT id, issue_type, details, status, created_at
    FROM maintenance_requests
    WHERE tenant_id = ?
    ORDER BY created_at DESC`;
  db.all(sql, [tenantId], (err, rows) => {
    if (err) {
      console.error("Error fetching maintenance requests:", err);
      return res
        .status(500)
        .json({ error: "Failed to fetch maintenance requests" });
    }
    res.json(rows);
  });
});

app.post("/api/maintenance-requests", requireLogin, (req, res) => {
  if (req.session.user.role !== "tenant") {
    return res.status(403).json({ success: false, error: "Forbidden" });
  }
  const { "problem-type": problemType, "problem-details": details } = req.body;
  if (!problemType || !details) {
    return res
      .status(400)
      .json({ success: false, error: "กรุณากรอกข้อมูลให้ครบถ้วน" });
  }
  const tenantId = req.session.user.id;
  const sql = `
    INSERT INTO maintenance_requests (tenant_id, issue_type, details, status)
    VALUES (?, ?, ?, 'pending')`;
  db.run(sql, [tenantId, problemType, details], function (err) {
    if (err) {
      console.error("Database error creating maintenance request:", err.message);
      return res
        .status(500)
        .json({ success: false, error: "เกิดข้อผิดพลาดในการบันทึกข้อมูล" });
    }
    res.status(201).json({ success: true, message: "แจ้งซ่อมสำเร็จ!" });
  });
});

/* ====== Owner: Billing (ใช้ payments เป็นบิล) ====== */

// GET /api/owner/billing?month=9&year=2025
// ดึงบิลรายเดือนทั้งหมดจาก payments (อิง due_date เป็นเดือน/ปีนั้น)
app.get("/api/owner/billing", requireOwner, (req, res) => {
  const { month, year } = req.query;
  if (!month || !year) return res.status(400).json({ error: "Missing month/year" });

  const mm = String(month).padStart(2, "0");
  const sql = `
    SELECT
      p.id, r.room_number AS roomNumber, u.name AS tenantName,
      r.rent AS rent, p.amount, p.status, p.due_date AS dueDate, p.note
    FROM payments p
    JOIN users u ON p.tenant_id = u.id
    JOIN rooms r ON u.room_id = r.id
    WHERE STRFTIME('%m', p.due_date) = ? AND STRFTIME('%Y', p.due_date) = ?
      AND p.id IN (
        SELECT MAX(id) FROM payments
        WHERE STRFTIME('%m', due_date) = ? AND STRFTIME('%Y', due_date) = ?
        GROUP BY tenant_id
      )
    ORDER BY r.room_number ASC
  `;
  db.all(sql, [mm, String(year), mm, String(year)], (err, rows) => {
    if (err) return res.status(500).json({ error: "Failed to fetch billing" });
    const bills = (rows || []).map(row => {
      const note = safeParseJSON(row.note, null);
      if (note) {
        return {
          id: row.id,
          roomNumber: row.roomNumber,
          tenantName: row.tenantName,
          rent: row.rent,
          water_total: Number(note.water_total || 0),
          elec_total:  Number(note.elec_total  || 0),
          others:      Number(note.others      || 0),
          total: Number(row.amount || 0),
          status: row.status,
          dueDate: row.dueDate,
          // ค่าเริ่มต้นสำหรับโมดัล
          waterPrev: Number(note.waterPrev || 0),
          waterCurr: Number(note.waterCurr || 0),
          elecPrev:  Number(note.elecPrev  || 0),
          elecCurr:  Number(note.elecCurr  || 0),
        };
      } else {
        // fallback: ไม่มี note → กระจายส่วนเกินเป็น others
        const rent = Number(row.rent || 0);
        const amount = Number(row.amount || 0);
        const others = Math.max(0, amount - rent);
        return {
          id: row.id,
          roomNumber: row.roomNumber,
          tenantName: row.tenantName,
          rent,
          water_total: 0,
          elec_total:  0,
          others,
          total: amount,
          status: row.status,
          dueDate: row.dueDate,
          waterPrev: 0, waterCurr: 0, elecPrev: 0, elecCurr: 0,
        };
      }
    });
    res.json({ bills });
  });
});

// GET /api/owner/billing/:id  (ใช้ตอนเปิดโมดัล)
app.get("/api/owner/billing/:id", requireOwner, (req, res) => {
  const { id } = req.params;
  const sql = `
    SELECT p.id, r.room_number AS roomNumber, u.name AS tenantName,
           r.rent AS rent, p.amount, p.status, p.due_date AS dueDate, p.note
    FROM payments p
    JOIN users u ON p.tenant_id = u.id
    JOIN rooms r ON u.room_id = r.id
    WHERE p.id = ?`;
  db.get(sql, [id], (err, row) => {
    if (err) return res.status(500).json({ error: "Failed to fetch bill" });
    if (!row) return res.status(404).json({ error: "Bill not found" });
    const note = safeParseJSON(row.note, {});
    const rent = Number(row.rent || 0);
    const amount = Number(row.amount || 0);
    res.json({
      id: row.id,
      roomNumber: row.roomNumber,
      tenantName: row.tenantName,
      rent,
      waterPrev: Number(note.waterPrev || 0),
      waterCurr: Number(note.waterCurr || 0),
      elecPrev:  Number(note.elecPrev  || 0),
      elecCurr:  Number(note.elecCurr  || 0),
      others:    note.others != null ? Number(note.others) : Math.max(0, amount - rent),
      water_total: Number(note.water_total || 0),
      elec_total:  Number(note.elec_total  || 0),
      total: amount,
      status: row.status,
      dueDate: row.dueDate
    });
  });
});

// POST /api/owner/billing/generate  {month, year}
// สร้างบิลจากค่าเช่าล้วน ๆ ให้ผู้เช่าที่ "ยังไม่มีบิลเดือนนั้น"
app.post("/api/owner/billing/generate", requireOwner, (req, res) => {
  const { month, year } = req.body;
  if (!month || !year) return res.status(400).json({ error: "Missing month/year" });

  const due = lastDayOfMonthISO(Number(year), Number(month));
  const mm  = String(month).padStart(2, "0");

  const sql = `
    INSERT INTO payments (tenant_id, amount, status, due_date, note)
    SELECT u.id, r.rent, 'unpaid', ?, json('{}')
    FROM users u
    JOIN rooms r ON u.room_id = r.id
    WHERE u.role = 'tenant'
      AND NOT EXISTS (
        SELECT 1 FROM payments p
        WHERE p.tenant_id = u.id
          AND STRFTIME('%m', p.due_date) = ?
          AND STRFTIME('%Y', p.due_date) = ?
      )`;
  db.run(sql, [due, mm, String(year)], function (err) {
    if (err) return res.status(500).json({ error: "Failed to generate bills" });
    res.json({ success: true, inserted: this.changes || 0, dueDate: due });
  });
});

// PUT /api/owner/billing/:id  {waterPrev, waterCurr, elecPrev, elecCurr, others}
// คำนวณยอดรวมใหม่ แล้วอัปเดต payments.amount + เก็บรายละเอียดลง note (JSON)
app.put("/api/owner/billing/:id", requireOwner, (req, res) => {
  const { id } = req.params;
  const { waterPrev=0, waterCurr=0, elecPrev=0, elecCurr=0, others=0 } = req.body;

  // ต้องรู้ค่า rent ปัจจุบันจากห้อง เพื่อรวมยอด
  const sqlFetch = `
    SELECT r.rent AS rent, p.note
    FROM payments p
    JOIN users u ON p.tenant_id = u.id
    JOIN rooms r ON u.room_id = r.id
    WHERE p.id = ?`;
  db.get(sqlFetch, [id], (err, row) => {
    if (err) return res.status(500).json({ error: "Failed to load bill" });
    if (!row) return res.status(404).json({ error: "Bill not found" });

    const { rent } = row;
    const calc = computeBillTotals({ rent, waterPrev, waterCurr, elecPrev, elecCurr, others });

    const noteObj = {
      waterPrev, waterCurr, elecPrev, elecCurr, others,
      water_total: calc.water_total,
      elec_total:  calc.elec_total,
      rates: { water: BILL_WATER_RATE, elec: BILL_ELEC_RATE }
    };

    const sqlUpdate = `
      UPDATE payments
      SET amount = ?, note = ?
      WHERE id = ?`;
    db.run(sqlUpdate, [calc.total, JSON.stringify(noteObj), id], function (err2) {
      if (err2) return res.status(500).json({ error: "Failed to update bill" });
      if (this.changes === 0) return res.status(404).json({ error: "Bill not found" });
      res.json({ success: true, total: calc.total, detail: noteObj });
    });
  });
});

// POST /api/owner/billing/:id/mark-paid
app.post("/api/owner/billing/:id/mark-paid", requireOwner, (req, res) => {
  const { id } = req.params;
  const sql = `UPDATE payments SET status='paid', paid_date=CURRENT_TIMESTAMP WHERE id=?`;
  db.run(sql, [id], function (err) {
    if (err) return res.status(500).json({ error: "Failed to mark paid" });
    if (this.changes === 0) return res.status(404).json({ error: "Bill not found" });
    res.json({ success: true });
  });
});


app.get("/api/owner/available-rooms", requireOwner, (req, res) => {
  const sql = `SELECT id, room_number FROM rooms WHERE status IN ('available','vacant') ORDER BY room_number ASC`;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(rows || []);
  });
});

function safeParseJSON(s, fallback = {}) {
  try { return s ? JSON.parse(s) : fallback; } catch { return fallback; }
}

function computeBillTotals({ rent=0, waterPrev=0, waterCurr=0, elecPrev=0, elecCurr=0, others=0 }) {
  const wUnits = Math.max(0, Number(waterCurr) - Number(waterPrev));
  const eUnits = Math.max(0, Number(elecCurr) - Number(elecPrev));
  const water_total = wUnits * BILL_WATER_RATE;
  const elec_total  = eUnits * BILL_ELEC_RATE;
  const total = Number(rent) + water_total + elec_total + Number(others || 0);
  return { wUnits, eUnits, water_total, elec_total, total };
}

function lastDayOfMonthISO(year, month) {
  // month: 1-12 → ISO yyyy-mm-dd เป็นวันสิ้นเดือน
  const m = String(month).padStart(2, "0");
  const d = new Date(`${year}-${m}-01T00:00:00Z`);
  d.setUTCMonth(d.getUTCMonth() + 1);
  d.setUTCDate(0);
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${year}-${m}-${day}`;
}

// สร้างผู้เช่าใหม่ (owner เท่านั้น)
app.post("/api/owner/tenants", requireOwner, (req, res) => {
  const { name, email, phone, password, roomId } = req.body || {};

  if (!name || !email || !password) {
    return res.status(400).json({ success: false, error: "กรอกชื่อ อีเมล และรหัสผ่าน" });
  }

  // ใช้ hashPassword ที่มีอยู่แล้วในโปรเจ็กต์; ถ้าไม่มี ให้ใช้ fallback นี้:
  // const bcrypt = require("bcrypt");
  // const hashPassword = (p) => bcrypt.hashSync(p, bcrypt.genSaltSync(10));

  const checkSql = `SELECT id FROM users WHERE LOWER(email)=LOWER(?)`;
  db.get(checkSql, [email], (err, exists) => {
    if (err) return res.status(500).json({ success:false, error:"Database error (check email)" });
    if (exists) return res.status(409).json({ success:false, error:"อีเมลนี้ถูกใช้งานแล้ว" });

    const hashed = hashPassword(password);

    db.serialize(() => {
      db.run("BEGIN");
      let newTenantId;

      // 1) สร้างผู้เช่า
      const insertUserSql = `
        INSERT INTO users (name, email, phone, password, role)
        VALUES (?, ?, ?, ?, 'tenant')`;
      db.run(insertUserSql, [name, email, phone || null, hashed], function (err1) {
        if (err1) {
          db.run("ROLLBACK");
          return res.status(500).json({ success:false, error:"Database error (insert user)" });
        }
        newTenantId = this.lastID;

        // ไม่ผูกห้อง → จบเลย
        if (!roomId) {
          db.run("COMMIT");
          return res.json({ success:true, id:newTenantId });
        }

        // 2) ตรวจห้องว่างจริงก่อน
        const roomCheckSql = `SELECT id FROM rooms WHERE id = ? AND status IN ('available','vacant')`;
        db.get(roomCheckSql, [roomId], (err2, room) => {
          if (err2) {
            db.run("ROLLBACK");
            return res.status(500).json({ success:false, error:"Database error (check room)" });
          }
          if (!room) {
            db.run("ROLLBACK");
            return res.status(400).json({ success:false, error:"ห้องที่เลือกไม่ว่าง" });
          }

          // 3) ผูก room_id ให้ผู้เช่า + เปลี่ยนสถานะห้องเป็น occupied
          const updateUserSql = `UPDATE users SET room_id = ? WHERE id = ?`;
          const updateRoomSql = `UPDATE rooms SET status = 'occupied' WHERE id = ?`;

          db.run(updateUserSql, [roomId, newTenantId], function (err3) {
            if (err3) {
              db.run("ROLLBACK");
              return res.status(500).json({ success:false, error:"Database error (assign room)" });
            }
            db.run(updateRoomSql, [roomId], function (err4) {
              if (err4) {
                db.run("ROLLBACK");
                return res.status(500).json({ success:false, error:"Database error (update room)" });
              }

              // [ออปชัน] ถ้าต้องการ สร้างสัญญาเริ่มต้น
              // const leaseSql = `INSERT INTO leases (tenant_id, room_id, start_date, status) VALUES (?, ?, DATE('now'), 'active')`;
              // db.run(leaseSql, [newTenantId, roomId], () => { /* ignore */ });

              db.run("COMMIT");
              return res.json({ success:true, id:newTenantId });
            });
          });
        });
      });
    });
  });
});


app.post("/api/contact-message", requireLogin, (req, res) => {
  const { message } = req.body;
  const tenantId = req.session.user.id;

  if (!message) {
    return res
      .status(400)
      .json({ success: false, error: "Message cannot be empty." });
  }
  const sql = "INSERT INTO contact_messages (tenant_id, message) VALUES (?, ?)";
  db.run(sql, [tenantId, message], function (err) {
    if (err) {
      console.error("Database error saving contact message:", err.message);
      return res
        .status(500)
        .json({ success: false, error: "Failed to send message." });
    }
    res.status(201).json({ success: true, message: "Message sent successfully." });
  });
});

app.post("/api/moveout-request", requireLogin, (req, res) => {
  if (req.session.user.role !== "tenant") {
    return res.status(403).json({ success: false, error: "Forbidden" });
  }

  const {
    "moveout-date": moveoutDate,
    "moveout-reason": reason,
    "forwarding-address": forwardingAddress,
  } = req.body;

  const tenantId = req.session.user.id;

  if (!moveoutDate) {
    return res
      .status(400)
      .json({ success: false, error: "กรุณาระบุวันที่ต้องการย้ายออก" });
  }

  const sql = `
    INSERT INTO moveout_requests (tenant_id, moveout_date, reason, forwarding_address)
    VALUES (?, ?, ?, ?)
  `;

  db.run(sql, [tenantId, moveoutDate, reason, forwardingAddress], function (err) {
    if (err) {
      console.error("Database error creating move-out request:", err.message);
      return res
        .status(500)
        .json({ success: false, error: "เกิดข้อผิดพลาดในการบันทึกข้อมูล" });
    }
    res.status(201).json({ success: true, message: "แจ้งย้ายออกสำเร็จ!" });
  });
});
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});


/* ====== Owner: Tenants management extras ====== */

// GET /api/owner/tenants/:id - ข้อมูลโปรไฟล์ + ห้องปัจจุบัน
app.get("/api/owner/tenants/:id", requireOwner, (req, res) => {
  const { id } = req.params;
  const sql = `
    SELECT u.id, u.name, u.email, u.phone, u.room_id AS roomId,
           r.room_number AS roomNumber
    FROM users u
    LEFT JOIN rooms r ON u.room_id = r.id
    WHERE u.id = ? AND u.role = 'tenant'`;
  db.get(sql, [id], (err, row) => {
    if (err) return res.status(500).json({ error: "Failed to fetch tenant" });
    if (!row) return res.status(404).json({ error: "Tenant not found" });
    res.json(row);
  });
});

// PUT /api/owner/tenants/:id - อัปเดตโปรไฟล์ (ชื่อ/อีเมล/โทร/รหัสผ่าน)
app.put("/api/owner/tenants/:id", requireOwner, (req, res) => {
  const { id } = req.params;
  const { name, email, phone, password } = req.body || {};

  // ตรวจสอบมีผู้ใช้จริง
  db.get(`SELECT id FROM users WHERE id = ? AND role='tenant'`, [id], (err, exist) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!exist) return res.status(404).json({ error: "Tenant not found" });

    const fields = [];
    const params = [];

    if (name != null) { fields.push("name = ?"); params.push(name); }
    if (email != null) { fields.push("email = ?"); params.push(email); }
    if (phone != null) { fields.push("phone = ?"); params.push(phone); }

    if (password) {
      const hashed = hashPassword(password);
      fields.push("password = ?");
      params.push(hashed);
    }

    if (fields.length === 0) {
      return res.json({ success: true, message: "No changes" });
    }

    const sql = `UPDATE users SET ${fields.join(", ")} WHERE id = ?`;
    params.push(id);
    db.run(sql, params, function (err2) {
      if (err2) return res.status(500).json({ error: "Failed to update tenant" });
      res.json({ success: true });
    });
  });
});

// POST /api/owner/tenants/:id/move-room  {newRoomId}
app.post("/api/owner/tenants/:id/move-room", requireOwner, (req, res) => {
  const { id } = req.params;
  const { newRoomId } = req.body || {};
  if (!newRoomId) return res.status(400).json({ error: "Missing newRoomId" });

  db.serialize(() => {
    db.run("BEGIN");
    let oldRoomId = null;
    db.get(`SELECT room_id FROM users WHERE id = ? AND role='tenant'`, [id], (err1, row) => {
      if (err1) { db.run("ROLLBACK"); return res.status(500).json({ error: "DB error" }); }
      if (!row) { db.run("ROLLBACK"); return res.status(404).json({ error: "Tenant not found" }); }
      oldRoomId = row.room_id;

      // ตรวจสอบว่าห้องใหม่ว่าง (ไม่มีผู้เช่า)
      const checkSql = `
        SELECT r.id
        FROM rooms r
        LEFT JOIN users u ON u.room_id = r.id AND u.role='tenant'
        WHERE r.id = ? AND u.id IS NULL`;
      db.get(checkSql, [newRoomId], (err2, ok) => {
        if (err2) { db.run("ROLLBACK"); return res.status(500).json({ error: "DB error (check room)" }); }
        if (!ok)  { db.run("ROLLBACK"); return res.status(400).json({ error: "ห้องใหม่ไม่ว่าง" }); }

        db.run(`UPDATE users SET room_id = ? WHERE id = ?`, [newRoomId, id], function (err3) {
          if (err3) { db.run("ROLLBACK"); return res.status(500).json({ error: "Failed to assign room" }); }

          // อัปเดตสถานะห้อง (optional) เพื่อความสอดคล้องกับหน้าอื่น
          if (oldRoomId) {
            db.run(`UPDATE rooms SET status='vacant' WHERE id = ?`, [oldRoomId]);
          }
          db.run(`UPDATE rooms SET status='occupied' WHERE id = ?`, [newRoomId]);

          db.run("COMMIT");
          res.json({ success: true });
        });
      });
    });
  });
});



// POST /api/owner/tenants/:id/move-out  {moveOutDate?, notes?, createFinalBill?, finalAmount?}
app.post("/api/owner/tenants/:id/move-out", requireOwner, (req, res) => {
  const { id } = req.params;
  const { moveOutDate, notes, createFinalBill, finalAmount } = req.body || {};
  const endDate = moveOutDate || new Date().toISOString().slice(0,10);

  db.serialize(() => {
    db.run("BEGIN");
    // เอา room เดิมไว้ปรับสถานะ
    db.get(`SELECT room_id FROM users WHERE id = ? AND role='tenant'`, [id], (err1, u) => {
      if (err1) { db.run("ROLLBACK"); return res.status(500).json({ error: "DB error" }); }
      if (!u)   { db.run("ROLLBACK"); return res.status(404).json({ error: "Tenant not found" }); }
      const oldRoomId = u.room_id;

      // 1) users.room_id = NULL
      db.run(`UPDATE users SET room_id = NULL WHERE id = ?`, [id], function (err2) {
        if (err2) { db.run("ROLLBACK"); return res.status(500).json({ error: "Failed to unassign room" }); }

        // 2) ห้องเดิมเป็นว่าง
        if (oldRoomId) {
          db.run(`UPDATE rooms SET status='vacant' WHERE id = ?`, [oldRoomId]);
        }

        // 3) ปิดสัญญาที่ active ของผู้เช่าคนนี้ (ถ้ามี)
        const leaseSql = `
          UPDATE leases
          SET status = 'terminated', end_date = ?
          WHERE tenant_id = ? AND (status = 'active' OR status = 'ongoing')`;
        db.run(leaseSql, [endDate, id], function (err3) {
          if (err3) { db.run("ROLLBACK"); return res.status(500).json({ error: "Failed to update lease" }); }

          // 4) (ออปชัน) สร้างบิลสุดท้าย
          const goNext = () => {
            db.run("COMMIT");
            res.json({ success: true });
          };

          if (createFinalBill && finalAmount != null) {
            const insertPay = `
              INSERT INTO payments (tenant_id, amount, status, due_date, note)
              VALUES (?, ?, 'unpaid', ?, json(?))`;
            const noteObj = { finalBill: true, notes: notes || null };
            db.run(insertPay, [id, Number(finalAmount) || 0, endDate, JSON.stringify(noteObj)], function (err4) {
              if (err4) { db.run("ROLLBACK"); return res.status(500).json({ error: "Failed to create final bill" }); }
              goNext();
            });
          } else {
            goNext();
          }
        });
      });
    });
  });
});

// GET /api/owner/tenants/:id/payments  - ประวัติการชำระเงินของผู้เช่าคนนี้ (ใหม่→เก่า)
app.get("/api/owner/tenants/:id/payments", requireOwner, (req, res) => {
  const { id } = req.params;
  const sql = `
    SELECT p.id, p.amount, p.status, p.due_date AS dueDate, p.created_at AS createdAt
    FROM payments p
    WHERE p.tenant_id = ?
    ORDER BY date(p.due_date) DESC, p.id DESC`;
  db.all(sql, [id], (err, rows) => {
    if (err) return res.status(500).json({ error: "Failed to fetch payment history" });
    res.json({ payments: rows || [] });
  });
});


/* ==== FINANCE_MVP: Aging endpoint ==== */
app.get('/api/owner/aging', requireOwner, async (req, res) => {
  try {
    // Set today's date to midnight for accurate day-diff calculation
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const rows = await new Promise((resolve, reject) => {
      db.all(
        /*
         * IMPROVED QUERY:
         * - The subquery in the JOIN was replaced with a more efficient direct join.
         */
        `SELECT
           p.id,
           u.name AS tenant_name,
           r.room_number,
           p.due_date,
           p.amount
         FROM payments p
         JOIN users u ON u.id = p.tenant_id
         JOIN rooms r ON r.id = u.room_id
         WHERE p.status IN ('unpaid', 'pending', 'overdue')`,
        [],
        (err, rows) => {
          if (err) {
            reject(err);
          } else {
            resolve(rows || []);
          }
        }
      );
    });

    const buckets = { '0_30': [], '31_60': [], '61_90': [], '90_plus': [] };

    for (const rec of rows) {
      if (!rec.due_date) continue; // Skip if there's no due date

      // Normalize due date to midnight as well
      const due = new Date(rec.due_date);
      due.setHours(0, 0, 0, 0);

      const days = Math.floor((today - due) / (1000 * 60 * 60 * 24));

      if (days <= 0) continue; // Skip payments that are not yet overdue

      const row = {
        id: rec.id,
        room_number: rec.room_number,
        tenant_name: rec.tenant_name,
        due_date: rec.due_date,
        days_over: days,
        outstanding: Number(rec.amount || 0),
      };

      if (days <= 30) buckets['0_30'].push(row);
      else if (days <= 60) buckets['31_60'].push(row);
      else if (days <= 90) buckets['61_90'].push(row);
      else buckets['90_plus'].push(row);
    }

    res.json({ success: true, data: buckets });
  } catch (e) {
    console.error('Aging report error:', e);
    // Send a generic error message to the client for security
    res.status(500).json({ success: false, error: 'An internal server error occurred.' });
  }
});

// ===== Config: ensure room_types table =====
function ensureRoomTypesTable() {
  const sql = `CREATE TABLE IF NOT EXISTS room_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE,
    label TEXT,
    base_rent REAL,
    is_active INTEGER DEFAULT 1
  )`;
  db.run(sql);
}
ensureRoomTypesTable();

// GET current utility rates (latest)
app.get("/api/owner/config/utility-rates", requireOwner, (req, res) => {
  db.get("SELECT water_rate_per_unit AS water, electricity_rate_per_unit AS elec, other_rate_notes AS notes FROM utility_rates ORDER BY id DESC LIMIT 1", [], (err, row) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!row) return res.json({ water: 18.0, elec: 8.0, notes: "" });
    res.json(row);
  });
});

// Update utility rates (insert a new versioned row)
app.post("/api/owner/config/utility-rates", requireOwner, express.json(), (req, res) => {
  const { water, elec, notes } = req.body || {};
  const w = Number(water), e = Number(elec);
  if (!isFinite(w) || !isFinite(e)) return res.status(400).json({ error: "อัตราค่าน้ำ/ค่าไฟไม่ถูกต้อง" });
  const sql = `INSERT INTO utility_rates (water_rate_per_unit, electricity_rate_per_unit, other_rate_notes) VALUES (?,?,?)`;
  db.run(sql, [w, e, notes || null], function(err){
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ success: true, id: this.lastID });
  });
});

// CRUD room types
app.get("/api/owner/config/room-types", requireOwner, (req, res) => {
  db.all("SELECT id, key, label, base_rent, is_active FROM room_types ORDER BY id ASC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ types: rows });
  });
});

app.post("/api/owner/config/room-types", requireOwner, express.json(), (req, res) => {
  const { key, label, base_rent } = req.body || {};
  if (!key || !label || !isFinite(Number(base_rent))) return res.status(400).json({ error: "ข้อมูลไม่ครบถ้วน" });
  const sql = `INSERT INTO room_types (key, label, base_rent, is_active) VALUES (?,?,?,1)`;
  db.run(sql, [String(key).toLowerCase(), String(label), Number(base_rent)], function(err){
    if (err) return res.status(500).json({ error: "DB error, key อาจซ้ำ" });
    res.status(201).json({ id: this.lastID });
  });
});

app.put("/api/owner/config/room-types/:id", requireOwner, express.json(), (req, res) => {
  const { id } = req.params;
  const { key, label, base_rent, is_active } = req.body || {};
  const sql = `UPDATE room_types SET 
    key = COALESCE(?, key),
    label = COALESCE(?, label),
    base_rent = COALESCE(?, base_rent),
    is_active = COALESCE(?, is_active)
  WHERE id = ?`;
  db.run(sql, [
    key ? String(key).toLowerCase() : null,
    label ?? null,
    isFinite(Number(base_rent)) ? Number(base_rent) : null,
    typeof is_active === 'number' ? is_active : null,
    id
  ], function(err){
    if (err) return res.status(500).json({ error: "DB error" });
    if (this.changes === 0) return res.status(404).json({ error: "ไม่พบรายการ" });
    res.json({ success: true });
  });
});

app.delete("/api/owner/config/room-types/:id", requireOwner, (req, res) => {
  const { id } = req.params;
  db.run("UPDATE room_types SET is_active = 0 WHERE id = ?", [id], function(err){
    if (err) return res.status(500).json({ error: "DB error" });
    if (this.changes === 0) return res.status(404).json({ error: "ไม่พบรายการ" });
    res.json({ success: true });
  });
});

// Approvals: reject payment with reason
app.post("/api/owner/payments/:id/reject", requireOwner, express.json(), (req, res) => {
  const { id } = req.params;
  const { reason } = req.body || {};
  const sql = `UPDATE payments SET status='unpaid', note = COALESCE(?, note) WHERE id = ?`;
  db.run(sql, [reason || 'Rejected by owner', id], function(err){
    if (err) return res.status(500).json({ error: "Failed to reject payment" });
    if (this.changes === 0) return res.status(404).json({ error: "Payment not found" });
    // audit log (optional table exists)
    db.run("INSERT INTO payment_audits (payment_id, action, details, created_at) VALUES (?,?,?,CURRENT_TIMESTAMP)", [id, 'reject', reason || null], ()=>{});
    res.json({ success: true });
  });
});

// Simple reports summary
app.get("/api/owner/reports/summary", requireOwner, (req, res) => {
  const out = {};
  db.get("SELECT COUNT(*) AS total, SUM(CASE WHEN tenant_id IS NULL THEN 0 ELSE 1 END) AS occupied FROM rooms", [], (e, row) => {
    if (e) return res.status(500).json({ error: "DB error" });
    out.rooms = row || { total: 0, occupied: 0 };
    db.all(`SELECT strftime('%Y-%m', COALESCE(paid_date,due_date)) as ym, SUM(amount) as revenue 
            FROM payments WHERE status='paid' GROUP BY ym ORDER BY ym DESC LIMIT 12`, [], (e2, rows) => {
      if (e2) return res.status(500).json({ error: "DB error" });
      out.revenue = rows || [];
      res.json(out);
    });
  });
});


// ===== Move-in / Move-out =====
app.post("/api/owner/move-in", requireOwner, express.json(), (req, res) => {
  const { tenant_id, room_id, start_date, end_date } = req.body || {};
  if (!tenant_id || !room_id || !start_date || !end_date) return res.status(400).json({ error: "ข้อมูลไม่ครบ" });
  db.serialize(() => {
    db.run("BEGIN");
    db.run(`INSERT INTO leases (room_id, tenant_id, start_date, end_date, status) VALUES (?,?,?,?, 'active')`, 
      [room_id, tenant_id, start_date, end_date], function(err){
        if (err) { db.run("ROLLBACK"); return res.status(500).json({ error: "สร้างสัญญาไม่สำเร็จ" }); }
        const leaseId = this.lastID;
        db.run(`UPDATE users SET room_id = ? WHERE id = ? AND role='tenant'`, [room_id, tenant_id], function(e1){
          if (e1) { db.run("ROLLBACK"); return res.status(500).json({ error: "อัปเดตผู้เช่าไม่สำเร็จ" }); }
          db.run(`UPDATE rooms SET status='occupied', tenant_id=? WHERE id=?`, [tenant_id, room_id], function(e2){
            if (e2) { db.run("ROLLBACK"); return res.status(500).json({ error: "อัปเดตห้องไม่สำเร็จ" }); }
            db.run("COMMIT");
            res.json({ success: true, leaseId });
          });
        });
      });
  });
});

app.post("/api/owner/move-out", requireOwner, express.json(), (req, res) => {
  const { lease_id, note } = req.body || {};
  if (!lease_id) return res.status(400).json({ error: "ต้องระบุ lease_id" });
  db.get(`SELECT l.id, l.room_id, l.tenant_id FROM leases l WHERE l.id = ? AND l.status='active'`, [lease_id], (err, row) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (!row) return res.status(404).json({ error: "ไม่พบสัญญา active" });
    db.serialize(()=>{
      db.run("BEGIN");
      db.run(`UPDATE leases SET status='closed', end_date = COALESCE(end_date, DATE('now')) WHERE id=?`, [lease_id], function(e1){
        if (e1) { db.run("ROLLBACK"); return res.status(500).json({ error: "ปิดสัญญาไม่สำเร็จ" }); }
        db.run(`UPDATE users SET room_id = NULL WHERE id = ? AND role='tenant'`, [row.tenant_id], function(e2){
          if (e2) { db.run("ROLLBACK"); return res.status(500).json({ error: "อัปเดตผู้เช่าไม่สำเร็จ" }); }
          db.run(`UPDATE rooms SET status='vacant', tenant_id=NULL WHERE id=?`, [row.room_id], function(e3){
            if (e3) { db.run("ROLLBACK"); return res.status(500).json({ error: "อัปเดตห้องไม่สำเร็จ" }); }
            db.run(`INSERT INTO messages (tenant_id, message, created_at) VALUES (?,?, CURRENT_TIMESTAMP)`, [row.tenant_id, note || 'move-out'], ()=>{});
            db.run("COMMIT");
            res.json({ success: true });
          });
        });
      });
    });
  });
});
