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
    secret:
      process.env.SESSION_SECRET ||
      "a-very-strong-and-static-secret-key-that-you-should-change",
    resave: false,
    saveUninitialized: true,
    cookie: {
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
    const dir = "uploads/";
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir);
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    const paymentId = req.body.paymentId;
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const filename = `slip-${paymentId}-${uniqueSuffix}${path.extname(
      file.originalname
    )}`;
    cb(null, filename);
  },
});

const upload = multer({ storage: storage });

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
  } else {
    return res
      .status(401)
      .send("You must be logged in to access this resource.");
  }
}

app.get("/", (req, res) => {
  res.redirect("/login.html");
});

app.post("/login", loginLimiter, (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM users WHERE email = ?";

  db.get(sql, [email], (err, user) => {
    if (err) {
      return res.status(500).send("Server error");
    }
    if (user && comparePassword(password, user.password)) {
      const { password, ...userData } = user;
      userData.role = user.role ? user.role.toLowerCase() : "";
      req.session.user = userData;

      if (userData.role === "owner") {
        res.redirect("/owner");
      } else {
        res.redirect("/tenant");
      }
    } else {
      res.redirect("/login.html?error=1");
    }
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.redirect("/");
    }
    res.clearCookie("connect.sid");
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
  if (req.session.user) {
    res.json({ user: req.session.user });
  } else {
    res.status(401).json({ error: "Not authenticated" });
  }
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
    if (row) {
      res.json({ success: true, data: row });
    } else {
      res.status(404).json({ success: false, error: "ไม่พบข้อมูลผู้ใช้" });
    }
  });
});

app.get("/api/tenant/dashboard", requireLogin, (req, res) => {
  if (req.session.user.role !== "tenant") {
    return res.status(403).json({ error: "Forbidden" });
  }

  const tenantId = req.session.user.id;
  const dashboardData = {
    userInfo: req.session.user,
  };
  const dbPromises = [];

  dbPromises.push(
    new Promise((resolve, reject) => {
      const paymentSql = `
            SELECT id, amount, due_date, status
            FROM payments
            WHERE tenant_id = ? AND status IN ('pending', 'overdue')
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
      const roomSql = `SELECT r.rent FROM rooms r JOIN users u ON u.room_id = r.id WHERE u.id = ?`;
      db.get(roomSql, [tenantId], (err, roomRow) => {
        if (err) return reject(err);
        const room_rent = roomRow ? roomRow.rent : 0;

        const utilitiesSql = `SELECT water_fee, elec_usage FROM utilities WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1`;
        db.get(utilitiesSql, [tenantId], (err, utilRow) => {
          if (err) return reject(err);
          let water_bill = 0;
          let electricity_bill = 0;
          if (utilRow) {
            water_bill = utilRow.water_fee || 0;
            const electricityRate = 4.1;
            electricity_bill = (utilRow.elec_usage || 0) * electricityRate;
          }
          const totalAmount = room_rent + water_bill + electricity_bill;
          if (dashboardData.payment) {
            dashboardData.payment.amount = totalAmount;
          }
          resolve();
        });
      });
    })
  );

  Promise.all(dbPromises)
    .then(() => {
      res.json(dashboardData);
    })
    .catch((err) => {
      console.error("Error fetching dashboard data:", err);
      res.status(500).json({ error: "Failed to fetch dashboard data" });
    });
});

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
    `;
  db.get(sql, [tenantId], (err, row) => {
    if (err) {
      console.error("Database error fetching contract details:", err.message);
      return res
        .status(500)
        .json({ error: "เกิดข้อผิดพลาดในการดึงข้อมูลสัญญา" });
    }
    if (!row) {
      return res.status(404).json({ error: "ไม่พบข้อมูลสัญญาเช่า" });
    }
    res.json(row);
  });
});

app.get("/api/billing-details", requireLogin, (req, res) => {
  if (req.session.user.role !== "tenant") {
    return res.status(403).json({ error: "Forbidden" });
  }
  const tenantId = req.session.user.id;
  let billingDetails = {};

  const roomSql = `SELECT r.rent FROM rooms r JOIN users u ON u.room_id = r.id WHERE u.id = ?`;
  db.get(roomSql, [tenantId], (err, roomRow) => {
    if (err)
      return res.status(500).json({ error: "Failed to fetch billing details" });
    billingDetails.room_rent = roomRow ? roomRow.rent : 0;

    const utilitiesSql = `SELECT water_fee, elec_usage FROM utilities WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1`;
    db.get(utilitiesSql, [tenantId], (err, utilRow) => {
      if (err)
        return res
          .status(500)
          .json({ error: "Failed to fetch billing details" });

      if (utilRow) {
        billingDetails.water_bill = utilRow.water_fee || 0;
        const electricityRate = 4.1;
        billingDetails.electricity_bill =
          (utilRow.elec_usage || 0) * electricityRate;
      } else {
        billingDetails.water_bill = 0;
        billingDetails.electricity_bill = 0;
      }
      billingDetails.total_amount =
        billingDetails.room_rent +
        billingDetails.water_bill +
        billingDetails.electricity_bill;
      res.json(billingDetails);
    });
  });
});

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
    const sql = `
        UPDATE payments
        SET status = 'paid', paid_date = CURRENT_TIMESTAMP, slip_filename = ?
        WHERE id = ? AND tenant_id = ?`;
    db.run(sql, [slipFilename, paymentId, req.session.user.id], function (err) {
      if (err) {
        console.error("Database error during slip upload:", err);
        return res.status(500).json({ error: "Database error." });
      }
      if (this.changes === 0) {
        return res
          .status(404)
          .json({
            error:
              "Payment not found or you do not have permission to update it.",
          });
      }
      res.json({
        success: true,
        message: "Slip uploaded successfully!",
        filename: slipFilename,
      });
    });
  }
);

app.get("/api/announcements", requireLogin, (req, res) => {
  const sql = `
        SELECT id, title, content, target, created_at
        FROM announcements
        WHERE target = 'all' OR LOWER(target) = ?
        ORDER BY created_at DESC`;
  db.all(sql, [req.session.user.role.toLowerCase()], (err, rows) => {
    if (err) {
      console.error("Error fetching announcements:", err);
      return res.status(500).json({ error: "Failed to fetch announcements" });
    }
    res.json(rows);
  });
});

app.post("/api/announcements", requireLogin, (req, res) => {
  if (req.session.user.role !== "owner") {
    return res.status(403).json({ error: "Forbidden" });
  }
  const { title, content, target } = req.body;
  if (!title || !content) {
    return res.status(400).json({ error: "Title and content are required." });
  }
  const sql = `INSERT INTO announcements (title, content, target) VALUES (?, ?, ?)`;
  db.run(
    sql,
    [title, content, target ? target.toLowerCase() : "all"],
    function (err) {
      if (err) {
        console.error("Error inserting announcement:", err);
        return res.status(500).json({ error: "Failed to create announcement" });
      }
      res.json({ success: true, id: this.lastID });
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
      console.error(
        "Database error creating maintenance request:",
        err.message
      );
      return res
        .status(500)
        .json({ success: false, error: "เกิดข้อผิดพลาดในการบันทึกข้อมูล" });
    }
    res.status(201).json({ success: true, message: "แจ้งซ่อมสำเร็จ!" });
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
    res
      .status(201)
      .json({ success: true, message: "Message sent successfully." });
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

  db.run(
    sql,
    [tenantId, moveoutDate, reason, forwardingAddress],
    function (err) {
      if (err) {
        console.error("Database error creating move-out request:", err.message);
        return res
          .status(500)
          .json({ success: false, error: "เกิดข้อผิดพลาดในการบันทึกข้อมูล" });
      }
      res.status(201).json({ success: true, message: "แจ้งย้ายออกสำเร็จ!" });
    }
  );
});

const requireOwner = (req, res, next) => {
  if (req.session.user && req.session.user.role === "owner") {
    next();
  } else {
    res.status(403).json({ error: "Forbidden: Access is denied." });
  }
};

app.get("/api/owner/dashboard", requireOwner, (req, res) => {
  const queries = {
    vacantRooms:
      "SELECT COUNT(*) as count FROM rooms WHERE status = 'available'",
    overduePayments:
      "SELECT COUNT(*) as count FROM payments WHERE status = 'overdue'",
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
      results[key] = (row && row.count) || (row && row.total) || 0;
      completed++;

      if (completed === totalQueries) {
        const alertSql = `
                        SELECT u.name as tenant_name, r.room_number, mr.issue_type 
                        FROM maintenance_requests mr
                        JOIN users u ON mr.tenant_id = u.id
                        JOIN rooms r ON u.room_id = r.id
                        WHERE mr.status = 'pending' 
                        ORDER BY mr.created_at DESC LIMIT 5
                    `;
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
  const sql = `
        SELECT
            r.room_number as roomNumber,
            u.name,
            u.phone,
            COALESCE(p.status, 'No Data') as paymentStatus
        FROM users u
        JOIN rooms r ON u.room_id = r.id
        LEFT JOIN (
            SELECT tenant_id, status
            FROM payments
            WHERE id IN (
                SELECT MAX(id)
                FROM payments
                GROUP BY tenant_id
            )
        ) p ON u.id = p.tenant_id
        WHERE u.role = 'tenant'
    `;

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error("Database error fetching tenants:", err.message);
      return res.status(500).json({ error: "Failed to fetch tenant data." });
    }
    res.json({ tenants: rows });
  });
});

app.get('/api/owner/accounting', requireOwner, (req, res) => {
    const sql = `
        SELECT
            p.id as paymentId,
            r.room_number as roomNumber,
            u.name as tenantName,
            p.amount,
            p.status,
            p.slip_filename as slipFilename
        FROM payments p
        JOIN users u ON p.tenant_id = u.id
        JOIN rooms r ON u.room_id = r.id
        WHERE p.id IN (
            SELECT MAX(id)
            FROM payments
            GROUP BY tenant_id
        )
        ORDER BY
            CASE p.status
                WHEN 'pending' THEN 1
                WHEN 'overdue' THEN 2
                WHEN 'paid' THEN 3
                ELSE 4
            END,
            r.room_number ASC;
    `;

    db.all(sql, [], (err, rows) => {
        if (err) {
            console.error("Database error fetching accounting data:", err.message);
            return res.status(500).json({ error: 'Failed to fetch accounting data.' });
        }
        res.json({ accountingData: rows });
    });
});



app.get('/api/owner/rooms', requireOwner, (req, res) => {
    const sql = `
        SELECT
            r.id,
            r.room_number,
            r.type,
            r.rent,
            r.status,
            CASE 
                WHEN r.status = 'occupied' THEN u.name 
                ELSE NULL 
            END AS tenant_name
        FROM rooms r
        LEFT JOIN users u ON r.id = u.room_id AND u.role = 'tenant'
        ORDER BY r.room_number ASC
    `;

    db.all(sql, [], (err, rows) => {
        if (err) {
            console.error("Database error fetching rooms:", err.message);
            return res.status(500).json({ error: 'Failed to fetch room data.' });
        }

        const formattedRooms = rows.map(row => ({
            id: row.id,
            roomNumber: row.room_number,
            type: row.type,
            rent: row.rent,
            status: row.status === 'occupied' ? 'Occupied' : 'Vacant',
            tenant: row.tenant_name || '-', 
        }));

        res.json({ rooms: formattedRooms });
    });
});

app.get('/api/owner/repairs', requireOwner, (req, res) => {
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
            return res.status(500).json({ error: 'Failed to fetch repairs.' });
        }
        res.json({ repairs: rows });
    });
});

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
    
    // Change status to 'pending' instead of 'paid'
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
        return res
          .status(404)
          .json({
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

app.post('/api/owner/approve-payment', requireOwner, (req, res) => {
    const { paymentId } = req.body;

    if (!paymentId) {
        return res.status(400).json({ error: 'Missing paymentId.' });
    }
    
    const sql = `
        UPDATE payments 
        SET status = 'paid', 
            paid_date = CURRENT_TIMESTAMP 
        WHERE id = ?`;

    db.run(sql, [paymentId], function(err) {
        if (err) {
            console.error("Database error updating payment status:", err.message);
            return res.status(500).json({ error: 'Failed to update payment status.' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Payment not found.' });
        }
        res.json({ success: true, message: 'Payment approved successfully.' });
    });
});

app.get('/api/owner/leases', requireOwner, (req, res) => {
    const sql = `
        SELECT 
            l.id,
            r.room_number,
            u.name AS tenant_name,
            l.start_date,
            l.end_date,
            l.status
        FROM leases l
        JOIN rooms r ON l.room_id = r.id
        JOIN users u ON l.tenant_id = u.id
        ORDER BY l.start_date DESC
    `;
    db.all(sql, [], (err, rows) => {
        if (err) {
            console.error("Database error fetching leases:", err.message);
            return res.status(500).json({ error: "Failed to fetch leases." });
        }
        res.json(rows);
    });
});

// Add a new lease
app.post('/api/owner/leases', requireOwner, (req, res) => {
    const { room_id, tenant_id, start_date, end_date } = req.body;
    if (!room_id || !tenant_id || !start_date || !end_date) {
        return res.status(400).json({ error: 'Please provide all required fields.' });
    }

    const sql = `INSERT INTO leases (room_id, tenant_id, start_date, end_date, status) VALUES (?, ?, ?, ?, 'active')`;
    db.run(sql, [room_id, tenant_id, start_date, end_date], function(err) {
        if (err) {
            console.error("Database error creating lease:", err.message);
            return res.status(500).json({ error: 'Failed to create new lease.' });
        }
        res.status(201).json({ success: true, message: 'Lease created successfully.', leaseId: this.lastID });
    });
});


// Update a lease
app.put('/api/owner/leases/:id', requireOwner, (req, res) => {
    const { id } = req.params;
    const { start_date, end_date, status } = req.body;

    if (!start_date || !end_date || !status) {
        return res.status(400).json({ error: 'Missing required fields.' });
    }

    const sql = `UPDATE leases SET start_date = ?, end_date = ?, status = ? WHERE id = ?`;
    db.run(sql, [start_date, end_date, status, id], function(err) {
        if (err) {
            console.error("Database error updating lease:", err.message);
            return res.status(500).json({ error: 'Failed to update lease.' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Lease not found.' });
        }
        res.json({ success: true, message: 'Lease updated successfully.' });
    });
});


// Delete a lease
app.delete('/api/owner/leases/:id', requireOwner, (req, res) => {
    const { id } = req.params;
    const sql = `DELETE FROM leases WHERE id = ?`;
    db.run(sql, id, function(err) {
        if (err) {
            console.error("Database error deleting lease:", err.message);
            return res.status(500).json({ error: 'Failed to delete lease.' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Lease not found.' });
        }
        res.json({ success: true, message: 'Lease deleted successfully.' });
    });
});

// Helper endpoints to get available rooms and tenants for the form
app.get('/api/owner/available-rooms', requireOwner, (req, res) => {
    const sql = `SELECT id, room_number FROM rooms WHERE status = 'available'`;
    db.all(sql, [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

app.get('/api/owner/available-tenants', requireOwner, (req, res) => {
    // This query finds tenants who are not currently assigned to an active lease
    const sql = `
        SELECT u.id, u.name 
        FROM users u 
        WHERE u.role = 'tenant' AND u.id NOT IN (SELECT tenant_id FROM leases WHERE status = 'active')
    `;
    db.all(sql, [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

app.post('/api/owner/repairs/update-status', requireOwner, (req, res) => {
    const { repairId, status } = req.body;

    if (!repairId || !status) {
        return res.status(400).json({ error: 'Missing repairId or status.' });
    }

    const statusMap = {
        'pending': 'pending',
        'inprogress': 'in-progress',
        'done': 'completed'
    };
    
    const dbStatus = statusMap[status.toLowerCase()];

    if (!dbStatus) {
        return res.status(400).json({ error: 'Invalid status value.' });
    }
    
    const sql = `UPDATE maintenance_requests SET status = ? WHERE id = ?`;

    db.run(sql, [dbStatus, repairId], function(err) {
        if (err) {
            console.error("Database error updating repair status:", err.message);
            return res.status(500).json({ error: 'Failed to update repair status.' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Repair request not found.' });
        }
        res.json({ success: true, message: `Status updated to ${dbStatus}` });
    });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});