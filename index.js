const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const app = express();
const port = 3000;

// --- Database Connection ---
const db = new sqlite3.Database('./app_full.db', (err) => {
    if (err) {
        console.error('Error connecting to the database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

// --- Middleware ---
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // Serve uploaded files

// Generate a secure, random secret for the session
const sessionSecret = crypto.randomBytes(64).toString('hex');

app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false
    }
}));

// --- Multer Configuration for File Uploads ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = 'uploads/';
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir);
        }
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        const paymentId = req.body.paymentId;
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const filename = `slip-${paymentId}-${uniqueSuffix}${path.extname(file.originalname)}`;
        cb(null, filename);
    }
});

const upload = multer({ storage: storage });


// --- Helper Functions (Using bcrypt for secure password hashing) ---
function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hashSync(password, saltRounds);
}

function comparePassword(password, hash) {
    return bcrypt.compareSync(password, hash);
}

// Custom middleware to check if the user is logged in (Declared only ONCE)
function requireLogin(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    } else {
        return res.status(401).send('You must be logged in to access this resource.');
    }
}


// --- Routes ---
app.get('/', (req, res) => {
    res.redirect('/login.html');
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.get(sql, [email], (err, user) => {
        if (err) {
            return res.status(500).send('Server error');
        }
        if (user && comparePassword(password, user.password)) {
            const { password, ...userData } = user;
            // Normalize role to lowercase for consistency
            userData.role = user.role ? user.role.toLowerCase() : '';
            req.session.user = userData;
            if (userData.role === 'owner') {
                res.redirect('/owner');
            } else {
                res.redirect('/tenant');
            }
        } else {
            res.redirect('/login.html?error=1');
        }
    });
});

app.get('/owner', (req, res) => {
    if (req.session.user && req.session.user.role === 'owner') {
        res.sendFile(path.join(__dirname, 'public', 'owner.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/tenant', (req, res) => {
    if (req.session.user && req.session.user.role === 'tenant') {
        res.sendFile(path.join(__dirname, 'public', 'tenant.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/api/tenant/dashboard', requireLogin, (req, res) => {
    if (req.session.user.role !== 'tenant') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const tenantId = req.session.user.id;
    const dashboardData = {};
    dashboardData.userInfo = req.session.user;

    // Temporary variables to hold billing components
    let room_rent = 0;
    let water_bill = 0;
    let electricity_bill = 0;

    const dbPromises = [];

    // Promise to get the base payment record (ID, due_date, etc.)
    dbPromises.push(new Promise((resolve, reject) => {
        const paymentSql = `
      SELECT id, amount, due_date, status
      FROM payments
      WHERE tenant_id = ? AND status IN ('pending', 'overdue')
      ORDER BY due_date DESC
      LIMIT 1`;
        db.get(paymentSql, [tenantId], (err, row) => {
            if (err) return reject(err);
            dashboardData.payment = row || null;
            resolve();
        });
    }));

    // Promise to get maintenance request info
    dbPromises.push(new Promise((resolve, reject) => {
        const maintenanceSql = `
      SELECT issue_type, status, COUNT(*) as count
      FROM maintenance_requests
      WHERE tenant_id = ? AND status != 'completed'`;
        db.get(maintenanceSql, [tenantId], (err, row) => {
            if (err) return reject(err);
            dashboardData.maintenance = row || null;
            resolve();
        });
    }));

    // Promise to get the latest announcement
    dbPromises.push(new Promise((resolve, reject) => {
        const announcementSql = `
      SELECT title
      FROM announcements
      ORDER BY created_at DESC
      LIMIT 1`;
        db.get(announcementSql, [], (err, row) => {
            if (err) return reject(err);
            dashboardData.announcement = row || null;
            resolve();
        });
    }));

    // --- ADDED LOGIC: Fetch billing details to calculate the correct total ---
    dbPromises.push(new Promise((resolve, reject) => {
        const roomSql = `
        SELECT r.rent
        FROM rooms r
        JOIN users u ON u.room_id = r.id
        WHERE u.id = ?`;
        db.get(roomSql, [tenantId], (err, row) => {
            if (err) return reject(err);
            room_rent = row ? row.rent : 0;
            resolve();
        });
    }));

    dbPromises.push(new Promise((resolve, reject) => {
        const utilitiesSql = `
          SELECT water_fee, elec_usage
          FROM utilities
          WHERE tenant_id = ?
          ORDER BY created_at DESC
          LIMIT 1`;
        db.get(utilitiesSql, [tenantId], (err, row) => {
            if (err) return reject(err);
            if (row) {
                water_bill = row.water_fee || 0;
                const electricityRate = 4.1;
                electricity_bill = (row.elec_usage || 0) * electricityRate;
            }
            resolve();
        });
    }));
    // --- END of ADDED LOGIC ---

    Promise.all(dbPromises)
        .then(() => {
            if (dashboardData.payment) {
                const totalAmount = room_rent + water_bill + electricity_bill;
                dashboardData.payment.amount = totalAmount;
            }
            res.json(dashboardData);
        })
        .catch(err => {
            console.error('Error fetching dashboard data:', err);
            res.status(500).json({ error: 'Failed to fetch dashboard data' });
        });
});

// =================================================================
// --- API: Get Tenant's Contract/Lease Details ---
// =================================================================
app.get('/api/contract-details', requireLogin, (req, res) => {
    // ตรวจสอบว่าเป็นผู้เช่า (tenant) หรือไม่
    if (req.session.user.role !== 'tenant') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const tenantId = req.session.user.id;

    // SQL query เพื่อดึงข้อมูลสัญญาเช่าที่เกี่ยวข้องกับผู้เช่าคนปัจจุบัน
    // โดย JOIN ตาราง users, leases, และ rooms เข้าด้วยกัน
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

    // สั่งให้ฐานข้อมูลทำงาน
    db.get(sql, [tenantId], (err, row) => {
        if (err) {
            console.error('Database error fetching contract details:', err.message);
            return res.status(500).json({ error: 'เกิดข้อผิดพลาดในการดึงข้อมูลสัญญา' });
        }
        if (!row) {
            return res.status(404).json({ error: 'ไม่พบข้อมูลสัญญาเช่า' });
        }
        
        // ส่งข้อมูลที่ได้กลับไปเป็น JSON
        res.json(row);
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/');
        }
        res.clearCookie('connect.sid');
        res.redirect('/login.html');
    });
});

app.get('/api/billing-details', requireLogin, (req, res) => {
    if (req.session.user.role !== 'tenant') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const tenantId = req.session.user.id;
    let billingDetails = {};
    const dbPromises = [];

    dbPromises.push(new Promise((resolve, reject) => {
        const roomSql = `
            SELECT r.rent
            FROM rooms r
            JOIN users u ON u.room_id = r.id
            WHERE u.id = ?`;
        db.get(roomSql, [tenantId], (err, row) => {
            if (err) return reject(err);
            billingDetails.room_rent = row ? row.rent : 0;
            resolve();
        });
    }));

    dbPromises.push(new Promise((resolve, reject) => {
        const utilitiesSql = `
            SELECT water_fee, elec_usage
            FROM utilities
            WHERE tenant_id = ?
            ORDER BY created_at DESC
            LIMIT 1`;
        db.get(utilitiesSql, [tenantId], (err, row) => {
            if (err) return reject(err);
            if (row) {
                billingDetails.water_bill = row.water_fee || 0;
                const electricityRate = 4.1;
                billingDetails.electricity_bill = (row.elec_usage || 0) * electricityRate;
            } else {
                billingDetails.water_bill = 0;
                billingDetails.electricity_bill = 0;
            }
            resolve();
        });
    }));

    Promise.all(dbPromises)
        .then(() => {
            billingDetails.total_amount = billingDetails.room_rent + billingDetails.water_bill + billingDetails.electricity_bill;
            res.json(billingDetails);
        })
        .catch(err => {
            console.error('Error fetching billing details:', err);
            res.status(500).json({ error: 'Failed to fetch billing details' });
        });
});

// --- Get all announcements (tenant view) ---
app.get('/api/announcements', requireLogin, (req, res) => {
    const sql = `
        SELECT id, title, content, target, created_at
        FROM announcements
        WHERE target = 'all' OR LOWER(target) = ?
        ORDER BY created_at DESC`;
    db.all(sql, [req.session.user.role.toLowerCase()], (err, rows) => {
        if (err) {
            console.error('Error fetching announcements:', err);
            return res.status(500).json({ error: 'Failed to fetch announcements' });
        }
        res.json(rows);
    });
});

// --- Owner creates a new announcement ---
app.post('/api/announcements', requireLogin, (req, res) => {
    if (req.session.user.role !== 'owner') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const { title, content, target } = req.body;
    if (!title || !content) {
        return res.status(400).json({ error: 'Title and content are required.' });
    }
    const sql = `INSERT INTO announcements (title, content, target) VALUES (?, ?, ?)`;
    db.run(sql, [title, content, target ? target.toLowerCase() : 'all'], function (err) {
        if (err) {
            console.error('Error inserting announcement:', err);
            return res.status(500).json({ error: 'Failed to create announcement' });
        }
        res.json({ success: true, id: this.lastID });
    });
});

app.get('/api/maintenance-requests', requireLogin, (req, res) => {
    // ตรวจสอบว่าเป็นผู้เช่าหรือไม่
    if (req.session.user.role !== 'tenant') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const tenantId = req.session.user.id;
    const sql = `
        SELECT id, issue_type, details, status, created_at
        FROM maintenance_requests
        WHERE tenant_id = ?
        ORDER BY created_at DESC`; // เรียงลำดับจากล่าสุดไปเก่าสุด

    db.all(sql, [tenantId], (err, rows) => {
        if (err) {
            console.error('Error fetching maintenance requests:', err);
            return res.status(500).json({ error: 'Failed to fetch maintenance requests' });
        }
        res.json(rows); // ส่งข้อมูลกลับไปเป็น JSON
    });
});

app.get('/api/repairs', requireLogin, (req, res) => {
    if (req.session.user.role !== 'tenant') {
        return res.status(403).json({
            error: 'Forbidden'
        });
    }

    const tenantId = req.session.user.id;
    const sql = `
    SELECT issue_type, details, status, created_at
    FROM maintenance_requests
    WHERE tenant_id = ?
    ORDER BY created_at DESC`;

    db.all(sql, [tenantId], (err, rows) => {
        if (err) {
            console.error('Error fetching maintenance requests:', err);
            return res.status(500).json({
                error: 'Failed to fetch maintenance requests'
            });
        }
        res.json(rows);
    });
});

// --- New Route for Slip Upload ---
app.post('/api/upload-slip', requireLogin, upload.single('paymentSlip'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Please upload a file.' });
    }

    const { paymentId } = req.body;
    const slipFilename = req.file.filename;

    if (!paymentId) {
        return res.status(400).json({ error: 'Payment ID is missing.' });
    }

    const sql = `
        UPDATE payments
        SET
            status = 'paid',
            paid_date = CURRENT_DATE,
            slip_filename = ?
        WHERE
            id = ? AND tenant_id = ?`;

    db.run(sql, [slipFilename, paymentId, req.session.user.id], function (err) {
        if (err) {
            console.error('Database error during slip upload:', err);
            return res.status(500).json({ error: 'Database error.' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Payment not found or you do not have permission to update it.' });
        }
        res.json({ success: true, message: 'Slip uploaded successfully!', filename: slipFilename });
    });
});


app.get('/api/userinfo', (req, res) => {
    if (req.session.user) {
        res.json({ user: req.session.user });
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
});

// =================================================================
// --- API: เพิ่มรายการแจ้งซ่อมใหม่ (ระบบใหม่) ---
// =================================================================
app.post('/api/maintenance-requests', requireLogin, (req, res) => {
    // ตรวจสอบก่อนว่าผู้ใช้ที่ล็อกอินอยู่คือ 'tenant' (ผู้เช่า)
    if (req.session.user.role !== 'tenant') {
        return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    // ดึงข้อมูลประเภทปัญหาและรายละเอียดที่ส่งมาจากหน้าเว็บ
    const { 'problem-type': problemType, 'problem-details': details } = req.body;
    const tenantId = req.session.user.id;

    // ตรวจสอบว่ากรอกข้อมูลมาครบหรือไม่
    if (!problemType || !details) {
        return res.status(400).json({ success: false, error: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
    }

    // เตรียมคำสั่ง SQL เพื่อเพิ่มข้อมูลลงในตาราง maintenance_requests
    const sql = `
        INSERT INTO maintenance_requests (tenant_id, issue_type, details, status)
        VALUES (?, ?, ?, 'pending')
    `;

    // สั่งให้ฐานข้อมูลทำงาน (run a query)
    db.run(sql, [tenantId, problemType, details], function (err) {
        if (err) {
            // หากเกิดข้อผิดพลาดในการบันทึก
            console.error("Database error creating maintenance request:", err.message);
            return res.status(500).json({ success: false, error: 'เกิดข้อผิดพลาดในการบันทึกข้อมูล' });
        }
        
        // หากบันทึกสำเร็จ ส่งข้อความยืนยันกลับไป
        res.status(201).json({
            success: true,
            message: 'แจ้งซ่อมสำเร็จ!'
        });
    });
});


app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});