// -- ADDED --
// แนะนำให้ติดตั้ง dotenv เพื่อจัดการตัวแปร Environment -> npm install dotenv
require('dotenv').config(); 

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
// -- ADDED --
// แนะนำให้ติดตั้ง express-rate-limit เพื่อป้องกันการ Brute-force -> npm install express-rate-limit
const rateLimit = require('express-rate-limit');


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
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// -- CHANGED --
// ใช้ Secret แบบคงที่ และดึงจาก Environment Variables เพื่อความปลอดภัย
// ทุกครั้งที่เซิร์ฟเวอร์รีสตาร์ท session ของผู้ใช้จะไม่หายไป
app.use(session({
    secret: process.env.SESSION_SECRET || 'a-very-strong-and-static-secret-key-that-you-should-change',
    resave: false,
    saveUninitialized: true,
    cookie: {
        // ตั้งค่าเป็น true เมื่อใช้งานบน Production (HTTPS)
        secure: process.env.NODE_ENV === 'production' 
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


// --- Helper Functions ---
function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hashSync(password, saltRounds);
}

function comparePassword(password, hash) {
    return bcrypt.compareSync(password, hash);
}

// Custom middleware to check if the user is logged in
function requireLogin(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    } else {
        return res.status(401).send('You must be logged in to access this resource.');
    }
}

// -- ADDED --
// สร้าง Rate Limiter สำหรับหน้า Login เพื่อป้องกันการสุ่มรหัสผ่าน
const loginLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 นาที
	max: 10, // จำกัดให้ลองได้ 10 ครั้งต่อ 1 IP
	standardHeaders: true, 
	legacyHeaders: false, 
    message: 'Too many login attempts from this IP, please try again after 15 minutes'
});


// --- Routes ---
app.get('/', (req, res) => {
    res.redirect('/login.html');
});

// -- CHANGED -- เพิ่ม loginLimiter เข้าไปใน middleware
app.post('/login', loginLimiter, (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.get(sql, [email], (err, user) => {
        if (err) {
            return res.status(500).send('Server error');
        }
        if (user && comparePassword(password, user.password)) {
            const { password, ...userData } = user;
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

    const dbPromises = [];

    // Promise for payment info
    dbPromises.push(new Promise((resolve, reject) => {
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
    }));

    // Promise for maintenance request info
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

    // Promise for the latest announcement
    dbPromises.push(new Promise((resolve, reject) => {
        const announcementSql = `
            SELECT title FROM announcements ORDER BY created_at DESC LIMIT 1`;
        db.get(announcementSql, [], (err, row) => {
            if (err) return reject(err);
            dashboardData.announcement = row || null;
            resolve();
        });
    }));

    // Promise to get full billing details to calculate the correct total
    dbPromises.push(new Promise((resolve, reject) => {
        // This logic is similar to /api/billing-details and could be refactored
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
                // Update the payment amount with the calculated total
                if (dashboardData.payment) {
                    dashboardData.payment.amount = totalAmount;
                }
                resolve();
            });
        });
    }));

    Promise.all(dbPromises)
        .then(() => {
            res.json(dashboardData);
        })
        .catch(err => {
            console.error('Error fetching dashboard data:', err);
            res.status(500).json({ error: 'Failed to fetch dashboard data' });
        });
});

// API: Get Tenant's Contract/Lease Details 
// -- CHANGED -- เลือใช้เวอร์ชันที่สมบูรณ์กว่าและลบอันที่ซ้ำซ้อนออก
app.get('/api/contract-details', requireLogin, (req, res) => {
    if (req.session.user.role !== 'tenant') {
        return res.status(403).json({ error: 'Forbidden' });
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
            console.error('Database error fetching contract details:', err.message);
            return res.status(500).json({ error: 'เกิดข้อผิดพลาดในการดึงข้อมูลสัญญา' });
        }
        if (!row) {
            return res.status(404).json({ error: 'ไม่พบข้อมูลสัญญาเช่า' });
        }
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

    const roomSql = `SELECT r.rent FROM rooms r JOIN users u ON u.room_id = r.id WHERE u.id = ?`;
    db.get(roomSql, [tenantId], (err, roomRow) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch billing details' });
        billingDetails.room_rent = roomRow ? roomRow.rent : 0;

        const utilitiesSql = `SELECT water_fee, elec_usage FROM utilities WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1`;
        db.get(utilitiesSql, [tenantId], (err, utilRow) => {
            if (err) return res.status(500).json({ error: 'Failed to fetch billing details' });

            if (utilRow) {
                billingDetails.water_bill = utilRow.water_fee || 0;
                const electricityRate = 4.1;
                billingDetails.electricity_bill = (utilRow.elec_usage || 0) * electricityRate;
            } else {
                billingDetails.water_bill = 0;
                billingDetails.electricity_bill = 0;
            }
            billingDetails.total_amount = billingDetails.room_rent + billingDetails.water_bill + billingDetails.electricity_bill;
            res.json(billingDetails);
        });
    });
});


// Get all announcements (for tenants and owners)
// -- CHANGED -- เลือใช้เวอร์ชันที่สมบูรณ์กว่าและลบอันที่ซ้ำซ้อนออก
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

// Owner creates a new announcement
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

// Get maintenance requests for the logged-in tenant
app.get('/api/maintenance-requests', requireLogin, (req, res) => {
    if (req.session.user.role !== 'tenant') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const tenantId = req.session.user.id;
    const sql = `
        SELECT id, issue_type, details, status, created_at
        FROM maintenance_requests
        WHERE tenant_id = ?
        ORDER BY created_at DESC`;
    db.all(sql, [tenantId], (err, rows) => {
        if (err) {
            console.error('Error fetching maintenance requests:', err);
            return res.status(500).json({ error: 'Failed to fetch maintenance requests' });
        }
        res.json(rows);
    });
});

// -- DELETED --
// ลบ Route GET /api/repairs ที่ทำงานซ้ำซ้อนกับ /api/maintenance-requests ออก

// New Route for Slip Upload
app.post('/api/upload-slip', requireLogin, upload.single('paymentSlip'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Please upload a file.' });
    }
    const { paymentId } = req.body;
    if (!paymentId) {
        return res.status(400).json({ error: 'Payment ID is missing.' });
    }
    const slipFilename = req.file.filename;
    const sql = `
        UPDATE payments
        SET status = 'paid', paid_date = CURRENT_TIMESTAMP, slip_filename = ?
        WHERE id = ? AND tenant_id = ?`;
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

// Create a new maintenance request
app.post('/api/maintenance-requests', requireLogin, (req, res) => {
    if (req.session.user.role !== 'tenant') {
        return res.status(403).json({ success: false, error: 'Forbidden' });
    }
    const { 'problem-type': problemType, 'problem-details': details } = req.body;
    if (!problemType || !details) {
        return res.status(400).json({ success: false, error: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
    }
    const tenantId = req.session.user.id;
    const sql = `
        INSERT INTO maintenance_requests (tenant_id, issue_type, details, status)
        VALUES (?, ?, ?, 'pending')`;
    db.run(sql, [tenantId, problemType, details], function (err) {
        if (err) {
            console.error("Database error creating maintenance request:", err.message);
            return res.status(500).json({ success: false, error: 'เกิดข้อผิดพลาดในการบันทึกข้อมูล' });
        }
        res.status(201).json({ success: true, message: 'แจ้งซ่อมสำเร็จ!' });
    });
});

// POST Contact Message
app.post('/api/contact-message', requireLogin, (req, res) => {
    const { message } = req.body;
    const tenantId = req.session.user.id;

    if (!message) {
        return res.status(400).json({ success: false, error: 'Message cannot be empty.' });
    }
    const sql = "INSERT INTO contact_messages (tenant_id, message) VALUES (?, ?)";
    db.run(sql, [tenantId, message], function(err) {
        if (err) {
            console.error("Database error saving contact message:", err.message);
            return res.status(500).json({ success: false, error: 'Failed to send message.' });
        }
        res.status(201).json({ success: true, message: 'Message sent successfully.' });
    });
});
// POST Move-out Request
app.post('/api/moveout-request', requireLogin, (req, res) => {
    // 1. ตรวจสอบว่าเป็นผู้เช่าจริงหรือไม่
    if (req.session.user.role !== 'tenant') {
        return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    // 2. ดึงข้อมูลจากฟอร์มที่ส่งมา
    const { 
        'moveout-date': moveoutDate, 
        'moveout-reason': reason, 
        'forwarding-address': forwardingAddress 
    } = req.body;
    
    // 3. ดึง ID ของผู้เช่าจาก Session ที่ล็อกอินอยู่ (ปลอดภัยกว่า)
    const tenantId = req.session.user.id;

    // 4. ตรวจสอบข้อมูลเบื้องต้น
    if (!moveoutDate) {
        return res.status(400).json({ success: false, error: 'กรุณาระบุวันที่ต้องการย้ายออก' });
    }

    // 5. เตรียมคำสั่ง SQL เพื่อบันทึกข้อมูล
    const sql = `
        INSERT INTO moveout_requests (tenant_id, moveout_date, reason, forwarding_address)
        VALUES (?, ?, ?, ?)
    `;

    // 6. สั่งให้ Database ทำงาน
    db.run(sql, [tenantId, moveoutDate, reason, forwardingAddress], function(err) {
        if (err) {
            console.error("Database error creating move-out request:", err.message);
            return res.status(500).json({ success: false, error: 'เกิดข้อผิดพลาดในการบันทึกข้อมูล' });
        }
        // 7. ส่งผลลัพธ์กลับไปบอก Frontend ว่าสำเร็จแล้ว
        res.status(201).json({ success: true, message: 'แจ้งย้ายออกสำเร็จ!' });
    });
});
// -- DELETED --
// ลบ Routes ที่ประกาศซ้ำทั้งหมดที่อยู่ท้ายไฟล์ออกไป

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});