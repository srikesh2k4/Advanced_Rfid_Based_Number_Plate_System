// app.js
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const cors = require('cors');

const app = express();
const JWT_SECRET = "your_super_secret_key"; // Change this for production

// Create a MySQL connection pool (update with your MySQL credentials)
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',      // update with your MySQL username
  password: 'Srikesh@2004',  // update with your MySQL password
  database: 'rfid_system',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

app.use(bodyParser.json());
app.use(cors());

// Serve static files from the public folder
app.use(express.static(path.join(__dirname, 'public')));

// Main page route (serves index.html)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

// ===== User Signup Endpoint =====
app.post(
  '/api/signup',
  [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Please enter a valid email'),
    body('password')
      .isStrongPassword()
      .withMessage('Password must be at least 8 characters with uppercase, lowercase, number, and symbol'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ warn: "Unsuccessful", errors: errors.array() });
      }
      const { name, email, password } = req.body;
      // Check if user already exists
      const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      if (existingUsers.length > 0) {
        return res.status(400).json({ warn: "Unsuccessful", error: 'User already exists' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      await pool.query('INSERT INTO users (name, email, password, balance) VALUES (?, ?, ?, 0)', [name, email, hashedPassword]);
      res.json({ warn: "Successful", message: 'User created successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ warn: "Unsuccessful", error: 'Server error during signup' });
    }
  }
);

// ===== User Login Endpoint =====
app.post(
  '/api/login',
  [
    body('email').isEmail().withMessage('Please enter a valid email'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ warn: "Unsuccessful", errors: errors.array() });
      }
      const { email, password } = req.body;
      const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      if (rows.length === 0) {
        return res.status(400).json({ warn: "Unsuccessful", error: 'User not found' });
      }
      const user = rows[0];
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ warn: "Unsuccessful", error: 'Incorrect password' });
      }
      // Update login time
      const loginTime = new Date();
      await pool.query('UPDATE users SET loginTime = ? WHERE id = ?', [loginTime, user.id]);
      const token = jwt.sign(
        { id: user.id, email: user.email, name: user.name, role: 'user' },
        JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.json({
        warn: "Successful",
        message: 'Logged in successfully',
        token,
        user: { name: user.name, balance: user.balance, loginTime }
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ warn: "Unsuccessful", error: 'Server error during login' });
    }
  }
);

// ===== Authentication Middleware =====
function authMiddleware(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ warn: "Unsuccessful", error: 'No token provided' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ warn: "Unsuccessful", error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}
app.post('/api/admin/link-rfid', async (req, res) => {
  const { email, rfid_uid } = req.body;
  try {
    const [rows] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });

    await pool.query('UPDATE users SET rfid_uid = ? WHERE email = ?', [rfid_uid, email]);
    res.json({ message: '✅ RFID card linked successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to link RFID' });
  }
});
app.post('/api/admin/unlink-rfid', async (req, res) => {
  const { rfid_uid } = req.body;
  try {
    const [rows] = await pool.query('SELECT id FROM users WHERE rfid_uid = ?', [rfid_uid]);
    if (rows.length === 0) return res.status(404).json({ error: 'RFID card not found' });

    await pool.query('UPDATE users SET rfid_uid = NULL WHERE rfid_uid = ?', [rfid_uid]);
    res.json({ message: '✅ RFID card unlinked successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to unlink RFID' });
  }
});

app.post('/api/validate-vehicle', authMiddleware, async (req, res) => {
  const { vehicle } = req.body;
  try {
    const [rows] = await pool.query(
      'SELECT userId FROM payments WHERE vehicle = ? AND userId != ?',
      [vehicle, req.user.id]
    );
    const isUnique = rows.length === 0;
    res.json({ isUnique });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error checking vehicle uniqueness' });
  }
});



// ===== Payments Endpoint (Add Funds & Payment History) =====
app.post(
  '/api/payments',
  authMiddleware,
  [
    body('vehicle').notEmpty().withMessage('Vehicle number is required'),
    body('amount').isNumeric().withMessage('Amount must be a number'),
    body('reason').notEmpty().withMessage('Payment reason is required'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ warn: "Unsuccessful", errors: errors.array() });
      }
      const { vehicle, amount, reason } = req.body;
      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        const [paymentResult] = await conn.query(
          'INSERT INTO payments (userId, vehicle, amount, reason) VALUES (?, ?, ?, ?)',
          [req.user.id, vehicle, parseFloat(amount), reason]
        );
        await conn.query(
          'UPDATE users SET balance = balance + ? WHERE id = ?',
          [parseFloat(amount), req.user.id]
        );
        await conn.commit();
        res.json({ warn: "Successful", message: 'Payment successful', paymentId: paymentResult.insertId });
      } catch (tErr) {
        await conn.rollback();
        console.error(tErr);
        res.status(500).json({ warn: "Unsuccessful", error: 'Transaction error during payment' });
      } finally {
        conn.release();
      }
    } catch (err) {
      console.error(err);
      res.status(500).json({ warn: "Unsuccessful", error: 'Server error during payment' });
    }
  }
);

// ===== Wallet Endpoint (Balance & History) =====
app.get('/api/wallet', authMiddleware, async (req, res) => {
  try {
    const [userRows] = await pool.query('SELECT balance FROM users WHERE id = ?', [req.user.id]);
    if (userRows.length === 0) {
      return res.status(400).json({ warn: "Unsuccessful", error: 'User not found' });
    }

    const balance = userRows[0].balance;

    const [paymentsRows] = await pool.query(
      'SELECT amount, reason, vehicle, created_at FROM payments WHERE userId = ? ORDER BY created_at DESC',
      [req.user.id]
    );

    // ✅ SEND the response
    res.json({
      warn: "Successful",
      balance,
      payments: paymentsRows
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ warn: "Unsuccessful", error: 'Server error retrieving wallet' });
  }
});


// ===== Admin Login Endpoint =====
app.post(
  '/api/admin/login',
  [
    body('email').isEmail().withMessage('Please enter a valid email'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ warn: "Unsuccessful", errors: errors.array() });
      }
      const { email, password } = req.body;
      // In production, query your admins table. Here we use a hardcoded admin.
      const adminUser = {
        id: 999,
        name: 'Officer Sharma',
        email: 'admin@gov.in',
        password: await bcrypt.hash('Admin@123', 10),
        role: 'admin'
      };
      if (email !== adminUser.email) return res.status(400).json({ warn: "Unsuccessful", error: 'Admin not found' });
      const isMatch = await bcrypt.compare(password, adminUser.password);
      if (!isMatch) return res.status(400).json({ warn: "Unsuccessful", error: 'Incorrect password' });
      const token = jwt.sign(
        { id: adminUser.id, email: adminUser.email, name: adminUser.name, role: adminUser.role },
        JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.json({ warn: "Successful", message: 'Admin logged in successfully', token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ warn: "Unsuccessful", error: 'Server error during admin login' });
    }
  }
);

// ===== Admin Dashboard Endpoint =====
app.get('/api/admin/dashboard', async (req, res) => {
  try {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ warn: "Unsuccessful", error: 'No token provided' });
    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
      if (err) return res.status(401).json({ warn: "Unsuccessful", error: 'Invalid token' });
      if (decoded.role !== 'admin') return res.status(403).json({ warn: "Unsuccessful", error: 'Unauthorized access' });
      const [scansRows] = await pool.query('SELECT * FROM rfid_scans ORDER BY id DESC LIMIT 10');
      const [usersRows] = await pool.query('SELECT name, loginTime FROM users WHERE loginTime IS NOT NULL');
      const [totalVehiclesRow] = await pool.query('SELECT COUNT(*) as totalVehicles FROM users');
      const [activeWalletsRow] = await pool.query('SELECT COUNT(*) as activeWallets FROM users WHERE balance > 0');
      const [totalFinesRow] = await pool.query("SELECT IFNULL(SUM(amount),0) as totalFinesIssued FROM payments WHERE reason = 'fine'");
      res.json({
        warn: "Successful",
        recentRFIDScans: scansRows.map(scan => ({
          vehicle: scan.vehicle,
          date: scan.date,
          time: scan.time,
          location: {
            village: scan.village,
            district: scan.district,
            state: scan.state
          }
        })),
        userLoginTimes: usersRows,
        stats: {
          totalVehicles: totalVehiclesRow[0].totalVehicles,
          activeWallets: activeWalletsRow[0].activeWallets,
          totalFinesIssued: totalFinesRow[0].totalFinesIssued
        }
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ warn: "Unsuccessful", error: 'Server error retrieving admin dashboard' });
  }
});

app.post('/api/rfid/scan', async (req, res) => {
  const { rfid, village, district, state } = req.body;

  try {
    const [user] = await pool.query('SELECT * FROM users WHERE rfid_uid = ?', [rfid]);
    if (!user.length) return res.status(404).json({ message: "RFID not registered" });

    const toll = 10; // Deduct ₹10
    if (user[0].balance < toll) return res.status(402).json({ message: "Insufficient balance" });

    await pool.query('UPDATE users SET balance = balance - ? WHERE id = ?', [toll, user[0].id]);

    await pool.query(
      'INSERT INTO rfid_scans (vehicle, date, time, village, district, state) VALUES (?, CURDATE(), CURTIME(), ?, ?, ?)',
      [rfid, village, district, state]
    );

    res.json({ message: "Toll deducted", user: user[0].name, newBalance: user[0].balance - toll });
  } catch (err) {
    console.error("RFID scan error:", err);
    res.status(500).json({ message: "Server error" });
  }
});





app.listen(4000, '0.0.0.0', () => {
  console.log("Listening on http://0.0.0.0:4000");
});
