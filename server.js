const express = require('express');
const http = require('http');
const path = require('path');
const os = require('os');
const cors = require('cors');
const socketIo = require('socket.io');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const XLSX = require('xlsx');
const { initDB, run, get, all, DESIGNATED_OFFICERS } = require('./db');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: '*' }
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'plms_secret_divisional_secretariat_2026';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Standalone Dedicated Messenger Route
app.get('/messenger', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'messenger.html'));
});

// Privacy Policy (Mandatory for Google Play Store compliance)
app.get('/privacy-policy', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'privacy-policy.html'));
});

// Google Play Store Digital Asset Links for Trusted Web Activity (TWA)
app.get('/.well-known/assetlinks.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.json([
    {
      relation: ["delegate_permission/common.handle_all_urls"],
      target: {
        namespace: "android_app",
        package_name: "lk.gov.msw.plms",
        sha256_cert_fingerprints: [
          "14:6D:E9:01:58:0D:E8:11:48:43:B6:6A:4B:5D:84:5C:92:81:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
        ]
      }
    }
  ]);
});

// Multer storage for profile photos
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'public', 'assets', 'uploads'));
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, 'officer_' + Date.now() + ext);
  }
});
const upload = multer({ storage });

// Helper: Password validator (Memorable & User-friendly: minimum 6 characters)
function validatePassword(pass) {
  return typeof pass === 'string' && pass.trim().length >= 6;
}

// Helper: Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'உள்நுழையவும் (Unauthorized)' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'செல்லுபடியற்ற அனுமதி (Invalid Token)' });
    req.user = user;
    next();
  });
}

// ----------------- AUTH APIS -----------------

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'மின்னஞ்சல் மற்றும் கடவுச்சொல் தேவை' });
    }

    const user = await get('SELECT * FROM users WHERE LOWER(email) = LOWER(?)', [email.trim()]);
    if (!user) {
      return res.status(401).json({ error: 'தவறான மின்னஞ்சல் அல்லது கடவுச்சொல்' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'தவறான மின்னஞ்சல் அல்லது கடவுச்சொல்' });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        designation: user.designation
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    const safeUser = { ...user };
    delete safeUser.password;

    res.json({ token, user: safeUser });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'சேவையக பிழை (Server Error)' });
  }
});

// POST /api/auth/register
app.post('/api/auth/register', upload.single('photo'), async (req, res) => {
  try {
    const { name, designation, email, password, phone, dob, gender } = req.body;

    if (!name || !email || !password || !designation) {
      return res.status(400).json({ error: 'அனைத்து முக்கிய விபரங்களையும் பூர்த்தி செய்யவும்' });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({
        error: 'கடவுச்சொல் நிபந்தனை: குறைந்தது 6 எழுத்துக்களைக் கொண்டிருக்க வேண்டும் (எளிதில் நினைவில் நிற்கக்கூடியதாக அமைக்கலாம்)!'
      });
    }

    const existing = await get('SELECT id FROM users WHERE LOWER(email) = LOWER(?)', [email.trim()]);
    if (existing) {
      return res.status(400).json({ error: 'இந்த மின்னஞ்சல் ஏற்கனவே பதிவு செய்யப்பட்டுள்ளது' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const photo_url = req.file ? `/assets/uploads/${req.file.filename}` : '/assets/default_avatar.svg';

    let role = 'officer';
    const emailLower = email.trim().toLowerCase();
    if (emailLower === 'virudsham@gmail.com' || emailLower === 'adpsasi@gmail.com') {
      role = 'super_admin';
    } else if (emailLower === 'mfahir25@gmail.com') {
      role = 'secondary_admin';
    }

    const result = await run(
      `INSERT INTO users (name, designation, email, password, phone, dob, gender, photo_url, role, points)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
      [name.trim(), designation.trim(), emailLower, hashedPassword, phone || '', dob || '', gender || 'Male', photo_url, role]
    );

    res.json({
      success: true,
      message: 'பதிவு வெற்றிகரமாக முடிவடைந்தது! இப்போது உள்நுழையலாம்.',
      userId: result.lastID
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'பதிவு செய்வதில் பிழை ஏற்பட்டது' });
  }
});

// POST /api/auth/forgot-password (OTP generation)
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'மின்னஞ்சல் முகவரியை உள்ளிடவும்' });

    const user = await get('SELECT * FROM users WHERE LOWER(email) = LOWER(?)', [email.trim()]);
    if (!user) {
      return res.status(404).json({
        error: 'இம்மின்னஞ்சல் முகவரியில் கணக்கு எதுவும் இல்லை. தயவுசெய்து virudsham@gmail.com அல்லது adpsasi@gmail.com ஐ தொடர்பு கொள்ளவும்.'
      });
    }

    // Generate 6 digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 mins

    await run('DELETE FROM password_resets WHERE LOWER(email) = LOWER(?)', [email.trim()]);
    await run('INSERT INTO password_resets (email, otp, expires_at) VALUES (?, ?, ?)', [email.trim().toLowerCase(), otp, expiresAt]);

    console.log(`[PLMS OTP SERVICE] Password reset OTP for ${email}: ${otp}`);

    res.json({
      success: true,
      otpSimulated: otp, // Returned for offline LAN seamless reset experience
      message: `கடவுச்சொல் மாற்றத்திற்கான 6-இலக்க OTP உங்கள் மின்னஞ்சலுக்கு (${email}) அனுப்பப்பட்டுள்ளது. (LAN முறைமையில் உடனடியாக திரையிலும் காண்பிக்கப்பட்டுள்ளது: ${otp})`
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'OTP அனுப்புவதில் பிழை' });
  }
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ error: 'அனைத்து விபரங்களையும் உள்ளிடவும்' });
    }

    if (!validatePassword(newPassword)) {
      return res.status(400).json({
        error: 'புதிய கடவுச்சொல் நிபந்தனை: குறைந்தது 6 எழுத்துக்களைக் கொண்டிருக்க வேண்டும் (எளிதில் நினைவில் நிற்கக்கூடியதாக அமைக்கலாம்)!'
      });
    }

    const resetRow = await get(
      'SELECT * FROM password_resets WHERE LOWER(email) = LOWER(?) AND otp = ?',
      [email.trim(), otp.trim()]
    );

    if (!resetRow) {
      return res.status(400).json({ error: 'தவறான OTP இலக்கம்' });
    }

    if (new Date(resetRow.expires_at) < new Date()) {
      return res.status(400).json({ error: 'OTP காலாவதியாகிவிட்டது, மீண்டும் புதிய OTP கோரவும்' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await run('UPDATE users SET password = ? WHERE LOWER(email) = LOWER(?)', [hashedPassword, email.trim()]);
    await run('DELETE FROM password_resets WHERE LOWER(email) = LOWER(?)', [email.trim()]);

    res.json({ success: true, message: 'கடவுச்சொல் வெற்றிகரமாக மாற்றப்பட்டது! இப்போது புதிய கடவுச்சொல்லுடன் உள்நுழையவும்.' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'கடவுச்சொல் மாற்றுவதில் பிழை' });
  }
});

// POST /api/auth/change-password (Authenticated user)
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'தற்போதைய மற்றும் புதிய கடவுச்சொல்லை உள்ளிடவும்' });
    }

    const user = await get('SELECT * FROM users WHERE id = ?', [req.user.id]);
    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) {
      return res.status(400).json({ error: 'தற்போதைய கடவுச்சொல் தவறானது' });
    }

    if (!validatePassword(newPassword)) {
      return res.status(400).json({
        error: 'புதிய கடவுச்சொல் நிபந்தனை: குறைந்தது 6 எழுத்துக்களைக் கொண்டிருக்க வேண்டும் (எளிதில் நினைவில் நிற்கக்கூடியதாக அமைக்கலாம்)!'
      });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await run('UPDATE users SET password = ? WHERE id = ?', [hashed, req.user.id]);

    res.json({ success: true, message: 'கடவுச்சொல் வெற்றிகரமாக மாற்றப்பட்டது!' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'கடவுச்சொல் மாற்றுவதில் பிழை' });
  }
});

// POST /api/auth/update-profile
app.post('/api/auth/update-profile', authenticateToken, upload.single('photo'), async (req, res) => {
  try {
    const { name, phone, dob, gender } = req.body;
    const photo_url = req.file ? `/assets/uploads/${req.file.filename}` : undefined;

    if (photo_url) {
      await run(
        'UPDATE users SET name = COALESCE(?, name), phone = COALESCE(?, phone), dob = COALESCE(?, dob), gender = COALESCE(?, gender), photo_url = ? WHERE id = ?',
        [name, phone, dob, gender, photo_url, req.user.id]
      );
    } else {
      await run(
        'UPDATE users SET name = COALESCE(?, name), phone = COALESCE(?, phone), dob = COALESCE(?, dob), gender = COALESCE(?, gender) WHERE id = ?',
        [name, phone, dob, gender, req.user.id]
      );
    }

    const updated = await get('SELECT id, name, designation, email, phone, dob, gender, photo_url, role, points FROM users WHERE id = ?', [req.user.id]);
    res.json({ success: true, user: updated });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: 'விபரங்களை மாற்றுவதில் பிழை' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await get('SELECT id, name, designation, email, phone, dob, gender, photo_url, role, points FROM users WHERE id = ?', [req.user.id]);
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'சேவையக பிழை' });
  }
});

// ----------------- OFFICERS / USERS APIS -----------------

// GET /api/users (List all officers)
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await all('SELECT id, name, designation, email, phone, dob, gender, photo_url, role, points, created_at FROM users ORDER BY id ASC');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'அதிகாரிகள் விபரத்தை பெறுவதில் பிழை' });
  }
});

// POST /api/users (Create Officer - Super Admin ONLY: virudsham@gmail.com & adpsasi@gmail.com)
app.post('/api/users', authenticateToken, upload.single('photo'), async (req, res) => {
  try {
    if (req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'புதிய உத்தியோகத்தர்களை இணைக்க virudsham@gmail.com அல்லது adpsasi@gmail.com முதன்மை நிர்வாகிகளுக்கு மட்டுமே அனுமதி உண்டு!' });
    }

    const { name, designation, email, password, phone, dob, gender, role } = req.body;
    if (!name || !designation || !email) {
      return res.status(400).json({ error: 'பெயர், பதவி நிலை, மின்னஞ்சல் கட்டாயம்' });
    }

    const userPass = password && password.trim().length > 0 ? password : 'Plms@admin2026';
    if (!validatePassword(userPass)) {
      return res.status(400).json({ error: 'கடவுச்சொல் நிபந்தனை: குறைந்தது 6 எழுத்துக்களைக் கொண்டிருக்க வேண்டும்!' });
    }

    const existing = await get('SELECT id FROM users WHERE LOWER(email) = LOWER(?)', [email.trim()]);
    if (existing) {
      return res.status(400).json({ error: 'இந்த மின்னஞ்சல் ஏற்கனவே பயன்பாட்டில் உள்ளது' });
    }

    const hashed = await bcrypt.hash(userPass, 10);
    const photo_url = req.file ? `/assets/uploads/${req.file.filename}` : '/assets/default_avatar.svg';

    const assignedRole = role || 'officer';

    const result = await run(
      `INSERT INTO users (name, designation, email, password, phone, dob, gender, photo_url, role, points)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
      [name.trim(), designation.trim(), email.trim().toLowerCase(), hashed, phone || '', dob || '', gender || 'Male', photo_url, assignedRole]
    );

    res.json({ success: true, message: 'உத்தியோகத்தர் வெற்றிகரமாக இணைக்கப்பட்டார்!', id: result.lastID });
  } catch (err) {
    console.error('Create user error:', err);
    res.status(500).json({ error: 'உத்தியோகத்தரை இணைப்பதில் பிழை' });
  }
});

// PUT /api/users/:id (Edit Officer - Super Admin ONLY)
app.put('/api/users/:id', authenticateToken, upload.single('photo'), async (req, res) => {
  try {
    if (req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'உத்தியோகத்தர் விபரங்களை திருத்த முதன்மை நிர்வாகிகளுக்கு (virudsham / adpsasi) மட்டுமே அனுமதி உண்டு!' });
    }

    const { id } = req.params;
    const { name, designation, email, phone, dob, gender, role, password } = req.body;
    const photo_url = req.file ? `/assets/uploads/${req.file.filename}` : undefined;

    let updateFields = [];
    let params = [];

    if (name) { updateFields.push('name = ?'); params.push(name.trim()); }
    if (designation) { updateFields.push('designation = ?'); params.push(designation.trim()); }
    if (email) { updateFields.push('email = ?'); params.push(email.trim().toLowerCase()); }
    if (phone !== undefined) { updateFields.push('phone = ?'); params.push(phone); }
    if (dob !== undefined) { updateFields.push('dob = ?'); params.push(dob); }
    if (gender) { updateFields.push('gender = ?'); params.push(gender); }
    if (role) { updateFields.push('role = ?'); params.push(role); }
    if (photo_url) { updateFields.push('photo_url = ?'); params.push(photo_url); }
    if (password && password.trim().length > 0) {
      if (!validatePassword(password)) {
        return res.status(400).json({ error: 'கடவுச்சொல் நிபந்தனை: குறைந்தது 6 எழுத்துக்களைக் கொண்டிருக்க வேண்டும்!' });
      }
      const hashed = await bcrypt.hash(password, 10);
      updateFields.push('password = ?');
      params.push(hashed);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'மாற்றுவதற்கு எந்த விபரமும் வழங்கப்படவில்லை' });
    }

    params.push(id);
    await run(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`, params);

    res.json({ success: true, message: 'உத்தியோகத்தர் விபரம் திருத்தப்பட்டது!' });
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ error: 'திருத்துவதில் பிழை' });
  }
});

// DELETE /api/users/:id (Delete Officer - Super Admin ONLY)
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'உத்தியோகத்தர்களை நீக்க முதன்மை நிர்வாகிகளுக்கு மட்டுமே அனுமதி உண்டு!' });
    }

    const { id } = req.params;
    const target = await get('SELECT email FROM users WHERE id = ?', [id]);
    if (!target) return res.status(404).json({ error: 'உத்தியோகத்தர் காணப்படவில்லை' });

    if (target.email === 'virudsham@gmail.com' || target.email === 'adpsasi@gmail.com') {
      return res.status(400).json({ error: 'முதன்மை நிர்வாகி கணக்கை நீக்க முடியாது!' });
    }

    await run('DELETE FROM users WHERE id = ?', [id]);
    res.json({ success: true, message: 'உத்தியோகத்தர் நீக்கப்பட்டார்!' });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: 'நீக்குவதில் பிழை' });
  }
});

// ----------------- LETTERS MANAGEMENT -----------------

// Helper to calculate score for a letter
function calculateLetterPoints(dueDateStr, respondedDateStr) {
  if (!respondedDateStr) return 0;
  const due = new Date(dueDateStr);
  const resp = new Date(respondedDateStr);
  // Compare date parts only
  due.setHours(0, 0, 0, 0);
  resp.setHours(0, 0, 0, 0);

  const diffTime = due.getTime() - resp.getTime();
  const diffDays = Math.round(diffTime / (1000 * 60 * 60 * 24));

  if (diffDays >= 0) {
    // Responded on time or early: +1 point per day early (minimum +1 point bonus)
    return Math.max(1, diffDays);
  } else {
    // Delayed response: -1 point per day delayed
    return diffDays; // negative value, e.g. -1, -2, etc.
  }
}

// Generate serial number in format: Serial No/date/month/Year
async function generateSerialNumber() {
  const now = new Date();
  const day = String(now.getDate()).padStart(2, '0');
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const year = now.getFullYear();

  const countRow = await get('SELECT COUNT(*) as count FROM letters');
  const seq = String((countRow ? countRow.count : 0) + 1).padStart(3, '0');

  return `${seq}/${day}/${month}/${year}`;
}

// Recalculate all officers' total points in DB
async function recalculateOfficerPoints() {
  await run(`
    UPDATE users SET points = (
      SELECT COALESCE(SUM(points), 0) FROM letters WHERE assigned_officer_id = users.id
    )
  `);
}

// GET /api/letters (List with filters & search)
app.get('/api/letters', authenticateToken, async (req, res) => {
  try {
    const { status, officer_id, search, start_date, end_date } = req.query;

    let sql = `
      SELECT l.*, u.photo_url as officer_photo, u.designation as officer_designation
      FROM letters l
      LEFT JOIN users u ON l.assigned_officer_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (status && status !== 'all') {
      if (status === 'overdue') {
        const today = new Date().toISOString().split('T')[0];
        sql += ` AND l.responded_date IS NULL AND l.due_date < ?`;
        params.push(today);
      } else if (status === 'due_soon') {
        const today = new Date().toISOString().split('T')[0];
        const next3 = new Date(Date.now() + 3 * 86400000).toISOString().split('T')[0];
        sql += ` AND l.responded_date IS NULL AND l.due_date >= ? AND l.due_date <= ?`;
        params.push(today, next3);
      } else {
        sql += ` AND LOWER(l.status) = LOWER(?)`;
        params.push(status);
      }
    }

    if (officer_id && officer_id !== 'all') {
      sql += ` AND l.assigned_officer_id = ?`;
      params.push(officer_id);
    }

    if (start_date) {
      sql += ` AND l.received_date >= ?`;
      params.push(start_date);
    }

    if (end_date) {
      sql += ` AND l.received_date <= ?`;
      params.push(end_date);
    }

    if (search && search.trim().length > 0) {
      const s = `%${search.trim()}%`;
      sql += ` AND (l.serial_no LIKE ? OR l.subject LIKE ? OR l.file_no LIKE ? OR l.assigned_officer_name LIKE ?)`;
      params.push(s, s, s, s);
    }

    sql += ` ORDER BY l.id DESC`;

    const letters = await all(sql, params);
    res.json(letters);
  } catch (err) {
    console.error('Get letters error:', err);
    res.status(500).json({ error: 'கடிதங்களை பெறுவதில் பிழை' });
  }
});

// POST /api/letters (Create Letter - Admins ONLY: virudsham, adpsasi, mfahir)
app.post('/api/letters', authenticateToken, async (req, res) => {
  try {
    const isAuthorized =
      req.user.role === 'super_admin' || req.user.role === 'secondary_admin';

    if (!isAuthorized) {
      return res.status(403).json({
        error: 'கடிதங்களை பதிவு செய்வதற்கு virudsham@gmail.com, adpsasi@gmail.com அல்லது mfahir25@gmail.com ஆகிய நிர்வாகிகளுக்கு மட்டுமே அனுமதி உண்டு!'
      });
    }

    const {
      serial_no,
      assigned_officer_id,
      assigned_officer_name,
      received_date,
      subject,
      file_no,
      due_date,
      responded_date
    } = req.body;

    if (!received_date || !subject || !file_no || !due_date) {
      return res.status(400).json({ error: 'கடித விபரங்கள், விடயம், திகதி, கோவை இலக்கம் மற்றும் காலக்கெடு கட்டாயமாகும்!' });
    }

    // Resolve officer
    let offId = assigned_officer_id;
    let offName = assigned_officer_name;
    if (offId) {
      const officer = await get('SELECT id, name FROM users WHERE id = ?', [offId]);
      if (officer) {
        offName = officer.name;
      }
    } else if (offName) {
      const officer = await get('SELECT id, name FROM users WHERE name = ?', [offName]);
      if (officer) {
        offId = officer.id;
      }
    }

    if (!offName) {
      return res.status(400).json({ error: 'பொறுப்பளிக்கப்பட்ட உத்தியோகத்தரை தெரிவு செய்யவும்' });
    }

    const finalSerialNo = serial_no && serial_no.trim().length > 0
      ? serial_no.trim()
      : await generateSerialNumber();

    let points = 0;
    let status = 'Pending';
    if (responded_date && responded_date.trim().length > 0) {
      status = 'Responded';
      points = calculateLetterPoints(due_date, responded_date);
    } else {
      const today = new Date().toISOString().split('T')[0];
      if (today > due_date) {
        status = 'Overdue';
        const diffDays = Math.round((new Date(today) - new Date(due_date)) / (1000 * 60 * 60 * 24));
        points = -diffDays;
      }
    }

    const result = await run(
      `INSERT INTO letters (serial_no, assigned_officer_id, assigned_officer_name, received_date, subject, file_no, due_date, responded_date, status, points, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        finalSerialNo,
        offId || null,
        offName,
        received_date,
        subject.trim(),
        file_no.trim(),
        due_date,
        responded_date || null,
        status,
        points,
        req.user.email
      ]
    );

    await recalculateOfficerPoints();

    // Broadcast socket event for real-time notification
    io.emit('new_letter_assigned', {
      letterId: result.lastID,
      officerId: offId,
      officerName: offName,
      subject,
      serialNo: finalSerialNo
    });

    res.json({
      success: true,
      message: 'கடிதம் வெற்றிகரமாக பதிவு செய்யப்பட்டது!',
      id: result.lastID,
      serial_no: finalSerialNo
    });
  } catch (err) {
    console.error('Create letter error:', err);
    res.status(500).json({ error: 'கடிதம் பதிவு செய்வதில் பிழை (சீரியல் எண் ஏற்கனவே இருக்கலாம்)' });
  }
});

// PUT /api/letters/:id (Update Letter)
// Super/Secondary admins can edit everything.
// General officers can ONLY update received_date and file_no.
app.put('/api/letters/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await get('SELECT * FROM letters WHERE id = ?', [id]);
    if (!existing) return res.status(404).json({ error: 'கடிதம் காணப்படவில்லை' });

    const isAdmin = req.user.role === 'super_admin' || req.user.role === 'secondary_admin';

    if (!isAdmin) {
      // General officer: restricted to updating received_date and file_no only
      const { received_date, file_no } = req.body;
      if (!received_date && !file_no) {
        return res.status(400).json({ error: 'உங்களுக்கு பெற்றுகொண்ட திகதி மற்றும் கோவை இலக்கம் மட்டுமே திருத்த அனுமதி உண்டு' });
      }

      await run(
        `UPDATE letters SET
           received_date = COALESCE(?, received_date),
           file_no = COALESCE(?, file_no),
           updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [received_date || existing.received_date, file_no || existing.file_no, id]
      );

      return res.json({
        success: true,
        message: 'பெற்றுகொண்ட திகதி மற்றும் கோவை இலக்கம் வெற்றிகரமாக புதுப்பிக்கப்பட்டது!'
      });
    }

    // Admins (virudsham, adpsasi, mfahir) have full update authority
    const {
      serial_no,
      assigned_officer_id,
      assigned_officer_name,
      received_date,
      subject,
      file_no,
      due_date,
      responded_date
    } = req.body;

    let offId = assigned_officer_id !== undefined ? assigned_officer_id : existing.assigned_officer_id;
    let offName = assigned_officer_name || existing.assigned_officer_name;

    if (offId && !assigned_officer_name) {
      const off = await get('SELECT name FROM users WHERE id = ?', [offId]);
      if (off) offName = off.name;
    }

    const finalDueDate = due_date || existing.due_date;
    const finalRespondedDate = responded_date !== undefined ? responded_date : existing.responded_date;

    let points = 0;
    let status = 'Pending';
    if (finalRespondedDate && finalRespondedDate.trim().length > 0) {
      status = 'Responded';
      points = calculateLetterPoints(finalDueDate, finalRespondedDate);
    } else {
      const today = new Date().toISOString().split('T')[0];
      if (today > finalDueDate) {
        status = 'Overdue';
        const diffDays = Math.round((new Date(today) - new Date(finalDueDate)) / (1000 * 60 * 60 * 24));
        points = -diffDays;
      }
    }

    await run(
      `UPDATE letters SET
         serial_no = COALESCE(?, serial_no),
         assigned_officer_id = ?,
         assigned_officer_name = ?,
         received_date = COALESCE(?, received_date),
         subject = COALESCE(?, subject),
         file_no = COALESCE(?, file_no),
         due_date = ?,
         responded_date = ?,
         status = ?,
         points = ?,
         updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [
        serial_no || existing.serial_no,
        offId,
        offName,
        received_date || existing.received_date,
        subject || existing.subject,
        file_no || existing.file_no,
        finalDueDate,
        finalRespondedDate || null,
        status,
        points,
        id
      ]
    );

    await recalculateOfficerPoints();

    io.emit('letter_updated', { letterId: id });

    res.json({ success: true, message: 'கடிதம் வெற்றிகரமாக திருத்தப்பட்டது!' });
  } catch (err) {
    console.error('Update letter error:', err);
    res.status(500).json({ error: 'கடிதம் திருத்துவதில் பிழை' });
  }
});

// DELETE /api/letters/:id (Delete Letter - Admins ONLY: virudsham, adpsasi, mfahir)
app.delete('/api/letters/:id', authenticateToken, async (req, res) => {
  try {
    const isAuthorized =
      req.user.role === 'super_admin' || req.user.role === 'secondary_admin';

    if (!isAuthorized) {
      return res.status(403).json({
        error: 'கடிதங்களை நீக்குவதற்கு virudsham@gmail.com, adpsasi@gmail.com அல்லது mfahir25@gmail.com ஆகியோருக்கு மட்டுமே அனுமதி உண்டு!'
      });
    }

    const { id } = req.params;
    await run('DELETE FROM letters WHERE id = ?', [id]);
    await recalculateOfficerPoints();

    io.emit('letter_deleted', { letterId: id });

    res.json({ success: true, message: 'கடிதம் முழுமையாக அழிக்கப்பட்டது!' });
  } catch (err) {
    console.error('Delete letter error:', err);
    res.status(500).json({ error: 'கடிதம் அழிப்பதில் பிழை' });
  }
});

// GET /api/letters/stats (Summary Statistics)
app.get('/api/letters/stats', authenticateToken, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const next3Days = new Date(Date.now() + 3 * 86400000).toISOString().split('T')[0];

    const totalRow = await get('SELECT COUNT(*) as count FROM letters');
    const pendingRow = await get('SELECT COUNT(*) as count FROM letters WHERE responded_date IS NULL');
    const respondedRow = await get('SELECT COUNT(*) as count FROM letters WHERE responded_date IS NOT NULL');
    const overdueRow = await get('SELECT COUNT(*) as count FROM letters WHERE responded_date IS NULL AND due_date < ?', [today]);
    const dueSoonRow = await get('SELECT COUNT(*) as count FROM letters WHERE responded_date IS NULL AND due_date >= ? AND due_date <= ?', [today, next3Days]);

    res.json({
      total: totalRow ? totalRow.count : 0,
      pending: pendingRow ? pendingRow.count : 0,
      responded: respondedRow ? respondedRow.count : 0,
      overdue: overdueRow ? overdueRow.count : 0,
      due_soon: dueSoonRow ? dueSoonRow.count : 0
    });
  } catch (err) {
    res.status(500).json({ error: 'புள்ளிவிபரங்கள் பெறுவதில் பிழை' });
  }
});

// ----------------- LEADERBOARD & MONTHLY AWARDS -----------------

// GET /api/leaderboard
// Monthly cycle: 29th of current/previous month to 29th of current/next month
app.get('/api/leaderboard', authenticateToken, async (req, res) => {
  try {
    const now = new Date();
    const currentDay = now.getDate();
    let cycleStart, cycleEnd;

    if (currentDay >= 29) {
      // e.g. Oct 29 to Nov 29
      cycleStart = new Date(now.getFullYear(), now.getMonth(), 29);
      cycleEnd = new Date(now.getFullYear(), now.getMonth() + 1, 29);
    } else {
      // e.g. Sep 29 to Oct 29
      cycleStart = new Date(now.getFullYear(), now.getMonth() - 1, 29);
      cycleEnd = new Date(now.getFullYear(), now.getMonth(), 29);
    }

    const startStr = cycleStart.toISOString().split('T')[0];
    const endStr = cycleEnd.toISOString().split('T')[0];

    // Calculate score earned within this 29th to 29th cycle, plus all-time points
    const sql = `
      SELECT
        u.id,
        u.name,
        u.designation,
        u.email,
        u.photo_url,
        COALESCE(SUM(CASE WHEN l.received_date >= ? AND l.received_date <= ? THEN l.points ELSE 0 END), 0) as monthly_points,
        COALESCE(SUM(l.points), 0) as total_points,
        COUNT(CASE WHEN l.responded_date IS NOT NULL THEN 1 END) as letters_responded,
        COUNT(CASE WHEN l.responded_date IS NULL AND l.due_date < date('now') THEN 1 END) as letters_overdue,
        COUNT(l.id) as total_assigned
      FROM users u
      LEFT JOIN letters l ON l.assigned_officer_id = u.id
      WHERE u.designation NOT IN ('DS', 'ADS', 'DDP')
        AND u.name NOT LIKE '%SUTHAKAR%'
        AND u.name NOT LIKE '%PARTHEEPAN%'
        AND u.name NOT LIKE '%SASIKUMAR%'
      GROUP BY u.id
      ORDER BY monthly_points DESC, total_points DESC, letters_responded DESC
    `;

    const rankings = await all(sql, [startStr, endStr]);

    res.json({
      cycle: {
        start: startStr,
        end: endStr,
        label: `${startStr} முதல் ${endStr} வரையிலான காலப்பகுதி`
      },
      rankings
    });
  } catch (err) {
    console.error('Leaderboard error:', err);
    res.status(500).json({ error: 'மதிப்பீட்டு விபரங்களை பெறுவதில் பிழை' });
  }
});

// ----------------- BIRTHDAYS -----------------

// GET /api/birthdays/today
app.get('/api/birthdays/today', authenticateToken, async (req, res) => {
  try {
    const now = new Date();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const target = `-${month}-${day}`; // matches %-MM-DD in dob

    const birthdays = await all(
      `SELECT id, name, designation, dob, photo_url, email
       FROM users
       WHERE dob LIKE ?`,
      [`%${target}`]
    );

    res.json(birthdays);
  } catch (err) {
    res.status(500).json({ error: 'பிறந்தநாள் விபரம் பெறுவதில் பிழை' });
  }
});

// GET /api/birthdays/all
app.get('/api/birthdays/all', authenticateToken, async (req, res) => {
  try {
    const users = await all(
      `SELECT id, name, designation, dob, photo_url, email
       FROM users
       WHERE dob IS NOT NULL AND dob != ''
       ORDER BY SUBSTR(dob, 6, 5) ASC`
    );
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'பிறந்தநாள் பட்டியல் பெறுவதில் பிழை' });
  }
});

// ----------------- DUE SOON / NOTIFICATION CHIME REMINDERS -----------------

// GET /api/reminders/due-soon
// Checks if letters are due within 3 days or overdue where no response is recorded
app.get('/api/reminders/due-soon', authenticateToken, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const next3Days = new Date(Date.now() + 3 * 86400000).toISOString().split('T')[0];

    let sql, params;
    if (req.user.role === 'super_admin' || req.user.role === 'secondary_admin') {
      // Admins receive reminders for all pending/overdue division letters
      sql = `
        SELECT l.*, u.name as assigned_officer_name, u.designation as officer_designation
        FROM letters l
        LEFT JOIN users u ON l.assigned_officer_id = u.id
        WHERE l.responded_date IS NULL
          AND l.due_date <= ?
        ORDER BY l.due_date ASC
      `;
      params = [next3Days];
    } else {
      // Individual officers receive reminders for their own assigned letters
      sql = `
        SELECT l.*, u.name as assigned_officer_name, u.designation as officer_designation
        FROM letters l
        LEFT JOIN users u ON l.assigned_officer_id = u.id
        WHERE l.assigned_officer_id = ?
          AND l.responded_date IS NULL
          AND l.due_date <= ?
        ORDER BY l.due_date ASC
      `;
      params = [req.user.id, next3Days];
    }

    const reminders = await all(sql, params);
    res.json(reminders);
  } catch (err) {
    res.status(500).json({ error: 'நினைவூட்டல் விபரம் பெறுவதில் பிழை' });
  }
});

// ----------------- INSTANT MESSENGER (CHAT) -----------------

// GET /api/messages?peer_id=X (peer_id can be numeric user id or 'group')
app.get('/api/messages', authenticateToken, async (req, res) => {
  try {
    const peerId = req.query.peer_id || 'group';

    let sql, params;
    if (peerId === 'group') {
      sql = `
        SELECT m.*, u.photo_url as sender_photo, u.designation as sender_designation
        FROM messages m
        LEFT JOIN users u ON m.sender_id = u.id
        WHERE m.recipient_id = 'group'
        ORDER BY m.id ASC
        LIMIT 200
      `;
      params = [];
    } else {
      const myId = req.user.id;
      sql = `
        SELECT m.*, u.photo_url as sender_photo, u.designation as sender_designation
        FROM messages m
        LEFT JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.recipient_id = ?)
           OR (m.sender_id = ? AND m.recipient_id = ?)
        ORDER BY m.id ASC
        LIMIT 200
      `;
      params = [myId, peerId, peerId, String(myId)];
    }

    const messages = await all(sql, params);
    res.json(messages);
  } catch (err) {
    console.error('Get messages error:', err);
    res.status(500).json({ error: 'செய்திகளை பெறுவதில் பிழை' });
  }
});

// GET /api/messages/unread-counts (Unread counts per sender for current user)
app.get('/api/messages/unread-counts', authenticateToken, async (req, res) => {
  try {
    const unread = await all(
      `SELECT m.sender_id, m.sender_name, COUNT(*) as count, MAX(m.created_at) as last_time,
              (SELECT message FROM messages WHERE sender_id = m.sender_id AND recipient_id = ? ORDER BY id DESC LIMIT 1) as last_message
       FROM messages m
       WHERE m.recipient_id = ? AND m.is_read = 0
       GROUP BY m.sender_id, m.sender_name`,
      [String(req.user.id), String(req.user.id)]
    );
    res.json(unread);
  } catch (err) {
    console.error('Unread counts error:', err);
    res.status(500).json({ error: 'பிழை' });
  }
});

// POST /api/messages (Send message)
app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { recipient_id, message } = req.body;
    if (!recipient_id || !message || message.trim().length === 0) {
      return res.status(400).json({ error: 'செய்தி உள்ளடக்கத்தை உள்ளிடவும்' });
    }

    const result = await run(
      `INSERT INTO messages (sender_id, sender_name, recipient_id, message, is_read)
       VALUES (?, ?, ?, ?, 0)`,
      [req.user.id, req.user.name, String(recipient_id), message.trim()]
    );

    const newMsg = await get(
      `SELECT m.*, u.photo_url as sender_photo, u.designation as sender_designation
       FROM messages m
       LEFT JOIN users u ON m.sender_id = u.id
       WHERE m.id = ?`,
      [result.lastID]
    );

    // Emit real-time socket event
    io.emit('new_chat_message', newMsg);

    res.json({ success: true, message: newMsg });
  } catch (err) {
    console.error('Send message error:', err);
    res.status(500).json({ error: 'செய்தி அனுப்புவதில் பிழை' });
  }
});

// POST /api/messages/mark-read
app.post('/api/messages/mark-read', authenticateToken, async (req, res) => {
  try {
    const { sender_id } = req.body;
    if (!sender_id) return res.status(400).json({ error: 'Sender ID தேவை' });

    await run(
      `UPDATE messages
       SET is_read = 1, read_at = CURRENT_TIMESTAMP
       WHERE sender_id = ? AND recipient_id = ? AND is_read = 0`,
      [sender_id, String(req.user.id)]
    );

    io.emit('messages_read_by_recipient', {
      readerId: req.user.id,
      senderId: sender_id
    });

    res.json({ success: true });
  } catch (err) {
    console.error('Mark read error:', err);
    res.status(500).json({ error: 'வாசிப்பு நிலையை புதுப்பிப்பதில் பிழை' });
  }
});

// ----------------- EXCEL EXPORT (PrintReportView.xlsx) -----------------

// GET /api/export/excel
app.get('/api/export/excel', authenticateToken, async (req, res) => {
  try {
    const letters = await all(`
      SELECT
        l.serial_no as "தொடர் இலக்கம் (Serial No)",
        l.assigned_officer_name as "பொறுப்பளிக்கப்பட்ட உத்தியோகத்தர் (Assigned Officer)",
        l.received_date as "பெற்றுக்கொண்ட திகதி (Received Date)",
        l.subject as "விடயம் (Subject)",
        l.file_no as "கோவை இலக்கம் (File No)",
        l.due_date as "பதிலளிக்க வேண்டிய திகதி (Due Date)",
        COALESCE(l.responded_date, 'பதில் வழங்கப்படவில்லை') as "பதில் வழங்கிய திகதி (Responded Date)",
        l.status as "நிலை (Status)",
        l.points as "புள்ளிகள் (Points)"
      FROM letters l
      ORDER BY l.id ASC
    `);

    const worksheet = XLSX.utils.json_to_sheet(letters);

    // Set column widths for clean reading
    worksheet['!cols'] = [
      { wch: 18 }, // Serial No
      { wch: 28 }, // Officer
      { wch: 15 }, // Received Date
      { wch: 45 }, // Subject
      { wch: 20 }, // File No
      { wch: 16 }, // Due Date
      { wch: 16 }, // Responded Date
      { wch: 14 }, // Status
      { wch: 10 }  // Points
    ];

    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, 'கடிதங்கள் (Letters)');

    const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });

    res.setHeader('Content-Disposition', 'attachment; filename="PrintReportView.xlsx"');
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buffer);
  } catch (err) {
    console.error('Excel export error:', err);
    res.status(500).json({ error: 'Excel அறிக்கை தயாரிப்பதில் பிழை' });
  }
});

// ----------------- NETWORK & PUBLIC INTERNET IP DISCOVERY API -----------------
app.get('/api/network-info', (req, res) => {
  const nets = os.networkInterfaces();
  const ips = [];
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        ips.push({ interface: name, ip: net.address });
      }
    }
  }

  // Detect Public Cloud or Tunnel URL
  let publicUrl = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || '';
  if (!publicUrl) {
    try {
      const pubPath = path.join(__dirname, 'public', 'public_url.txt');
      if (fs.existsSync(pubPath)) {
        publicUrl = fs.readFileSync(pubPath, 'utf8').trim();
      }
    } catch (e) {}
  }

  // Detect if requested via public domain or proxy
  const reqHost = req.get('host') || '';
  const proto = req.headers['x-forwarded-proto'] || (req.connection.encrypted ? 'https' : 'http');
  const currentOrigin = `${proto}://${reqHost}`;
  if (!publicUrl && !reqHost.includes('localhost') && !reqHost.includes('127.0.0.1') && !reqHost.includes('172.20.')) {
    publicUrl = currentOrigin;
  }

  const effectiveUrl = publicUrl || (ips.length > 0 ? `http://${ips[0].ip}:${PORT}` : `http://localhost:${PORT}`);
  const whatsappText = encodeURIComponent(`🏛️ PLMS - திட்டமிடல் கடித முகாமைத்துவ முறைமை\nமண்முனை தென்மேற்கு பிரதேச செயலகம் (பட்டிப்பளை)\n\nஅலுவலகத்தின் 50+ உத்தியோகத்தர்களும் மொபைல் & கணினியில் பயன்படுத்த நேரடி இணைப்பு:\n👉 ${effectiveUrl}\n\n(Dialog, Mobitel, Airtel, Hutch அத்தனையிலும் 24 மணிநேரமும் இயங்கும்!)`);

  res.json({
    port: PORT,
    ips,
    localUrl: `http://localhost:${PORT}`,
    networkUrl: ips.length > 0 ? `http://${ips[0].ip}:${PORT}` : `http://localhost:${PORT}`,
    publicUrl: publicUrl || effectiveUrl,
    isPublic: Boolean(publicUrl),
    whatsappShareUrl: `https://api.whatsapp.com/send?text=${whatsappText}`,
    telecoms: ['Dialog Axiata (4G/5G)', 'SLT Mobitel (4G/5G/Fiber)', 'Airtel Sri Lanka', 'Hutch Sri Lanka', 'SLT Broadband']
  });
});

// GET /api/admin/backup-db (Export full SQLite Database for Cloud migration / safe storage)
app.get('/api/admin/backup-db', authenticateToken, (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'முதன்மை நிர்வாகிக்கு மட்டுமே அனுமதி உண்டு' });
  }

  const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'plms_database.sqlite');
  if (fs.existsSync(dbPath)) {
    const filename = `PLMS_Backup_${new Date().toISOString().split('T')[0]}.sqlite`;
    res.download(dbPath, filename);
  } else {
    res.status(404).json({ error: 'தரவுத்தளக் கோப்பு காணப்படவில்லை' });
  }
});

// ----------------- DOWNLOAD WINDOWS DESKTOP INSTALLER SCRIPT -----------------
app.get('/api/download-shortcut', (req, res) => {
  const host = req.get('host') || `localhost:${PORT}`;
  const targetUrl = `http://${host}`;

  const batContent = `@echo off
title PLMS Desktop App Shortcut Installer
echo ===============================================================================
echo   PLMS - Planning Letter Management System
echo   Divisional Secretariat Manmunai South West - Letter Management Planning Branch
echo ===============================================================================
echo.
echo Installing PLMS shortcut on your Windows Desktop...

powershell -NoProfile -ExecutionPolicy Bypass -Command "$url = '${targetUrl}'; $desk = [System.Environment]::GetFolderPath('Desktop'); $urlFile = Join-Path $desk 'PLMS - Planning Letter Management System.url'; Set-Content -Path $urlFile -Value \\"[InternetShortcut]\`r\`nURL=$url\`r\`nIconIndex=0\`r\`nIconFile=C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\`r\`n\\"; try { $ws = New-Object -ComObject WScript.Shell; $lnk = Join-Path $desk 'PLMS - Planning Letter Management System.lnk'; $s = $ws.CreateShortcut($lnk); $edge = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'; $edge64 = 'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe'; $chrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'; if (Test-Path $edge) { $s.TargetPath = $edge; $s.Arguments = \\"--app=$url\\"; $s.IconLocation = \\"$edge,0\\"; } elseif (Test-Path $edge64) { $s.TargetPath = $edge64; $s.Arguments = \\"--app=$url\\"; $s.IconLocation = \\"$edge64,0\\"; } elseif (Test-Path $chrome) { $s.TargetPath = $chrome; $s.Arguments = \\"--app=$url\\"; $s.IconLocation = \\"$chrome,0\\"; } else { $s.TargetPath = $url; }; $s.Description = 'PLMS - Planning Letter Management System'; $s.Save(); } catch {}; Write-Host '\`n================================================================' -ForegroundColor Cyan; Write-Host '  SUCCESS: PLMS Desktop Shortcut Created Successfully!' -ForegroundColor Green; Write-Host '  Desktop Icon: PLMS - Planning Letter Management System' -ForegroundColor Yellow; Write-Host '  Target URL: ' $url -ForegroundColor White; Write-Host '================================================================\`n' -ForegroundColor Cyan;"

pause
`;

  res.setHeader('Content-Disposition', 'attachment; filename="Setup_PLMS_Desktop.bat"');
  res.setHeader('Content-Type', 'application/x-bat; charset=utf-8');
  res.send(batContent);
});

// GET /api/download-url (Direct .url download for 1-click Desktop saving)
app.get('/api/download-url', (req, res) => {
  const host = req.get('host') || `localhost:${PORT}`;
  const targetUrl = `http://${host}`;

  const urlContent = `[InternetShortcut]\r\nURL=${targetUrl}\r\nIconIndex=0\r\nIconFile=C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\r\n`;

  res.setHeader('Content-Disposition', 'attachment; filename="PLMS - Planning Letter Management System.url"');
  res.setHeader('Content-Type', 'application/internet-shortcut');
  res.send(urlContent);
});

// Catch-all fallback to serve index.html for SPA
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Socket.io connection handling
io.on('connection', (socket) => {
  // Officer joined
  socket.on('user_online', (data) => {
    socket.userId = data.userId;
    io.emit('user_status_changed', { userId: data.userId, online: true });
  });

  socket.on('disconnect', () => {
    if (socket.userId) {
      io.emit('user_status_changed', { userId: socket.userId, online: false });
    }
  });
});

// Start Server after DB initialization
initDB().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    const nets = os.networkInterfaces();
    const ips = [];
    for (const name of Object.keys(nets)) {
      for (const net of nets[name]) {
        if (net.family === 'IPv4' && !net.internal) {
          ips.push(net.address);
        }
      }
    }

    console.log('================================================================');
    console.log('  🏛️  PLMS - Planning Letter Management System');
    console.log('  மண்முனை தென்மேற்கு பிரதேச செயலகம் - திட்டமிடல் பிரிவு');
    console.log('================================================================');
    console.log(`  🚀 Local Access:   http://localhost:${PORT}`);
    if (ips.length > 0) {
      ips.forEach(ip => {
        console.log(`  🌐 Office LAN:     http://${ip}:${PORT}`);
      });
      console.log('  👉 Share http://' + ips[0] + ':' + PORT + ' with all 50 officers!');
    }
    console.log('  💻 PWA Desktop:    Open in Browser & Click "Install to PC"');
    console.log('================================================================');
  });
}).catch(err => {
  console.error('Database initialization failed:', err);
});

module.exports = { app, server, io };
