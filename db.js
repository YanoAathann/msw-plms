const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'plms_database.sqlite');
const db = new sqlite3.Database(dbPath);

// Helper for promise-based queries
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// Master designated officers list in exact required order
const DESIGNATED_OFFICERS = [
  { name: 'MR .S. SUTHAKAR', designation: 'DS', email: 'ds.msw@gov.lk', gender: 'Male', dob: '1975-05-12' },
  { name: 'MR .S. PARTHEEPAN', designation: 'ADS', email: 'ads.msw@gov.lk', gender: 'Male', dob: '1980-08-20' },
  { name: 'MR. S. SASIKUMAR', designation: 'DDP', email: 'adpsasi@gmail.com', gender: 'Male', dob: '1982-11-15' }, // Primary Super Admin
  { name: 'MR. M.H.M. FAHIR', designation: 'MSO', email: 'mfahir25@gmail.com', gender: 'Male', dob: '1985-03-25' }, // Secondary Admin
  { name: 'MR. T RUDRAN', designation: 'TO', email: 'rudran.to@gov.lk', gender: 'Male', dob: '1988-07-10' },
  { name: 'MR. J. VINOKANTHAN', designation: 'CEO', email: 'vinokanthan.ceo@gov.lk', gender: 'Male', dob: '1987-09-14' },
  { name: 'MRS. J.JEEVARATHY', designation: 'CEO', email: 'jeevarathy.ceo@gov.lk', gender: 'Female', dob: '1989-12-05' },
  { name: 'MRS. P. LIVIYA', designation: 'DO', email: 'liviya.do@gov.lk', gender: 'Female', dob: '1992-04-18' },
  { name: 'MRS. M. SHYAMINI', designation: 'DO', email: 'shyamini.do@gov.lk', gender: 'Female', dob: '1991-06-22' },
  { name: 'MR. Y. THANANJAYAN', designation: 'DO', email: 'thananjayan.do@gov.lk', gender: 'Male', dob: '1990-10-30' },
  { name: 'MR. C. PIRATHAPAN', designation: 'DO', email: 'pirathapan.do@gov.lk', gender: 'Male', dob: '1989-01-19' },
  { name: 'MR. P .YANOPAN', designation: 'CEO', email: 'virudsham@gmail.com', gender: 'Male', dob: '1993-02-14' }, // Primary Super Admin (Janopan)
  { name: 'MR B. SATHEESKUMAR', designation: 'DO', email: 'satheeskumar.do@gov.lk', gender: 'Male', dob: '1986-08-08' },
  { name: 'MR. T. PUVANES', designation: 'CEO', email: 'puvanes.ceo@gov.lk', gender: 'Male', dob: '1984-12-28' },
  { name: 'MRS. K. RAJINI', designation: 'DO', email: 'rajini.do@gov.lk', gender: 'Female', dob: '1988-03-17' },
  { name: 'MR. S.JASOTHANATHNAN', designation: 'MSO', email: 'jasothan.mso@gov.lk', gender: 'Male', dob: '1992-09-02' },
  { name: 'MRS. M.F.R FARMANA', designation: 'MSO', email: 'farmana.mso@gov.lk', gender: 'Female', dob: '1994-11-23' },
  { name: 'MRS. M.M.F AATHIKA', designation: 'MSO', email: 'aathika.mso@gov.lk', gender: 'Female', dob: '1995-07-07' }
];

async function initDB() {
  // Users table
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    designation TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    phone TEXT,
    dob TEXT,
    gender TEXT,
    photo_url TEXT DEFAULT '/assets/default_avatar.png',
    role TEXT DEFAULT 'officer',
    points INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Letters table
  await run(`CREATE TABLE IF NOT EXISTS letters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_no TEXT UNIQUE NOT NULL,
    assigned_officer_id INTEGER,
    assigned_officer_name TEXT NOT NULL,
    received_date TEXT NOT NULL,
    subject TEXT NOT NULL,
    file_no TEXT NOT NULL,
    due_date TEXT NOT NULL,
    responded_date TEXT,
    status TEXT DEFAULT 'Pending',
    points INTEGER DEFAULT 0,
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Messages table
  await run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    sender_name TEXT NOT NULL,
    recipient_id TEXT NOT NULL, -- 'group' or numeric user ID
    message TEXT NOT NULL,
    is_read INTEGER DEFAULT 0, -- 0 = Unread (Black), 1 = Read (Green)
    read_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Password reset OTPs table
  await run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    otp TEXT NOT NULL,
    expires_at DATETIME NOT NULL
  )`);

  // Notifications table
  await run(`CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT DEFAULT 'info',
    is_read INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Seed default officers if table is empty
  const userCount = await get('SELECT COUNT(*) as count FROM users');
  if (userCount.count === 0) {
    console.log('Seeding initial officers...');
    // Default initial password meeting security criteria (1 Uppercase, 6+ Lowercase, 1 Symbol): Plms@admin2026
    const defaultHashedPassword = await bcrypt.hash('Plms@admin2026', 10);

    for (const officer of DESIGNATED_OFFICERS) {
      let role = 'officer';
      const emailLower = officer.email.toLowerCase();
      if (emailLower === 'virudsham@gmail.com' || emailLower === 'adpsasi@gmail.com') {
        role = 'super_admin';
      } else if (emailLower === 'mfahir25@gmail.com') {
        role = 'secondary_admin';
      }

      await run(
        `INSERT INTO users (name, designation, email, password, phone, dob, gender, photo_url, role, points)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          officer.name,
          officer.designation,
          officer.email,
          defaultHashedPassword,
          '0652222222',
          officer.dob,
          officer.gender,
          '/assets/default_avatar.png',
          role,
          0
        ]
      );
    }
    console.log('Successfully seeded 18 master officers with roles.');

    // Seed sample letters to showcase tracking and scoring
    const sampleLetters = [
      {
        serial_no: '001/10/10/2026',
        officer_name: 'MR .S. SUTHAKAR',
        received_date: '2026-10-10',
        subject: 'பிரதேச அபிவிருத்தி திட்ட முன்மொழிவு - 2027 (District Dev Proposal)',
        file_no: 'PLN/DEV/2026/014',
        due_date: '2026-10-18',
        responded_date: null,
        status: 'Pending'
      },
      {
        serial_no: '002/08/10/2026',
        officer_name: 'MR. P .YANOPAN',
        received_date: '2026-10-08',
        subject: 'சமூக வலுவூட்டல் பயிற்சி பட்டறை நிதி ஒதுக்கீட்டு கடிதம்',
        file_no: 'PLN/EMP/2026/089',
        due_date: '2026-10-15',
        responded_date: '2026-10-12',
        status: 'Responded'
      },
      {
        serial_no: '003/05/10/2026',
        officer_name: 'MR. S. SASIKUMAR',
        received_date: '2026-10-05',
        subject: 'வருடாந்த முன்னேற்ற மீளாய்வு அறிக்கை 2026 (Annual Progress Review)',
        file_no: 'PLN/PRG/2026/003',
        due_date: '2026-10-14',
        responded_date: '2026-10-11',
        status: 'Responded'
      },
      {
        serial_no: '004/01/10/2026',
        officer_name: 'MR. M.H.M. FAHIR',
        received_date: '2026-10-01',
        subject: 'திட்டமிடல் பிரிவின் எழுதுபொருட்கள் கேள்விப்பத்திர ஆவணம்',
        file_no: 'PLN/ADM/2026/052',
        due_date: '2026-10-09',
        responded_date: '2026-10-08',
        status: 'Responded'
      },
      {
        serial_no: '005/12/10/2026',
        officer_name: 'MRS. P. LIVIYA',
        received_date: '2026-10-12',
        subject: 'வாழ்வாதார உதவி திட்ட பயனாளிகள் விபரக் கோரிக்கை',
        file_no: 'PLN/LIV/2026/102',
        due_date: '2026-10-16',
        responded_date: null,
        status: 'Pending'
      }
    ];

    for (const l of sampleLetters) {
      const off = await get('SELECT id FROM users WHERE name = ?', [l.officer_name]);
      const offId = off ? off.id : 1;
      
      // Calculate points
      let points = 0;
      if (l.responded_date) {
        const due = new Date(l.due_date);
        const resp = new Date(l.responded_date);
        const diffDays = Math.round((due - resp) / (1000 * 60 * 60 * 24));
        if (diffDays >= 0) {
          points = Math.max(1, diffDays); // +1 point per day early (minimum +1)
        } else {
          points = diffDays; // negative points for delay
        }
      }

      await run(
        `INSERT INTO letters (serial_no, assigned_officer_id, assigned_officer_name, received_date, subject, file_no, due_date, responded_date, status, points, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          l.serial_no,
          offId,
          l.officer_name,
          l.received_date,
          l.subject,
          l.file_no,
          l.due_date,
          l.responded_date,
          l.status,
          points,
          'virudsham@gmail.com'
        ]
      );
    }

    // Update officers aggregated points
    await run(`UPDATE users SET points = (
      SELECT COALESCE(SUM(points), 0) FROM letters WHERE assigned_officer_id = users.id
    )`);
  }
}

module.exports = {
  db,
  run,
  get,
  all,
  initDB,
  DESIGNATED_OFFICERS
};
