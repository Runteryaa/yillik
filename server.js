const express = require('express');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const axios = require('axios');
const multer = require('multer');
const admin = require('firebase-admin');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const FormData = require('form-data');
require('dotenv').config();
const cloudinary = require('cloudinary').v2;
const rateLimit = require('express-rate-limit');


cloudinary.config();

const app = express();
app.use('/s', express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);

const serviceAccount = {
  type: process.env.FIREBASE_TYPE,
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI,
  token_uri: process.env.FIREBASE_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
  universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.DB_URL
});
const db = admin.database();

app.get('/hakkinda', (req, res) => {
    res.render('hakkinda', { 
        title: 'Hakkında | Yillik.com.tr'
    });
});

app.get('/gizlilik', (req, res) => {
    res.render('gizlilik', { 
        title: 'Gizlilik Politikası | Yillik.com.tr'
    });
});

app.get('/kullanim', (req, res) => {
    res.render('kullanim', { 
        title: 'Kullanim Şartları | Yillik.com.tr'
    });
});


// Serve ads.txt from root
app.get('/ads.txt', (req, res) => {
    res.sendFile(path.join(__dirname, 'ads.txt'));
});

// Serve robots.txt from root
app.get('/robots.txt', (req, res) => {
    res.sendFile(path.join(__dirname, 'robots.txt'));
});

// Show all schools on homepage
app.get('/', async (req, res) => {
  const snapshot = await db.ref('/schools').once('value');
  const schools = snapshot.val() || {};

  res.render('index', {
    title: 'Okullar | Yillik.com.tr',
    schools
  });
});


app.get('/search', async (req, res) => {
  const query = req.query.q?.toLowerCase().trim() || '';
  const snapshot = await db.ref('/schools').once('value');
  const schools = snapshot.val() || {};
  const results = [];

  for (const [key, data] of Object.entries(schools)) {
    const longName = data.name?.toLowerCase() || '';
    const image = data.image || '/s/placeholder.svg';

    if (key.includes(query) || longName.includes(query)) {
      results.push({
        key,
        name: data.name || key,
        image,
        yearCount: data.years ? Object.keys(data.years).length : 0
      });
    }
  }

  res.render('schoolsearch', {
    title: `"${query}" için okul arama`,
    results,
    query
  });
});



app.get('/d/:school/search', async (req, res) => {
  const { school } = req.params;
  const query = req.query.q?.toLowerCase();
  if (!query) return res.redirect(`/d/${school}`);

  const results = [];
  const schoolRef = db.ref(`/schools/${school.toLowerCase()}/years`);
  const yearsSnapshot = await schoolRef.once('value');
  const years = yearsSnapshot.val() || {};

  for (const [yearKey, yearData] of Object.entries(years)) {
    const classes = yearData.classes || {};
    for (const [classKey, classData] of Object.entries(classes)) {
      const students = classData.students || {};
      for (const [studentKey, student] of Object.entries(students)) {
        const name = student.name?.toLowerCase() || '';
        const number = student.number?.toString() || '';
        const instagram = student.instagram?.toLowerCase() || '';

        if (name.includes(query) || number.includes(query) || instagram.includes(query)) {
          results.push({
            student,
            year: yearKey,
            className: classKey
          });
        }
      }
    }
  }

  res.render('studentsearch', {
    title: `"${query}" için ${school} öğrencileri araması | Yillik75`,
    query,
    results,
    type: 'student',
    school
  });
});

// Show years for selected school
app.get('/d/:school', async (req, res) => {
  const { school } = req.params;
  const snapshot = await db.ref(`/schools/${school}/years`).once('value');
  const years = snapshot.val() || {};

  res.render('years', {
    title: `${school} Yıllar | Yillik.com.tr`,
    school,
    years
  });
});

// Show classes for given school and year
app.get('/d/:school/:year', async (req, res) => {
  const { school, year } = req.params;
  const snapshot = await db.ref(`/schools/${school}/years/${year}/classes`).once('value');
  const classes = snapshot.val() || {};

  res.render('classes', {
    title: `${school} ${year} Sınıfları | Yillik.com.tr`,
    school,
    year,
    classes
  });
});

// Show students for class
app.get('/d/:school/:year/:className', async (req, res) => {
  const { school, year, className } = req.params;
  const snapshot = await db.ref(`/schools/${school}/years/${year}/classes/${className}/students`).once('value');
  const students = snapshot.val() || [];

  res.render('students', {
    title: `${school} ${year} ${className} Öğrenciler | Yillik.com.tr`,
    school,
    year,
    className,
    students
  });
});

// Show single student details
app.get('/d/:school/:year/:className/:studentNumber', async (req, res) => {
  const { school, year, className, studentNumber } = req.params;
  const snapshot = await db.ref(`/schools/${school}/years/${year}/classes/${className}/students`).once('value');
  const students = snapshot.val() || [];

  const student = students.find(s => s.number === studentNumber);
  if (!student) {
    return res.status(404).send('Öğrenci bulunamadı');
  }

  res.render('student', {
    title: `${student.name} | ${school} ${year} ${className}`,
    school,
    year,
    className,
    student
  });
});


const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD
function parseCookies(req) {
    const list = {};
    const rc = req.headers.cookie;
    if (rc) {
        rc.split(';').forEach(cookie => {
            const parts = cookie.split('=');
            list[parts.shift().trim()] = decodeURI(parts.join('='));
        });
    }
    return list;
}

function requireAdmin(req, res, next) {
    const cookies = parseCookies(req);
    if (cookies.admin === process.env.ADMIN_PASSWORD) {
        return next();
    }
    res.redirect('/admin/login');
}

app.get('/admin', requireAdmin, (req, res) => {
    res.render('admin', { title: 'Admin Paneli' });
});

app.get('/admin/login', (req, res) => {
    res.render('admin_login', { error: null });
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Çok fazla giriş denemesi yaptınız. Lütfen 15 dakika sonra tekrar deneyin.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429);
    res.render('admin_login', { error: 'Çok fazla giriş denemesi yaptınız. Lütfen 15 dakika sonra tekrar deneyin.' });
  }
});

app.post('/admin/login', loginLimiter, async (req, res) => {
    const { password } = req.body;

    const now = new Date();
    const utc3 = new Date(now.getTime() + 3 * 60 * 60 * 1000);
    const formatted = utc3.toISOString().replace('T', ' ').substring(0, 19) + ' (UTC+3)';

    const cfConnectingIp = req.headers['cf-connecting-ip'] || req.ip;

    const attemptLog = {
        time: formatted,
        ip: cfConnectingIp,
        cf_ip: cfConnectingIp,
        timestamp: Date.now(),
        headers: req.headers,
        password_length: password ? password.length : 0,
        success: password === ADMIN_PASSWORD
    };

    console.log(`[ADMIN LOGIN ATTEMPT] IP: ${req.ip} | Time: ${formatted}`);
    console.log('Attempting to log to Firebase:', attemptLog);

    try {
        const dbResult = await db.ref('login_attempts').push(attemptLog);
        console.log('Logged to Firebase successfully:', dbResult.key);
    } catch (err) {
        console.error('Error logging to Firebase:', err);
    }

    if (password === ADMIN_PASSWORD) {
        const sessionToken = crypto.randomBytes(32).toString('hex');
        const isProd = process.env.NODE_ENV === 'production';
        res.setHeader('Set-Cookie', [
            `admin=${process.env.ADMIN_PASSWORD}; Path=/; HttpOnly; SameSite=Strict${isProd ? '; Secure' : ''}`
        ]);
        return res.redirect('/admin');
    }
    res.render('admin_login', { error: 'Hatalı şifre' });
});

app.get('/admin/edit', requireAdmin, (req, res) => {
    res.render('admin_edit', { title: 'Edit | Admin Paneli' });
});

app.post('/upload-image', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file uploaded' });
    }

    const stream = cloudinary.uploader.upload_stream(
      { 
        resource_type: 'image',
        folder: 'yillik75',
        quality: "auto:best",
        fetch_format: "auto",
        width: 400,
        crop: "limit"
      },
      (error, result) => {
        if (error) {
          console.error('Cloudinary upload error:', error);
          return res.status(500).json({ error: 'Cloudinary upload error', details: error.message });
        }
        return res.json({ url: result.secure_url });
      }
    );
    stream.end(req.file.buffer);

  } catch (err) {
    console.error('Upload error:', err.message);
    return res.status(500).json({ error: 'Upload error', details: err.message });
  }
});


app.post('/admin/add-student', requireAdmin, async (req, res) => {
  const { year, className, student } = req.body;
  const ref = db.ref(`years/${year}/classes/${className}/students`);
  const snapshot = await ref.once('value');
  const students = snapshot.val() || [];
  students.push(student);
  await ref.set(students);
  res.json({ success: true });
});

app.post('/admin/edit-student', requireAdmin, async (req, res) => {
  const { year, className, index, student } = req.body;
  const ref = db.ref(`years/${year}/classes/${className}/students`);
  const snapshot = await ref.once('value');
  const students = snapshot.val() || [];
  students[index] = student;
  await ref.set(students);
  res.json({ success: true });
});

app.post('/admin/remove-student', requireAdmin, async (req, res) => {
  const { year, className, index } = req.body;
  const ref = db.ref(`years/${year}/classes/${className}/students`);
  const snapshot = await ref.once('value');
  const students = snapshot.val() || [];
  students.splice(index, 1);
  await ref.set(students);
  res.json({ success: true });
});

app.get('/admin/firebase-data', requireAdmin, async (req, res) => {
  const snapshot = await db.ref('/').once('value');
  res.json(snapshot.val());
});

app.post('/admin/save-json', requireAdmin, async (req, res) => {
  const data = req.body;
  await db.ref('/').set(data);
  res.json({ success: true });
});

app.get('/admin/logs', requireAdmin, async (req, res) => {
    const snapshot = await db.ref('login_attempts').once('value');
    let logs = [];
    snapshot.forEach(child => {
        logs.push({ key: child.key, ...child.val() });
    });
    logs.sort((a, b) => b.key.localeCompare(a.key));
    logs = logs.slice(0, 100);
    res.render('admin_logs', { title: 'Admin Giriş Logları', logs });
});

app.get('/admin/logout', (req, res) => {
    const isProd = process.env.NODE_ENV === 'production';

    res.setHeader('Set-Cookie', [
        `admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${isProd ? '; Secure' : ''}`
    ]);

    res.redirect('/admin/login');
});

// School admin login page
app.get('/admin/:school/login', (req, res) => {
    res.render('admin_login', { error: null, school: req.params.school });
});

// School admin login POST
app.post('/admin/:school/login', async (req, res) => {
    const { school } = req.params;
    const { password } = req.body;

    // Get hashed password from /school_admins
    const adminSnap = await db.ref(`/school_admins/${school}`).once('value');
    const adminData = adminSnap.val();

    if (!adminData || !adminData.password) {
        return res.render('admin_login', { error: 'Okul bulunamadı veya şifre ayarlanmamış.', school });
    }

    const match = await bcrypt.compare(password, adminData.password);
    if (match) {
        const sessionToken = crypto.randomBytes(32).toString('hex');
        const isProd = process.env.NODE_ENV === 'production';
        res.setHeader('Set-Cookie', [
            `school_admin_${school}=${sessionToken}; Path=/; HttpOnly; SameSite=Strict${isProd ? '; Secure' : ''}`
        ]);
        // Optionally: Save sessionToken in DB for session tracking
        return res.redirect(`/admin/${school}`);
    }
    res.render('admin_login', { error: 'Hatalı şifre', school });
});

app.use((req, res) => {
    res.status(404).render('404', { title: 'Sayfa Bulunamadı | Yillik.com.tr' });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});