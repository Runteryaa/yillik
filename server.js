const express = require('express');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const axios = require('axios');
const multer = require('multer');
const admin = require('firebase-admin');
const crypto = require('crypto');
const FormData = require('form-data');
require('dotenv').config();
const cloudinary = require('cloudinary').v2;
const rateLimit = require('express-rate-limit');

cloudinary.config();

const app = express();
const PORT = process.env.PORT || 3000;
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
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


// Show all schools on homepage
app.get('/', async (req, res) => {
  const snapshot = await db.ref('/schools').once('value');
  const schools = snapshot.val() || {};

  res.render('index', {
    title: 'Okullar | Yillik.com.tr',
    schools
  });
});

// Show years for selected school
app.get('/:school', async (req, res) => {
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
app.get('/:school/:year', async (req, res) => {
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
app.get('/:school/:year/:className', async (req, res) => {
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
app.get('/:school/:year/:className/:studentNumber', async (req, res) => {
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




app.get('/search', async (req, res) => {
    const query = req.query.q?.toLowerCase().trim();
    const snapshot = await db.ref('/').once('value');
    const studentData = snapshot.val();

    if (!query) {
        return res.render('search', { title: 'Mezun Ara | Yillik.com.tr', results: [], query: '' });
    }

    let results = [];
    for (const [year, yearData] of Object.entries(studentData.years)) {
        for (const [className, classData] of Object.entries(yearData.classes)) {
            for (const student of (classData.students || [])) {
                if (
                    student.name.toLowerCase().includes(query) ||
                    student.number === query ||
                    ( Array.isArray(student.socials) && student.socials.some( s => s.name.toLowerCase() === 'instagram' && ( (s.link && s.link.toLowerCase().includes(query)) || (s.username && s.username.toLowerCase().includes(query)) ) ) ) ) {
                    
                    results.push({
                        year,
                        className,
                        student
                    });
                }
            }
        }
    }

    res.render('search', { title: 'Mezun Ara | Yillik.com.tr', results, query });
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

app.use((req, res) => {
    res.status(404).render('404', { title: 'Sayfa Bulunamadı | Yillik.com.tr' });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});