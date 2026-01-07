require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

const app = express();

// データベース保存用設定
const dbDir = path.join(__dirname, 'database');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir);
const db = new sqlite3.Database(path.join(dbDir, 'database.sqlite'));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY, userId TEXT, userName TEXT, userEmail TEXT, 
    userPhoto TEXT, message TEXT, reply TEXT, createdAt DATETIME
  )`);
});

// Google OAuth
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, {
      id: profile.id,
      name: profile.displayName,
      email: profile.emails[0].value,
      photo: profile.photos[0].value
    });
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'sese-secret',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// --- ここが重要：publicフォルダを静的ファイルとして公開 ---
app.use(express.static(path.join(__dirname, 'public')));

// 管理者判定
const isAdmin = (user) => {
  const admins = (process.env.ADMIN_EMAILS || "").split(',');
  return user && admins.includes(user.email);
};

// API
app.get('/api/user', (req, res) => {
  res.json(req.isAuthenticated() ? { isLoggedIn: true, user: { ...req.user, isAdmin: isAdmin(req.user) } } : { isLoggedIn: false });
});

app.post('/api/contact', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).send();
  const { message } = req.body;
  db.run(`INSERT INTO contacts (id, userId, userName, userEmail, userPhoto, message, createdAt) VALUES (?,?,?,?,?,?,?)`,
    [Date.now().toString(), req.user.id, req.user.name, req.user.email, req.user.photo, message, new Date().toISOString()]);
  res.json({ success: true });
});

app.get('/api/my-contacts', (req, res) => {
  if (!req.isAuthenticated()) return res.json([]);
  db.all(`SELECT * FROM contacts WHERE userId = ? ORDER BY createdAt DESC`, [req.user.id], (err, rows) => res.json(rows || []));
});

app.get('/api/admin/contacts', (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).send();
  db.all(`SELECT * FROM contacts ORDER BY createdAt DESC`, (err, rows) => res.json(rows || []));
});

app.post('/api/admin/reply/:id', (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).send();
  db.run(`UPDATE contacts SET reply = ? WHERE id = ?`, [req.body.reply, req.params.id], () => res.json({ success: true }));
});

// 認証
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => res.redirect('/#contact'));
app.get('/logout', (req, res) => req.logout(() => res.redirect('/')));

// --- 修正：ルートにアクセスした時に public/index.html を返す ---
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server is running on port ${PORT}`));
