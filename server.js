require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

const app = express();

// データベース保存用ディレクトリの作成
const dbDir = path.join(__dirname, 'database');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir);
}

// SQLiteデータベースの初期化
const db = new sqlite3.Database(path.join(dbDir, 'database.sqlite'));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,
    userId TEXT,
    userName TEXT,
    userEmail TEXT,
    userPhoto TEXT,
    message TEXT,
    reply TEXT,
    createdAt DATETIME
  )`);
});

// Google OAuth 設定
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL
  },
  (accessToken, refreshToken, profile, done) => {
    const user = {
      id: profile.id,
      name: profile.displayName,
      email: profile.emails[0].value,
      photo: profile.photos[0].value
    };
    return done(null, user);
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ミドルウェア
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'sese_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));
app.use(passport.initialize());
app.use(passport.session());

// 静的ファイルの提供 (publicフォルダを指定)
app.use(express.static(path.join(__dirname, 'public')));

// 管理者判定
const isAdmin = (user) => {
  if (!user || !user.email) return false;
  const adminList = (process.env.ADMIN_EMAILS || "").split(',');
  return adminList.includes(user.email);
};

// --- API ---
app.get('/api/user', (req, res) => {
  if (!req.isAuthenticated()) return res.json({ isLoggedIn: false });
  res.json({
    isLoggedIn: true,
    user: { ...req.user, isAdmin: isAdmin(req.user) }
  });
});

app.post('/api/contact', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });
  const { message } = req.body;
  const id = Date.now().toString();
  const createdAt = new Date().toISOString();

  db.run(`INSERT INTO contacts (id, userId, userName, userEmail, userPhoto, message, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [id, req.user.id, req.user.name, req.user.email, req.user.photo, message, createdAt],
    (err) => {
      if (err) return res.status(500).json({ error: 'DBエラー' });
      res.json({ success: true });
    }
  );
});

app.get('/api/my-contacts', (req, res) => {
  if (!req.isAuthenticated()) return res.json([]);
  db.all(`SELECT * FROM contacts WHERE userId = ? ORDER BY createdAt DESC`, [req.user.id], (err, rows) => {
    res.json(rows || []);
  });
});

app.get('/api/admin/contacts', (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).send('拒否されました');
  db.all(`SELECT * FROM contacts ORDER BY createdAt DESC`, [], (err, rows) => {
    res.json(rows || []);
  });
});

app.post('/api/admin/reply/:id', (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).send('拒否されました');
  db.run(`UPDATE contacts SET reply = ? WHERE id = ?`, [req.body.reply, req.params.id], (err) => {
    res.json({ success: true });
  });
});

// 認証ルート
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  res.redirect('/#contact');
});
app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// メインページ (public/index.html を返す)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
});
