require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');

const app = express();

// 簡易データベース（サーバー再起動でリセットされます）
// 本番運用ではSQLiteやMongoDBなどのDB接続を推奨します
let contacts = []; 

// --- Passport 設定 ---
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

// --- ミドルウェア ---
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// 管理者判定関数
const isAdmin = (user) => {
  if (!user || !user.email) return false;
  const adminList = process.env.ADMIN_EMAILS.split(',');
  return adminList.includes(user.email);
};

// --- API エンドポイント ---

// ユーザー情報取得
app.get('/api/user', (req, res) => {
  if (!req.isAuthenticated()) return res.json({ isLoggedIn: false });
  res.json({
    isLoggedIn: true,
    user: { ...req.user, isAdmin: isAdmin(req.user) }
  });
});

// お問い合わせ送信
app.post('/api/contact', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Login required' });
  const newEntry = {
    id: Date.now().toString(),
    userId: req.user.id,
    userName: req.user.name,
    userEmail: req.user.email,
    userPhoto: req.user.photo,
    message: req.body.message,
    reply: null,
    createdAt: new Date()
  };
  contacts.push(newEntry);
  res.json({ success: true, message: '運営に送信されました！' });
});

// 自分の履歴取得
app.get('/api/my-contacts', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json([]);
  const userHistory = contacts.filter(c => c.userId === req.user.id);
  res.json(userHistory);
});

// 管理者：全件取得
app.get('/api/admin/contacts', (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).send('Access Denied');
  res.json(contacts);
});

// 管理者：返答保存
app.post('/api/admin/reply/:id', (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).send('Access Denied');
  const entry = contacts.find(c => c.id === req.params.id);
  if (entry) {
    entry.reply = req.body.reply;
    res.json({ success: true });
  } else {
    res.status(404).send('Not found');
  }
});

// --- 認証ルート ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  res.redirect('/#contact');
});
app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// 静的ファイルの配信
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server: http://localhost:${PORT}`));
