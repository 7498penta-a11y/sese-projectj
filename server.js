require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');

const app = express();

// --- 簡易データベース（本番ではMongoDBやSQLを推奨） ---
let contacts = []; // お問い合わせデータ保存用

// --- Passportの設定 (Googleログイン) ---
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL
  },
  (accessToken, refreshToken, profile, done) => {
    // ユーザー情報を整理
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

// --- ミドルウェア設定 ---
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static('public')); // HTMLファイルを置くフォルダ

// --- 管理者判定用ヘルパー ---
const isAdmin = (user) => {
  if (!user || !user.email) return false;
  const adminList = process.env.ADMIN_EMAILS.split(',');
  return adminList.includes(user.email);
};

// --- APIルート ---

// ログイン状態と管理者フラグを返す
app.get('/api/user', (req, res) => {
  if (!req.isAuthenticated()) return res.json({ isLoggedIn: false });
  res.json({
    isLoggedIn: true,
    user: {
      ...req.user,
      isAdmin: isAdmin(req.user)
    }
  });
});

// お問い合わせ送信
app.post('/api/contact', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });
  
  const newContact = {
    id: Date.now().toString(),
    userId: req.user.id,
    userName: req.user.name,
    userEmail: req.user.email,
    userPhoto: req.user.photo,
    message: req.body.message,
    reply: null,
    createdAt: new Date()
  };
  
  contacts.push(newContact);
  res.json({ success: true, message: '送信が完了しました' });
});

// 自分の履歴取得
app.get('/api/my-contacts', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).send();
  const myData = contacts.filter(c => c.userId === req.user.id);
  res.json(myData);
});

// 【管理者専用】全件取得
app.get('/api/admin/contacts', (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).send('Forbidden');
  res.json(contacts);
});

// 【管理者専用】返信の保存
app.post('/api/admin/reply/:id', (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).send('Forbidden');
  
  const ticket = contacts.find(c => c.id === req.params.id);
  if (ticket) {
    ticket.reply = req.body.reply;
    res.json({ success: true });
  } else {
    res.status(404).send('Not found');
  }
});

// --- 認証ルート ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => res.redirect('/#contact') // ログイン後にお問い合わせページへ
);

app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// サーバー起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
