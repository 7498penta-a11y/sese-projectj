require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const axios = require('axios');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;

// --- データの保存場所（ここがサーバーのメモリです） ---
let allMessages = []; 

app.use(session({
  secret: process.env.SESSION_SECRET || 'sese_secure_key_1122',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL || "/auth/google/callback",
    proxy: true
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, {
      name: profile.displayName,
      photo: profile.photos[0].value,
      email: profile.emails[0].value
    });
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ユーザー情報
app.get('/api/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ isLoggedIn: true, user: req.user, isAdmin: req.user.email === ADMIN_EMAIL });
  } else {
    res.json({ isLoggedIn: false });
  }
});

// メッセージ送信
app.post('/api/contact', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });
  
  const newMessage = {
    id: Date.now().toString(),
    userName: req.user.name,
    email: req.user.email,
    content: req.body.message,
    reply: "",
    timestamp: new Date().toLocaleString('ja-JP')
  };

  allMessages.push(newMessage);

  // Discordへバックアップとして通知
  if (process.env.DISCORD_WEBHOOK_URL) {
    try {
      await axios.post(process.env.DISCORD_WEBHOOK_URL, {
        content: `📩 **新着メッセージ**: ${req.user.name}さんより\n内容: ${req.body.message}`
      });
    } catch (e) { console.error("Discord通知失敗"); }
  }

  res.json({ success: true });
});

// 自分のメッセージ取得
app.get('/api/my-messages', (req, res) => {
  if (!req.isAuthenticated()) return res.json({ messages: [] });
  const mine = allMessages.filter(m => m.email === req.user.email);
  res.json({ messages: mine });
});

// 【管理用】全メッセージ取得
app.get('/api/admin/messages', (req, res) => {
  if (req.isAuthenticated() && req.user.email === ADMIN_EMAIL) {
    res.json({ messages: allMessages });
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
});

// 【管理用】返信
app.post('/api/admin/reply', (req, res) => {
  if (req.isAuthenticated() && req.user.email === ADMIN_EMAIL) {
    const { messageId, replyContent } = req.body;
    const msg = allMessages.find(m => m.id === messageId);
    if (msg) {
      msg.reply = replyContent;
      res.json({ success: true });
    } else {
      res.status(404).json({ error: 'Not Found' });
    }
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
});

app.get('/logout', (req, res) => { req.logout(() => res.redirect('/')); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
