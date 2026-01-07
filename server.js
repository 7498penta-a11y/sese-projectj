require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const axios = require('axios');
const path = require('path');
const mongoose = require('mongoose'); // 追加

const app = express();
app.use(express.json());
app.use(express.static('public'));

// --- 1. MongoDB 接続設定 ---
const MONGODB_URI = process.env.MONGODB_URI;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;

mongoose.connect(MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected Successfully"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err));

// --- 2. データベースの保存形式（スキーマ）定義 ---
const MessageSchema = new mongoose.Schema({
  userName: String,
  email: String,
  content: String,
  reply: { type: String, default: "" }, // 運営からの返信内容
  timestamp: { type: String, default: () => new Date().toLocaleString('ja-JP') }
});
const Message = mongoose.model('Message', MessageSchema);

// --- 3. セッションとPassport設定 ---
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

// --- 4. 認証ルート ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => res.redirect('/#contact')
);

app.get('/api/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ 
      isLoggedIn: true, 
      user: req.user,
      isAdmin: req.user.email === ADMIN_EMAIL 
    });
  } else {
    res.json({ isLoggedIn: false });
  }
});

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// --- 5. ユーザー用API ---

// お問い合わせ送信（DB保存 ＋ Discord通知）
app.post('/api/contact', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });
  
  const { message } = req.body;
  
  try {
    // MongoDBに保存
    const newMessage = new Message({
      userName: req.user.name,
      email: req.user.email,
      content: message
    });
    await newMessage.save();

    // Discordへ通知
    if (process.env.DISCORD_WEBHOOK_URL) {
      await axios.post(process.env.DISCORD_WEBHOOK_URL, {
        embeds: [{
          title: "📩 新着お問い合わせ (DB保存済)",
          color: 5814783,
          fields: [
            { name: "ユーザー名", value: req.user.name, inline: true },
            { name: "メール", value: req.user.email, inline: true },
            { name: "内容", value: message }
          ],
          footer: { text: `ID: ${newMessage._id}` }
        }]
      });
    }

    res.json({ success: true, message: '送信完了！' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: '送信失敗' });
  }
});

// 自分のメッセージと運営からの返信を取得
app.get('/api/my-messages', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });
  
  try {
    // 自分のメールアドレスに一致するものを取得
    const messages = await Message.find({ email: req.user.email }).sort({ _id: -1 });
    res.json({ messages });
  } catch (err) {
    res.status(500).json({ error: '取得失敗' });
  }
});

// --- 6. 運営専用API ---

// 全メッセージ取得
app.get('/api/admin/messages', async (req, res) => {
  if (req.isAuthenticated() && req.user.email === ADMIN_EMAIL) {
    try {
      const messages = await Message.find().sort({ _id: -1 });
      res.json({ messages });
    } catch (err) {
      res.status(500).json({ error: '取得失敗' });
    }
  } else {
    res.status(403).json({ error: '閲覧権限がありません' });
  }
});

// 返信をDBに書き込む
app.post('/api/admin/reply', async (req, res) => {
  if (req.isAuthenticated() && req.user.email === ADMIN_EMAIL) {
    const { messageId, replyContent } = req.body;
    
    try {
      // メッセージIDを元に返信を更新
      await Message.findByIdAndUpdate(messageId, { reply: replyContent });
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: '返信の保存に失敗しました' });
    }
  } else {
    res.status(403).json({ error: '権限がありません' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on: http://localhost:${PORT}`));
