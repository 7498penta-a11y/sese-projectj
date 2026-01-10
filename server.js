require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const axios = require('axios');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const hpp = require('hpp');
const mongoose = require('mongoose');

const app = express();

/** ----------------------------------------------------------------
 * データベース設定 (MongoDB Atlas)
 * ---------------------------------------------------------------- */
// RenderのEnvironment設定から取得。後ろのデフォルト値を消してエラーを防ぐ
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('❌ エラー: MONGODB_URI が設定されていません。RenderのEnvironment設定を確認してください。');
}

mongoose.connect(MONGODB_URI)
  .then(() => console.log('🍃 MongoDB Connected'))
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
  });

// メッセージの保存形式（スキーマ）を定義
const messageSchema = new mongoose.Schema({
  userName: String,
  email: String,
  content: String,
  reply: { type: String, default: "" },
  photo: String,
  timestamp: { type: String, default: () => new Date().toLocaleString('ja-JP') }
});

const Message = mongoose.model('Message', messageSchema);

/** ----------------------------------------------------------------
 * セキュリティ・ミドルウェア設定
 * ---------------------------------------------------------------- */
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://*.googleusercontent.com", "https:"],
      connectSrc: ["'self'", "https://discord.com"],
    },
  },
}));
app.use(hpp());
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static('public'));

/** ----------------------------------------------------------------
 * セッション & パスポート
 * ---------------------------------------------------------------- */
app.use(session({
  secret: process.env.SESSION_SECRET || 'sese_secure_key_1122',
  resave: false,
  saveUninitialized: false,
  name: 'sessionId',
  cookie: { 
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000 
  }
}));

app.use(passport.initialize());
app.use(passport.session());

const ADMIN_EMAILS = (process.env.ADMIN_EMAIL || "").split(',').map(email => email.trim());

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL || "/auth/google/callback",
    proxy: true
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, {
      name: profile.displayName,
      email: profile.emails[0].value,
      photo: profile.photos && profile.photos[0] ? profile.photos[0].value : ""
    });
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

/** ----------------------------------------------------------------
 * 補助関数・管理者チェック
 * ---------------------------------------------------------------- */
function requireAdmin(req, res, next) {
  if (req.isAuthenticated() && ADMIN_EMAILS.includes(req.user.email)) return next();
  return res.status(403).json({ error: '権限がありません' });
}

/** ----------------------------------------------------------------
 * API ルート
 * ---------------------------------------------------------------- */

// お問い合わせ送信
app.post('/api/contact', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });
  
  const content = req.body.message;
  if (!content || content.length > 5000) return res.status(400).json({ error: '内容が不正です' });

  try {
    const newMessage = new Message({
      userName: req.user.name,
      email: req.user.email,
      content: content,
      photo: req.user.photo
    });
    
    await newMessage.save();

    // Discord Webhook通知
    if (process.env.DISCORD_WEBHOOK_URL) {
      try {
        await axios.post(process.env.DISCORD_WEBHOOK_URL, {
          embeds: [{
            title: "📩 新しいお問い合わせ",
            color: 3447003,
            fields: [
              { name: "👤 名前", value: req.user.name, inline: true },
              { name: "📧 Email", value: req.user.email, inline: true },
              { name: "📝 内容", value: content }
            ]
          }]
        });
      } catch (e) { console.error("Discord通知失敗"); }
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: '保存失敗' });
  }
});

// ログイン状況確認
app.get('/api/user', (req, res) => {
  res.json(req.isAuthenticated() ? { 
    isLoggedIn: true, 
    user: req.user, 
    isAdmin: ADMIN_EMAILS.includes(req.user.email) 
  } : { isLoggedIn: false });
});

// 自分の履歴取得
app.get('/api/my-messages', async (req, res) => {
  if (!req.isAuthenticated()) return res.json({ messages: [] });
  try {
    const messages = await Message.find({ email: req.user.email }).sort({ _id: -1 });
    res.json({ messages });
  } catch (e) { res.status(500).send('取得失敗'); }
});

// 管理者：全取得
app.get('/api/admin/messages', requireAdmin, async (req, res) => {
  try {
    const messages = await Message.find().sort({ _id: -1 });
    res.json({ messages });
  } catch (e) { res.status(500).send('取得失敗'); }
});

// 管理者：返信保存
app.post('/api/admin/reply', requireAdmin, async (req, res) => {
  const { messageId, replyContent } = req.body;
  try {
    await Message.findByIdAndUpdate(messageId, { reply: replyContent });
    res.json({ success: true });
  } catch (e) { res.status(500).send('返信失敗'); }
});

/** ----------------------------------------------------------------
 * 認証ルート
 * ---------------------------------------------------------------- */
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => res.redirect('/#contact'));
app.get('/logout', (req, res) => req.logout(() => res.redirect('/')));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🛡️ Server running on port ${PORT}`));
