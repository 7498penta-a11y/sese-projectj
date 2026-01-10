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
const mongoose = require('mongoose'); // 追加

const app = express();

/** ----------------------------------------------------------------
 * データベース設定 (MongoDB)
 * ---------------------------------------------------------------- */
// 環境変数 MONGODB_URI が設定されていない場合はローカルに繋ぎに行く設定
const MONGODB_URI = process.env.MONGODB_URI;


mongoose.connect(MONGODB_URI)
  .then(() => console.log('🍃 MongoDB Connected'))
  .catch(err => console.error('MongoDB connection error:', err));

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
 * レート制限 (連投対策)
 * ---------------------------------------------------------------- */
const apiBurstLimiter = rateLimit({
  windowMs: 1000, 
  max: 3,
  message: { error: 'リクエストが速すぎます。' }
});

const contactStrictLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, 
  max: 2,
  message: { error: '5分間に2回までしか送信できません。' }
});

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
function validateMessage(msg) {
  if (!msg || typeof msg !== 'string') return false;
  return msg.trim().length > 0 && msg.trim().length <= 5000;
}

function requireAdmin(req, res, next) {
  if (req.isAuthenticated() && ADMIN_EMAILS.includes(req.user.email)) return next();
  return res.status(403).json({ error: '権限がありません' });
}

/** ----------------------------------------------------------------
 * API ルート
 * ---------------------------------------------------------------- */

// 全APIにバースト制限を適用
app.use('/api/', apiBurstLimiter);

// お問い合わせ送信（MongoDBへ保存）
app.post('/api/contact', contactStrictLimiter, async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });

  if (!validateMessage(req.body.message)) {
    return res.status(400).json({ error: '内容が不正です' });
  }

  try {
    const newMessage = new Message({
      userName: req.user.name,
      email: req.user.email,
      content: req.body.message,
      photo: req.user.photo
    });
    
    await newMessage.save(); // ここでDBに保存される

    // Discord Webhook通知
    if (process.env.DISCORD_WEBHOOK_URL) {
      try {
        await axios.post(process.env.DISCORD_WEBHOOK_URL, {
          embeds: [{
            title: "📩 新しいお問い合わせ",
            color: 3447003,
            thumbnail: { url: req.user.photo },
            fields: [
              { name: "👤 名前", value: req.user.name, inline: true },
              { name: "📧 Email", value: req.user.email, inline: true },
              { name: "📝 内容", value: req.body.message }
            ]
          }]
        });
      } catch (e) { console.error("Discord通知失敗"); }
    }

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: '保存に失敗しました' });
  }
});

// ログイン中のユーザー情報
app.get('/api/user', (req, res) => {
  res.json(req.isAuthenticated() ? { 
    isLoggedIn: true, 
    user: req.user, 
    isAdmin: ADMIN_EMAILS.includes(req.user.email) 
  } : { isLoggedIn: false });
});

// 自分の履歴取得（MongoDBから検索）
app.get('/api/my-messages', async (req, res) => {
  if (!req.isAuthenticated()) return res.json({ messages: [] });
  try {
    const messages = await Message.find({ email: req.user.email }).sort({ _id: -1 });
    res.json({ messages });
  } catch (e) {
    res.status(500).json({ error: '取得失敗' });
  }
});

// 管理者：全件取得
app.get('/api/admin/messages', requireAdmin, async (req, res) => {
  try {
    const messages = await Message.find().sort({ _id: -1 });
    res.json({ messages });
  } catch (e) {
    res.status(500).json({ error: '取得失敗' });
  }
});

// 管理者：返信の保存
app.post('/api/admin/reply', requireAdmin, async (req, res) => {
  const { messageId, replyContent } = req.body;
  try {
    await Message.findByIdAndUpdate(messageId, { reply: replyContent });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: '返信失敗' });
  }
});

/** ----------------------------------------------------------------
 * 認証ルート
 * ---------------------------------------------------------------- */
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => res.redirect('/#contact'));
app.get('/logout', (req, res) => req.logout(() => res.redirect('/')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🛡️ Server running on port ${PORT}`));
