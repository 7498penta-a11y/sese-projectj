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
const sanitizeHtml = require('sanitize-html'); // 【追加】XSS対策用ライブラリ

const app = express();

/** ----------------------------------------------------------------
 * MongoDB 接続設定
 * ---------------------------------------------------------------- */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('🍃 MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// メッセージの保存スキーマ定義
const MessageSchema = new mongoose.Schema({
  userName: String,
  email: String,
  content: String,
  reply: { type: String, default: "" },
  timestamp: { type: String, default: () => new Date().toLocaleString('ja-JP') }
});
const Message = mongoose.model('Message', MessageSchema);

/** ----------------------------------------------------------------
 * セキュリティ設定
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
 * レート制限
 * ---------------------------------------------------------------- */
const apiBurstLimiter = rateLimit({
  windowMs: 1000, 
  max: 5,
  message: { error: 'リクエストが速すぎます。' }
});

const contactStrictLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, 
  max: 3,
  message: { error: '5分間に3回までしか送信できません。' }
});

/** ----------------------------------------------------------------
 * セッション & パスポート設定
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
 * ミドルウェア
 * ---------------------------------------------------------------- */
function requireAdmin(req, res, next) {
  if (req.isAuthenticated() && ADMIN_EMAILS.includes(req.user.email)) return next();
  return res.status(403).json({ error: '権限がありません' });
}

/** ----------------------------------------------------------------
 * API ルート定義
 * ---------------------------------------------------------------- */

app.use('/api/', apiBurstLimiter);

// お問い合わせ送信 (MongoDB保存版)
app.post('/api/contact', contactStrictLimiter, async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });
  
  const { message } = req.body;
  if (!message || message.length > 5000) return res.status(400).json({ error: '内容が不正です' });

  // 【修正箇所】入力内容をサニタイズ（XSS対策）
  // 許可するタグを空配列に設定し、HTMLタグをすべてエスケープまたは削除します。
  const cleanMessage = sanitizeHtml(message, {
    allowedTags: [],       // HTMLタグを一切許可しない
    allowedAttributes: {}, // 属性も許可しない
    disallowedTagsMode: 'escape' // タグを消すのではなく、文字列としてエスケープする（<script> -> &lt;script&gt;）
  });

  try {
    const newMessage = new Message({
      userName: req.user.name,
      email: req.user.email,
      content: cleanMessage // サニタイズ済みの内容を保存
    });
    await newMessage.save();

    // Discord Webhook 通知
    if (process.env.DISCORD_WEBHOOK_URL) {
      await axios.post(process.env.DISCORD_WEBHOOK_URL, {
        embeds: [{
          title: "📩 新しいお問い合わせ (DB保存済)",
          color: 3447003,
          thumbnail: { url: req.user.photo },
          fields: [
            { name: "📧 Email", value: req.user.email, inline: true },
            { name: "📝 内容", value: cleanMessage } // 通知もサニタイズ済みを送る
          ]
        }]
      });
    }
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// ログインユーザー情報
app.get('/api/user', (req, res) => {
  res.json(req.isAuthenticated() ? { 
    isLoggedIn: true, 
    user: req.user, 
    isAdmin: ADMIN_EMAILS.includes(req.user.email) 
  } : { isLoggedIn: false });
});

// 自分のメッセージ履歴取得 (MongoDBから取得)
app.get('/api/my-messages', async (req, res) => {
  if (!req.isAuthenticated()) return res.json({ messages: [] });
  const messages = await Message.find({ email: req.user.email });
  res.json({ messages });
});

/** ----------------------------------------------------------------
 * 管理者専用 API
 * ---------------------------------------------------------------- */

// 全メッセージ取得
app.get('/api/admin/messages', requireAdmin, async (req, res) => {
  const messages = await Message.find({});
  res.json({ messages });
});

// お問い合わせに回答する
app.post('/api/admin/reply', requireAdmin, async (req, res) => {
  const { messageId, replyContent } = req.body;

  // 管理者の返信も念のためサニタイズ（管理者が攻撃されるのを防ぐ、または誤入力防止）
  const cleanReply = sanitizeHtml(replyContent, {
    allowedTags: [],
    allowedAttributes: {},
    disallowedTagsMode: 'escape'
  });

  try {
    const updated = await Message.findByIdAndUpdate(messageId, { reply: cleanReply }, { new: true });
    if (!updated) return res.status(404).json({ error: 'メッセージが見つかりません' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: '更新に失敗しました' });
  }
});

app.delete('/api/admin/message/:id', requireAdmin, async (req, res) => {
  try {
    const deleted = await Message.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'メッセージが見つかりません' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: '削除に失敗しました' });
  }
});

/** ----------------------------------------------------------------
 * 認証ルート
 * ---------------------------------------------------------------- */
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  res.redirect('/#contact');
});
app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🛡️ Full-Feature Server on port ${PORT}`));
