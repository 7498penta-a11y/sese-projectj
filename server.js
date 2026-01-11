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
      scriptSrc: ["'self' Hex", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "https://*.googleusercontent.com", "https:", "data:"],
      connectSrc: ["'self'", "https://discord.com"],
    },
  },
}));
app.use(hpp());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 静的ファイルの提供（icon.pngなどがここに含まれます）
app.use(express.static('public'));

/** ----------------------------------------------------------------
 * セッション & Passport (Google OAuth)
 * ---------------------------------------------------------------- */
app.use(session({
  secret: process.env.SESSION_SECRET || 'sese-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

/** ----------------------------------------------------------------
 * ミドルウェア
 * ---------------------------------------------------------------- */
// 管理者チェック
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',');
const requireAdmin = (req, res, next) => {
  if (req.isAuthenticated() && ADMIN_EMAILS.includes(req.user.emails[0].value)) {
    return next();
  }
  res.status(403).json({ error: 'Forbidden' });
};

/** ----------------------------------------------------------------
 * 一般 API
 * ---------------------------------------------------------------- */

// ログイン状態確認
app.get('/api/user', (req, res) => {
  if (req.isAuthenticated()) {
    const isAdmin = ADMIN_EMAILS.includes(req.user.emails[0].value);
    res.json({ loggedIn: true, user: req.user, isAdmin });
  } else {
    res.json({ loggedIn: false });
  }
});

// お問い合わせ送信
app.post('/api/contact', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Login required' });
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Content is empty' });

  try {
    const newMessage = new Message({
      userName: req.user.displayName,
      email: req.user.emails[0].value,
      content: content
    });
    await newMessage.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: '保存に失敗しました' });
  }
});

// 自分のメッセージ履歴取得
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
  try {
    const updated = await Message.findByIdAndUpdate(messageId, { reply: replyContent }, { new: true });
    if (!updated) return res.status(404).json({ error: 'メッセージが見つかりません' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: '更新に失敗しました' });
  }
});

// ★追加箇所: 質問を終了してデータを削除する
app.delete('/api/admin/messages/:id', requireAdmin, async (req, res) => {
  try {
    const deleted = await Message.findByIdAndDelete(req.params.id);
    if (!deleted) {
      return res.status(404).json({ error: 'メッセージが見つかりません' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Delete Error:', err);
    res.status(500).json({ error: '削除中にエラーが発生しました' });
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

/** ----------------------------------------------------------------
 * サーバー起動
 * ---------------------------------------------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
