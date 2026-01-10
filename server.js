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
const MongoStore = require('connect-mongo'); // セッションをDBに保存
const sanitize = require('mongo-sanitize');  // NoSQLインジェクション対策

const app = express();

/** ----------------------------------------------------------------
 * MongoDB 接続設定
 * ---------------------------------------------------------------- */
const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI;

if (!MONGO_URI) {
  console.error('❌ MONGO_URIが設定されていません。環境変数を確認してください。');
}

mongoose.connect(MONGO_URI)
  .then(() => console.log('🍃 MongoDB接続完了'))
  .catch(err => console.error('❌ MongoDB接続失敗:', err));

// メッセージスキーマ（バリデーション強化）
const MessageSchema = new mongoose.Schema({
  userName: { type: String, required: true, trim: true, maxlength: 50 },
  email: { type: String, required: true, trim: true, lowercase: true },
  content: { type: String, required: true, maxlength: 5000 },
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
      imgSrc: ["'self'", "https://*.googleusercontent.com", "https:", "data:"],
      connectSrc: ["'self'", "https://discord.com"]
    }
  }
}));

app.use(express.json({ limit: '10kb' })); // 大容量データ攻撃を防止
app.use(cookieParser());
app.use(hpp()); // パラメータ汚染防止
app.use(express.static('.'));

/** ----------------------------------------------------------------
 * セッション管理（永続化：サーバー再起動でもログアウトされない）
 * ---------------------------------------------------------------- */
app.use(session({
  secret: process.env.SESSION_SECRET || 'sese_server_secure_key_2026',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: MONGO_URI,
    ttl: 14 * 24 * 60 * 60 // 14日間有効
  }),
  cookie: {
    secure: true, 
    httpOnly: true, 
    sameSite: 'lax',
    maxAge: 14 * 24 * 60 * 60 * 1000
  }
}));

/** ----------------------------------------------------------------
 * Passport (Google Auth)
 * ---------------------------------------------------------------- */
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL || "https://sesesaba.net/auth/google/callback",
    proxy: true
  },
  (accessToken, refreshToken, profile, done) => done(null, profile)
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

/** ----------------------------------------------------------------
 * 共通処理（サニタイズ等）
 * ---------------------------------------------------------------- */

const ADMIN_EMAILS = (process.env.ADMIN_EMAIL || "").split(',').map(e => e.trim());

// HTMLエスケープ（最強のXSS対策）
const escapeHtml = (str) => {
  if (typeof str !== 'string') return '';
  return str.replace(/[&<>"']/g, (m) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[m]);
};

// 荒らし対策：15分に10回まで
const contactRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: '連投制限中です。しばらく待ってから送信してください。' }
});

/** ----------------------------------------------------------------
 * API ルート
 * ---------------------------------------------------------------- */

// ログイン確認
app.get('/api/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ 
      loggedIn: true, 
      user: req.user,
      isAdmin: ADMIN_EMAILS.includes(req.user.emails[0].value)
    });
  } else {
    res.json({ loggedIn: false });
  }
});

// お問い合わせ送信（Discord通知付き）
app.post('/api/contact', contactRateLimit, async (req, res) => {
  try {
    // 1. NoSQLインジェクション対策
    const cleanBody = sanitize(req.body);
    const { userName, email, content } = cleanBody;

    if (!userName || !email || !content) {
      return res.status(400).json({ error: '入力項目が足りません' });
    }

    // 2. XSS対策（サーバー側サニタイズ）
    const newMessage = new Message({
      userName: escapeHtml(userName),
      email: escapeHtml(email),
      content: escapeHtml(content)
    });

    await newMessage.save();

    // 3. Discordへの通知送信
    if (process.env.DISCORD_WEBHOOK_URL) {
      await axios.post(process.env.DISCORD_WEBHOOK_URL, {
        embeds: [{
          title: "📩 新着お問い合わせ",
          description: "公式サイトからメッセージが届きました。",
          color: 0x3498db, // 青色
          fields: [
            { name: "👤 お名前", value: newMessage.userName, inline: true },
            { name: "📧 メールアドレス", value: newMessage.email, inline: true },
            { name: "💬 内容", value: newMessage.content }
          ],
          footer: { text: "SESE SERVER Official Admin" },
          timestamp: new Date()
        }]
      }).catch(e => console.error("Discord通知失敗:", e.message));
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '送信失敗' });
  }
});

// 自分の履歴
app.get('/api/my-messages', async (req, res) => {
  if (!req.isAuthenticated()) return res.json({ messages: [] });
  const messages = await Message.find({ email: req.user.emails[0].value });
  res.json({ messages });
});

/** ----------------------------------------------------------------
 * 管理者用 API
 * ---------------------------------------------------------------- */
const requireAdmin = (req, res, next) => {
  if (req.isAuthenticated() && ADMIN_EMAILS.includes(req.user.emails[0].value)) {
    return next();
  }
  res.status(403).json({ error: '管理者権限が必要です' });
};

app.get('/api/admin/messages', requireAdmin, async (req, res) => {
  const messages = await Message.find({});
  res.json({ messages });
});

app.post('/api/admin/reply', requireAdmin, async (req, res) => {
  const { messageId, replyContent } = sanitize(req.body);
  try {
    const updated = await Message.findByIdAndUpdate(
      messageId, 
      { reply: escapeHtml(replyContent) }, 
      { new: true }
    );
    res.json({ success: !!updated });
  } catch (err) {
    res.status(500).json({ error: '返信失敗' });
  }
});

/** ----------------------------------------------------------------
 * 認証ルート
 * ---------------------------------------------------------------- */
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }), 
  (req, res) => res.redirect('/#contact')
);

app.get('/logout', (req, res) => {
  req.logout((err) => res.redirect('/'));
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🛡️ Secure Server active on port ${PORT}`));
