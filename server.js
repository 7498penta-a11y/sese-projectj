require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const axios = require('axios');
const helmet = require('helmet'); // セキュリティヘッダー設定
const rateLimit = require('express-rate-limit'); // 連投防止
const cookieParser = require('cookie-parser'); // Cookie解析

const app = express();

// --- セキュリティ設定 1: Renderなどのプロキシ環境での信頼設定 ---
// これがないとレート制限やSecure Cookieが正しく動作しません
app.set('trust proxy', 1);

// --- セキュリティ設定 2: HTTPヘッダーの強化 (Helmet) ---
app.use(helmet({
  contentSecurityPolicy: false, // フロントエンドのCSP設定と競合しないよう一旦オフ（必要に応じて調整）
}));

// --- セキュリティ設定 3: 基本ミドルウェア ---
app.use(express.json({ limit: '10kb' })); // ボディサイズ制限（DoS対策）
app.use(cookieParser());
app.use(express.static('public'));

// 管理者メールアドレスリスト
const ADMIN_EMAILS = (process.env.ADMIN_EMAIL || "").split(',').map(email => email.trim());

// データ保存場所（メモリ）
let allMessages = []; 

// --- セキュリティ設定 4: セキュアなセッション ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'sese_secure_key_1122',
  resave: false,
  saveUninitialized: false,
  name: 'sessionId', // デフォルトの connect.sid から変更（推測防止）
  cookie: { 
    httpOnly: true, // JavaScriptからのアクセス禁止 (XSS対策)
    secure: true,   // HTTPS必須 (Renderなどの本番環境用)
    sameSite: 'lax', // CSRF対策
    maxAge: 24 * 60 * 60 * 1000 // 24時間
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// --- セキュリティ設定 5: レート制限 (連投防止) ---
const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15分間
  max: 5, // 1IPあたり5回まで
  message: { error: '送信回数が多すぎます。しばらく待ってからお試しください。' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Google OAuth設定
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL || "/auth/google/callback",
    proxy: true
  },
  (accessToken, refreshToken, profile, done) => {
    // メールアドレスが取得できない場合はログインさせない
    if (!profile.emails || !profile.emails[0]) return done(new Error("Email not found"), null);
    return done(null, {
      name: profile.displayName,
      photo: profile.photos && profile.photos[0] ? profile.photos[0].value : "",
      email: profile.emails[0].value
    });
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- ヘルパー関数: 入力バリデーション (サーバー側) ---
function validateMessage(msg) {
  if (!msg || typeof msg !== 'string') return false;
  const trimmed = msg.trim();
  if (trimmed.length === 0 || trimmed.length > 5000) return false;
  // 簡易的な危険文字チェック（必要に応じて強化）
  if (/<script|javascript:/i.test(trimmed)) return false;
  return true;
}

// --- ミドルウェア: 管理者権限チェック ---
function requireAdmin(req, res, next) {
  if (req.isAuthenticated() && ADMIN_EMAILS.includes(req.user.email)) {
    return next();
  }
  return res.status(403).json({ error: '権限がありません' });
}

/** ----------------------------------------------------------------
 * ルート定義
 * ---------------------------------------------------------------- */

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => res.redirect('/#contact')
);

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// 1. ユーザー情報
app.get('/api/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ 
      isLoggedIn: true, 
      user: req.user, 
      isAdmin: ADMIN_EMAILS.includes(req.user.email) 
    });
  } else {
    res.json({ isLoggedIn: false });
  }
});

// 2. お問い合わせ送信 (レート制限 + バリデーション適用)
app.post('/api/contact', contactLimiter, async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });
  
  // CSRF対策: Origin/Refererチェック (簡易版だが効果的)
  const origin = req.get('origin');
  const referer = req.get('referer');
  // Renderのドメイン、もしくはローカルホストからのリクエストのみ許可
  if ((origin && !origin.includes('onrender.com') && !origin.includes('localhost')) ||
      (referer && !referer.includes('onrender.com') && !referer.includes('localhost'))) {
     return res.status(403).json({ error: '不正なリクエスト元です' });
  }

  // 入力検証
  if (!validateMessage(req.body.message)) {
    return res.status(400).json({ error: '入力内容が不正、または長すぎます' });
  }

  const newMessage = {
    id: Date.now().toString(),
    userName: req.user.name,
    email: req.user.email,
    content: req.body.message, // 表示時はフロントエンドでエスケープされるが、念のため
    reply: "",
    timestamp: new Date().toLocaleString('ja-JP')
  };

  allMessages.push(newMessage);

  // Discord通知
  if (process.env.DISCORD_WEBHOOK_URL) {
    try {
      await axios.post(process.env.DISCORD_WEBHOOK_URL, {
        embeds: [{
          title: "📩 新しいお問い合わせ",
          color: 3447003,
          fields: [
            { name: "👤 ユーザー", value: req.user.name, inline: true },
            { name: "📧 Email", value: req.user.email, inline: true },
            { name: "📝 内容", value: req.body.message }
          ],
          footer: { text: `Time: ${newMessage.timestamp}` }
        }]
      });
    } catch (e) { console.error("Discord Error"); }
  }

  res.json({ success: true });
});

// 3. 自分のメッセージ取得
app.get('/api/my-messages', (req, res) => {
  if (!req.isAuthenticated()) return res.json({ messages: [] });
  const mine = allMessages.filter(m => m.email === req.user.email);
  res.json({ messages: mine });
});

// 4. 【運営専用】全メッセージ取得 (厳格な権限チェック)
app.get('/api/admin/messages', requireAdmin, (req, res) => {
  res.json({ messages: allMessages });
});

// 5. 【運営専用】回答送信 (厳格な権限チェック)
app.post('/api/admin/reply', requireAdmin, (req, res) => {
  const { messageId, replyContent } = req.body;
  if (!validateMessage(replyContent)) {
    return res.status(400).json({ error: '回答内容が不正です' });
  }
  
  const msg = allMessages.find(m => m.id === messageId);
  if (msg) {
    msg.reply = replyContent;
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Message not found' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🛡️ Secure Server running on port ${PORT}`));
