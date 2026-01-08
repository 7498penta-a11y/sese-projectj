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

const app = express();

/** ----------------------------------------------------------------
 * セキュリティ設定 1: インフラ・プロキシ設定
 * ---------------------------------------------------------------- */
// Renderなどのリバースプロキシ環境でIP制限やSecure Cookieを正しく動作させるために必要
app.set('trust proxy', 1);

/** ----------------------------------------------------------------
 * セキュリティ設定 2: HTTPヘッダー (プロフィール画像表示対応版)
 * ---------------------------------------------------------------- */
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // Googleの画像ドメインを許可し、アイコンが表示されるようにする
      imgSrc: ["'self'", "data:", "https://*.googleusercontent.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      upgradeInsecureRequests: null,
    },
  },
  // 外部ドメインの画像読み込みをブラウザがブロックするのを防ぐ
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(hpp()); // パラメータ汚染攻撃を防止
app.use(express.json({ limit: '10kb' })); // 巨大なJSONによるDoS攻撃を防止
app.use(cookieParser());
app.use(express.static('public'));

/** ----------------------------------------------------------------
 * セキュリティ設定 3: 二段階レート制限 (キツキツ設定)
 * ---------------------------------------------------------------- */

// 全API共通：1秒間に3回までの短期制限（連打・スクリプト対策）
const apiBurstLimiter = rateLimit({
  windowMs: 1000, 
  max: 3,
  message: { error: 'リクエストが速すぎます。' },
  standardHeaders: true,
  legacyHeaders: false,
});

// お問い合わせ専用：5分間に2回までの厳格制限（スパム・嫌がらせ対策）
const contactStrictLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, 
  max: 2,
  message: { error: '5分間に2回までしか送信できません。' },
  standardHeaders: true,
  legacyHeaders: false,
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
    httpOnly: true, // XSS対策
    secure: true,   // HTTPS必須
    sameSite: 'lax', // CSRF対策
    maxAge: 24 * 60 * 60 * 1000 
  }
}));

app.use(passport.initialize());
app.use(passport.session());

const ADMIN_EMAILS = (process.env.ADMIN_EMAIL || "").split(',').map(email => email.trim());
let allMessages = []; 

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL || "/auth/google/callback",
    proxy: true
  },
  (accessToken, refreshToken, profile, done) => {
    if (!profile.emails || !profile.emails[0]) return done(new Error("Email not found"), null);
    
    // photo を含めて保存することでフロントエンドに渡せるようにする
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
 * ヘルパー & 権限チェック
 * ---------------------------------------------------------------- */
function validateMessage(msg) {
  if (!msg || typeof msg !== 'string') return false;
  const trimmed = msg.trim();
  return trimmed.length > 0 && trimmed.length <= 5000;
}

function requireAdmin(req, res, next) {
  if (req.isAuthenticated() && ADMIN_EMAILS.includes(req.user.email)) return next();
  return res.status(403).json({ error: '権限がありません' });
}

/** ----------------------------------------------------------------
 * ルート定義
 * ---------------------------------------------------------------- */

// すべてのAPIリクエストを秒間制限で保護
app.use('/api/', apiBurstLimiter);

// お問い合わせ送信 (レート制限 -> 認証 -> バリデーション -> 処理 の順)
app.post('/api/contact', contactStrictLimiter, async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });

  if (!validateMessage(req.body.message)) {
    return res.status(400).json({ error: '入力内容が不正です' });
  }

  const newMessage = {
    id: Date.now().toString(),
    userName: req.user.name,
    email: req.user.email,
    content: req.body.message,
    reply: "",
    timestamp: new Date().toLocaleString('ja-JP')
  };

  allMessages.push(newMessage);
  if (allMessages.length > 1000) allMessages.shift(); // メモリ負荷軽減

  // Discord送信 (制限を通過したリクエストのみ到達)
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

// ユーザー情報取得
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

// 自分のメッセージ取得
app.get('/api/my-messages', (req, res) => {
  if (!req.isAuthenticated()) return res.json({ messages: [] });
  res.json({ messages: allMessages.filter(m => m.email === req.user.email) });
});

// 管理者用API
app.get('/api/admin/messages', requireAdmin, (req, res) => {
  res.json({ messages: allMessages });
});

app.post('/api/admin/reply', requireAdmin, (req, res) => {
  const { messageId, replyContent } = req.body;
  if (!validateMessage(replyContent)) return res.status(400).json({ error: '回答内容不正' });
  const msg = allMessages.find(m => m.id === messageId);
  if (msg) {
    msg.reply = replyContent;
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

// 認証ルート
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => res.redirect('/#contact'));
app.get('/logout', (req, res) => req.logout(() => res.redirect('/')));

/** ----------------------------------------------------------------
 * サーバー起動 & スロー攻撃対策
 * ---------------------------------------------------------------- */
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => console.log(`🛡️ Strict Security Server on port ${PORT}`));

server.headersTimeout = 5000; // 5秒以内にヘッダーを送らない接続を切断
server.requestTimeout = 10000; // 10秒以内に完了しないリクエストを切断
