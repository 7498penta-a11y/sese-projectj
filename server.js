require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const axios = require('axios');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const hpp = require('hpp'); // HTTPパラメータ汚染対策

const app = express();

/** ----------------------------------------------------------------
 * セキュリティ設定 1: インフラ・プロキシ設定
 * ---------------------------------------------------------------- */
app.set('trust proxy', 1);

/** ----------------------------------------------------------------
 * セキュリティ設定 2: HTTPヘッダー・防御ミドルウェア
 * ---------------------------------------------------------------- */
app.use(helmet({
  contentSecurityPolicy: false, 
}));
app.use(hpp()); // 同じ名前のパラメータを複数送る攻撃を防止

/** ----------------------------------------------------------------
 * セキュリティ設定 3: レート制限 (キツキツ設定)
 * ---------------------------------------------------------------- */

// 全API共通：1秒間に3回までの短期制限（バースト・連打対策）
const apiBurstLimiter = rateLimit({
  windowMs: 1000, 
  max: 3,
  message: { error: 'リクエストが速すぎます。' },
  standardHeaders: true,
  legacyHeaders: false,
});

// お問い合わせ専用：5分間に2回までの厳格制限（スパム・連続投稿対策）
const contactStrictLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, 
  max: 2,
  message: { error: '5分間に2回までしか送信できません。' },
  standardHeaders: true,
  legacyHeaders: false,
});

/** ----------------------------------------------------------------
 * セキュリティ設定 4: ボディサイズ制限 & セッション
 * ---------------------------------------------------------------- */
app.use(express.json({ limit: '10kb' })); // 巨大なJSONによるメモリ攻撃を防止
app.use(cookieParser());
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'sese_secure_key_1122',
  resave: false,
  saveUninitialized: false,
  name: 'sessionId',
  cookie: { 
    httpOnly: true,
    secure: true, 
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000 
  }
}));

app.use(passport.initialize());
app.use(passport.session());

/** ----------------------------------------------------------------
 * 認証・データ管理
 * ---------------------------------------------------------------- */
const ADMIN_EMAILS = (process.env.ADMIN_EMAIL || "").split(',').map(email => email.trim());

// 注意：本番ではデータベース（MongoDB/PostgreSQL等）への変更を強く推奨します
let allMessages = []; 

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL || "/auth/google/callback",
    proxy: true
  },
  (accessToken, refreshToken, profile, done) => {
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

/** ----------------------------------------------------------------
 * ヘルパー・ミドルウェア
 * ---------------------------------------------------------------- */
function validateMessage(msg) {
  if (!msg || typeof msg !== 'string') return false;
  const trimmed = msg.trim();
  // 空文字または5000文字超えを拒否
  if (trimmed.length === 0 || trimmed.length > 5000) return false;
  return true;
}

function requireAdmin(req, res, next) {
  if (req.isAuthenticated() && ADMIN_EMAILS.includes(req.user.email)) {
    return next();
  }
  return res.status(403).json({ error: '権限がありません' });
}

/** ----------------------------------------------------------------
 * ルート定義
 * ---------------------------------------------------------------- */

// すべてのAPIルートに秒間制限を適用
app.use('/api/', apiBurstLimiter);

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => res.redirect('/#contact')
);

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// 1. ユーザー情報取得
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

// 2. お問い合わせ送信（二段階の制限適用）
app.post('/api/contact', contactStrictLimiter, async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });

  // 簡易CSRF/Originチェック
  const origin = req.get('origin');
  if (origin && !origin.includes('onrender.com') && !origin.includes('localhost')) {
     return res.status(403).json({ error: '不正なリクエスト元です' });
  }

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

  // メモリ負荷対策：配列が大きくなりすぎないよう制限（DB未実装時のみの暫定処置）
  if (allMessages.length > 1000) allMessages.shift(); 
  allMessages.push(newMessage);

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

// 4. 管理者専用：全取得
app.get('/api/admin/messages', requireAdmin, (req, res) => {
  res.json({ messages: allMessages });
});

// 5. 管理者専用：回答送信
app.post('/api/admin/reply', requireAdmin, (req, res) => {
  const { messageId, replyContent } = req.body;
  if (!validateMessage(replyContent)) return res.status(400).json({ error: '内容不正' });

  const msg = allMessages.find(m => m.id === messageId);
  if (msg) {
    msg.reply = replyContent;
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

/** ----------------------------------------------------------------
 * サーバー起動とタイムアウト対策 (DoS/Slowloris)
 * ---------------------------------------------------------------- */
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`🛡️ Extremely Secure Server running on port ${PORT}`);
});

// コネクションのタイムアウトを厳しく設定
server.headersTimeout = 5000; // ヘッダー読み取り制限 5秒
server.requestTimeout = 10000; // リクエスト全体制限 10秒
