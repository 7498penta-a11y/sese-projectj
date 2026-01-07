require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const axios = require('axios');

const app = express();
app.use(express.json());
app.use(express.static('public'));

/**
 * 管理者設定：複数のメールアドレスに対応
 * Renderの環境変数 ADMIN_EMAIL に "mail1@gmail.com,mail2@gmail.com" と入力してください
 */
const ADMIN_EMAILS = (process.env.ADMIN_EMAIL || "").split(',').map(email => email.trim());

// --- データの保存場所（メモリ上の配列） ---
// ⚠️ Renderの再起動（デプロイや無料プランの休止）でリセットされます
let allMessages = []; 

// セッション設定
app.use(session({
  secret: process.env.SESSION_SECRET || 'sese_secure_key_1122',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());

// Google OAuth 設定
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

/** ----------------------------------------------------------------
 * 認証ルート
 * ---------------------------------------------------------------- */

// ログイン開始
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Googleからの戻り先
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/#contact'); 
  }
);

// ログアウト
app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

/** ----------------------------------------------------------------
 * APIルート
 * ---------------------------------------------------------------- */

// 1. ユーザー情報（ログイン中か、管理者か）
app.get('/api/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ 
      isLoggedIn: true, 
      user: req.user, 
      isAdmin: ADMIN_EMAILS.includes(req.user.email) // 複数管理者の判定
    });
  } else {
    res.json({ isLoggedIn: false });
  }
});

// 2. お問い合わせ送信
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

  // Discord Webhook 通知
  if (process.env.DISCORD_WEBHOOK_URL) {
    try {
      await axios.post(process.env.DISCORD_WEBHOOK_URL, {
        embeds: [{
          title: "📩 新着メッセージ (メモリ保存)",
          color: 5814783,
          fields: [
            { name: "ユーザー", value: req.user.name, inline: true },
            { name: "メール", value: req.user.email, inline: true },
            { name: "内容", value: req.body.message }
          ]
        }]
      });
    } catch (e) { console.error("Discord通知失敗"); }
  }

  res.json({ success: true });
});

// 3. ユーザー自身のメッセージ（回答を含む）取得
app.get('/api/my-messages', (req, res) => {
  if (!req.isAuthenticated()) return res.json({ messages: [] });
  const mine = allMessages.filter(m => m.email === req.user.email);
  res.json({ messages: mine });
});

// 4. 【運営専用】全メッセージ取得
app.get('/api/admin/messages', (req, res) => {
  if (req.isAuthenticated() && ADMIN_EMAILS.includes(req.user.email)) {
    res.json({ messages: allMessages });
  } else {
    res.status(403).json({ error: '権限がありません' });
  }
});

// 5. 【運営専用】メッセージへの回答
app.post('/api/admin/reply', (req, res) => {
  if (req.isAuthenticated() && ADMIN_EMAILS.includes(req.user.email)) {
    const { messageId, replyContent } = req.body;
    const msg = allMessages.find(m => m.id === messageId);
    if (msg) {
      msg.reply = replyContent;
      res.json({ success: true });
    } else {
      res.status(404).json({ error: 'メッセージが見つかりません' });
    }
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server started on port ${PORT}`));
