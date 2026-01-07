require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const axios = require('axios');

const app = express();
app.use(express.json());
app.use(express.static('public')); // publicフォルダ内のファイルを配信

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;

// --- データの保存場所（メモリ上の配列） ---
// ※ Renderが再起動（デプロイや24時間経過）するとリセットされます
let allMessages = []; 

// セッションの設定
app.use(session({
  secret: process.env.SESSION_SECRET || 'sese_secure_key_1122',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // httpsを使用する場合はRender上でproxy: trueが必要
}));

app.use(passport.initialize());
app.use(passport.session());

// Googleログインの設定
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
 * 認証関連のルート
 * ---------------------------------------------------------------- */

// ログイン開始
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Googleからのコールバック
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/#contact'); // ログイン後にお問い合わせ場所へ戻す
  }
);

// ログアウト
app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

/** ----------------------------------------------------------------
 * APIルート（HTML側のJavaScriptから呼ばれる）
 * ---------------------------------------------------------------- */

// 1. ログインユーザー情報の取得
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

// 2. お問い合わせ送信
app.post('/api/contact', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });
  
  const newMessage = {
    id: Date.now().toString(), // 簡易ID
    userName: req.user.name,
    email: req.user.email,
    content: req.body.message,
    reply: "",
    timestamp: new Date().toLocaleString('ja-JP')
  };

  allMessages.push(newMessage);

  // Discordへの通知（Webhook設定がある場合）
  if (process.env.DISCORD_WEBHOOK_URL) {
    try {
      await axios.post(process.env.DISCORD_WEBHOOK_URL, {
        embeds: [{
          title: "📩 新着メッセージ",
          color: 5814783,
          fields: [
            { name: "ユーザー", value: req.user.name, inline: true },
            { name: "内容", value: req.body.message }
          ]
        }]
      });
    } catch (e) { console.error("Discord通知に失敗しました"); }
  }

  res.json({ success: true });
});

// 3. 自分のメッセージ（運営からの返信含む）を取得
app.get('/api/my-messages', (req, res) => {
  if (!req.isAuthenticated()) return res.json({ messages: [] });
  // 自分のメールアドレスと一致するものだけを抽出
  const mine = allMessages.filter(m => m.email === req.user.email);
  res.json({ messages: mine });
});

// 4. 【運営専用】全メッセージ取得
app.get('/api/admin/messages', (req, res) => {
  if (req.isAuthenticated() && req.user.email === ADMIN_EMAIL) {
    res.json({ messages: allMessages });
  } else {
    res.status(403).json({ error: '権限がありません' });
  }
});

// 5. 【運営専用】メッセージへの返信
app.post('/api/admin/reply', (req, res) => {
  if (req.isAuthenticated() && req.user.email === ADMIN_EMAIL) {
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

// サーバー起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server started on http://localhost:${PORT}`);
});
