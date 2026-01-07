require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const axios = require('axios');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// --- 設定値の準備 ---
const ADMIN_EMAIL = process.env.ADMIN_EMAIL; // .envから運営者のアドレスを取得

// メッセージ保存用（本番環境ではDBを推奨しますが、まずは動作確認用にメモリ保存します）
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

// Googleログイン設定
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

// --- ルーティング ---

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => res.redirect('/#contact')
);

// ユーザー情報を返すAPI（運営者かどうかのフラグを追加）
app.get('/api/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ 
      isLoggedIn: true, 
      user: req.user,
      isAdmin: req.user.email === ADMIN_EMAIL // ここで判定
    });
  } else {
    res.json({ isLoggedIn: false });
  }
});

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// お問い合わせ送信API
app.post('/api/contact', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });
  
  const { message } = req.body;
  
  // メッセージオブジェクトの作成
  const newMessage = {
    id: Date.now(),
    userName: req.user.name,
    email: req.user.email,
    content: message,
    timestamp: new Date().toLocaleString('ja-JP')
  };

  try {
    // 1. サーバーのメモリに保存（運営者が後で見れるようにする）
    allMessages.push(newMessage);

    // 2. Discordへ通知
    await axios.post(process.env.DISCORD_WEBHOOK_URL, {
      embeds: [{
        title: "📩 新着お問い合わせ",
        color: 5814783,
        fields: [
          { name: "ユーザー名", value: newMessage.userName, inline: true },
          { name: "メール", value: newMessage.email, inline: true },
          { name: "内容", value: newMessage.content }
        ],
        footer: { text: `送信日時: ${newMessage.timestamp}` }
      }]
    });

    res.json({ success: true, message: '送信完了！' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: '送信失敗' });
  }
});

// --- 運営専用API ---

// 全メッセージ取得
app.get('/api/admin/messages', (req, res) => {
  if (req.isAuthenticated() && req.user.email === ADMIN_EMAIL) {
    res.json({ messages: allMessages });
  } else {
    res.status(403).json({ error: '閲覧権限がありません' });
  }
});

// 運営からの返信（コンソールに出力する例）
app.post('/api/admin/reply', (req, res) => {
  if (req.isAuthenticated() && req.user.email === ADMIN_EMAIL) {
    const { replyTo, content } = req.body;
    console.log(`【返信実行】宛先: ${replyTo}, 内容: ${content}`);
    // ここにメール送信ロジックなどを追加可能
    res.json({ success: true });
  } else {
    res.status(403).json({ error: '権限がありません' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server: http://localhost:${PORT}`));
