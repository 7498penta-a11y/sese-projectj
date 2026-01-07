require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const axios = require('axios');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static('public')); // HTMLファイルを入れるフォルダ

// セッションの設定
app.use(session({
  secret: 'sese_secret_key', // 適当な長い文字列に変更してください
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// Googleログインの設定
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
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

// 1. Googleログイン実行
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// 2. Googleからのコールバック
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => res.redirect('/#contact')
);

// 3. ログイン状態の確認API
app.get('/api/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ isLoggedIn: true, user: req.user });
  } else {
    res.json({ isLoggedIn: false });
  }
});

// 4. ログアウト
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// 5. お問い合わせ送信API (Discord Webhookへ)
app.post('/api/contact', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });

  const { message } = req.body;
  const user = req.user;

  try {
    await axios.post(process.env.DISCORD_WEBHOOK_URL, {
      embeds: [{
        title: "📩 新着お問い合わせ",
        color: 5814783,
        fields: [
          { name: "ユーザー名", value: user.name, inline: true },
          { name: "メールアドレス", value: user.email, inline: true },
          { name: "内容", value: message }
        ],
        timestamp: new Date()
      }]
    });
    res.json({ success: true, message: '運営に送信されました！' });
  } catch (err) {
    res.status(500).json({ success: false, error: '送信失敗' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on http://localhost:${PORT}`));
