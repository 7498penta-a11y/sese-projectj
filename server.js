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

// セッション設定
app.use(session({
  secret: process.env.SESSION_SECRET || 'sese_secure_key_1122',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // HTTP通信（Renderの無料プラン等）の場合はfalse
}));

app.use(passport.initialize());
app.use(passport.session());

// Googleログイン設定
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    // ここを環境変数にすることで、Render上のURLに合わせます
    callbackURL: process.env.CALLBACK_URL || "/auth/google/callback",
    proxy: true // Renderのプロキシ経由の通信を許可
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

app.get('/api/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ isLoggedIn: true, user: req.user });
  } else {
    res.json({ isLoggedIn: false });
  }
});

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

app.post('/api/contact', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });
  const { message } = req.body;
  try {
    await axios.post(process.env.DISCORD_WEBHOOK_URL, {
      embeds: [{
        title: "📩 新着お問い合わせ",
        color: 5814783,
        fields: [
          { name: "ユーザー名", value: req.user.name, inline: true },
          { name: "メール", value: req.user.email, inline: true },
          { name: "内容", value: message }
        ],
        timestamp: new Date()
      }]
    });
    res.json({ success: true, message: '送信完了！' });
  } catch (err) {
    res.status(500).json({ success: false, error: '送信失敗' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server: http://localhost:${PORT}`));
