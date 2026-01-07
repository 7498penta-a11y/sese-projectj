// ==========================================
// SESE Server - Discord Webhook & Google Login
// ==========================================
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const https = require('https'); // Discordへの送信に使用

const app = express();
const PORT = process.env.PORT || 3000;

// 本番環境のURL（RenderのURL）
const CALLBACK_URL = "https://sese-qing.onrender.com/auth/google/callback";

// --- 1. ミドルウェア設定 ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'sese_default_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, 
        maxAge: 24 * 60 * 60 * 1000 
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// --- 2. Google OAuth設定 ---
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: CALLBACK_URL,
    proxy: true 
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- 3. ルーティング ---

// ログイン開始
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Googleコールバック
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/#contact');
  }
);

// ユーザー情報取得
app.get('/api/user', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({
            isLoggedIn: true,
            user: {
                name: req.user.displayName,
                email: req.user.emails[0].value,
                photo: req.user.photos[0].value
            }
        });
    } else {
        res.json({ isLoggedIn: false });
    }
});

// ★ お問い合わせ送信 (Discordへ飛ばす処理)
app.post('/api/contact', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'ログインが必要です' });
    }

    const { message } = req.body;
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL;

    if (!webhookUrl) {
        console.error("Discord Webhook URLが設定されていません");
        return res.status(500).json({ error: 'サーバー設定エラー' });
    }

    // Discordに送る見た目の設定
    const discordData = JSON.stringify({
        embeds: [{
            title: "📩 新しいお問い合わせ",
            color: 5814783, 
            fields: [
                { name: "送信者", value: req.user.displayName, inline: true },
                { name: "メールアドレス", value: req.user.emails[0].value, inline: true },
                { name: "メッセージ内容", value: message }
            ],
            thumbnail: { url: req.user.photos[0].value },
            timestamp: new Date()
        }]
    });

    // Discord Webhookへ送信
    const url = new URL(webhookUrl);
    const options = {
        hostname: url.hostname,
        path: url.pathname,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(discordData)
        }
    };

    const discordReq = https.request(options, (discordRes) => {
        console.log(`Discord status: ${discordRes.statusCode}`);
    });

    discordReq.on('error', (e) => {
        console.error(`Discord送信エラー: ${e.message}`);
    });

    discordReq.write(discordData);
    discordReq.end();

    res.json({ success: true, message: '運営へ送信されました（Discord通知済み）' });
});

// ログアウト
app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        res.redirect('/');
    });
});

// SPA対応
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// サーバー起動
app.listen(PORT, () => {
    console.log(`✅ SESE Server running on port ${PORT}`);
});
