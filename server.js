// ==========================================
// SESE Server - Production Version (Render対応)
// ==========================================
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');

const app = express();

// RenderではPORT環境変数が自動で割り当てられます（通常10000番）
const PORT = process.env.PORT || 3000;

// 本番環境のURL（あなたのRenderのURLに書き換えてください）
const CALLBACK_URL = "https://sese-qing.onrender.com/auth/google/callback";

// --- 1. ミドルウェア設定 ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// セッション設定
app.use(session({
    secret: process.env.SESSION_SECRET || 'sese_default_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Render(http)ではfalse、本来はhttps化してtrueが理想
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
    proxy: true // Renderなどのプロキシ環境下で認証を正常に動かすために必要
  },
  function(accessToken, refreshToken, profile, done) {
    // ユーザー情報をセッションに渡す
    return done(null, profile);
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- 3. ルーティング ---

// Googleログイン開始
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Googleログイン コールバック
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    // ログイン成功後、お問い合わせセクションへリダイレクト
    res.redirect('/#contact');
  }
);

// ユーザー情報取得API
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

// お問い合わせ送信API
app.post('/api/contact', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'ログインが必要です' });
    }
    const { message } = req.body;
    console.log(`[お問い合わせ受信] ${req.user.displayName}: ${message}`);
    res.json({ success: true, message: '運営へ送信されました！' });
});

// ログアウト
app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        res.redirect('/');
    });
});

// すべてのリクエストに対して index.html を返す (SPA対応)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- 4. 起動 ---
app.listen(PORT, () => {
    console.log(`--------------------------------------------------`);
    console.log(`✅ SESE Server is running on Port: ${PORT}`);
    console.log(`🔗 URL: ${CALLBACK_URL}`);
    console.log(`--------------------------------------------------`);
});
