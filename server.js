// ==========================================
// SESE Server - Backend Logic
// ==========================================
require('dotenv').config(); // .envファイルの読み込み

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// --- 1. ミドルウェア設定 ---
// JSONボディの解析
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 静的ファイルの配信 (publicフォルダ)
app.use(express.static(path.join(__dirname, 'public')));

// セッション設定 (ログイン状態の維持)
app.use(session({
    secret: process.env.SESSION_SECRET || 'default_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // https化する時はtrueにする
        maxAge: 24 * 60 * 60 * 1000 // 24時間有効
    }
}));

// Passportの初期化
app.use(passport.initialize());
app.use(passport.session());

// --- 2. Google OAuth設定 ---
// 注意: 実際の運用ではデータベース(UserDB)を用意してユーザーを保存します。
// 今回はデモのため、メモリ上で処理します。
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    // ログイン成功時の処理
    // ここで profile.id を使ってDBを検索・登録するのが一般的です
    return done(null, profile);
  }
));

// セッションへの保存・復元
passport.serializeUser((user, done) => {
    done(null, user);
});
passport.deserializeUser((obj, done) => {
    done(null, obj);
});

// --- 3. ルーティング (API) ---

// A. 認証ルート
// Googleログイン開始
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Googleからのコールバック
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    // 成功したらお問い合わせページへ転送
    res.redirect('/#contact');
  }
);

// ログアウト
app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        // セッションを破棄してホームへ
        req.session.destroy(() => {
            res.redirect('/');
        });
    });
});

// B. データ取得API
// 現在のユーザー情報をフロントに返す
app.get('/api/user', (req, res) => {
    if (req.isAuthenticated() && req.user) {
        res.json({
            isLoggedIn: true,
            user: {
                id: req.user.id,
                name: req.user.displayName,
                email: (req.user.emails && req.user.emails[0]) ? req.user.emails[0].value : '非公開',
                photo: (req.user.photos && req.user.photos[0]) ? req.user.photos[0].value : null
            }
        });
    } else {
        res.json({ isLoggedIn: false });
    }
});

// C. お問い合わせ送信API
app.post('/api/contact', (req, res) => {
    // 未ログインなら拒否
    if (!req.isAuthenticated()) {
        return res.status(401).json({ success: false, error: 'ログインが必要です' });
    }

    const { message } = req.body;

    // バリデーション（空文字チェック）
    if (!message || message.trim() === "") {
        return res.status(400).json({ success: false, error: 'メッセージが空です' });
    }

    // ★ここで本来はDiscordのWebhookに投げたり、データベースに保存したりします
    console.log("==========================================");
    console.log(`[お問い合わせ受信]`);
    console.log(`送信者: ${req.user.displayName} (${req.user.emails[0].value})`);
    console.log(`内容: ${message}`);
    console.log("==========================================");

    // 成功レスポンス
    res.json({ success: true, message: 'お問い合わせを受け付けました。運営からの返信をお待ちください。' });
});

// D. その他 (SPA対応)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- 4. サーバー起動 ---
app.listen(PORT, () => {
    console.log(`--------------------------------------------------`);
    console.log(`✅ SESE Server running at http://localhost:${PORT}`);
    console.log(`ℹ️  Google Login requires setup in .env file`);
    console.log(`--------------------------------------------------`);
});
