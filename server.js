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
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo'); // セッション永続化用に追加

const app = express();

/** ----------------------------------------------------------------
 * 0. 環境変数バリデーション (起動時にチェック)
 * ---------------------------------------------------------------- */
const REQUIRED_KEYS = ['MONGO_URI', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'SESSION_SECRET'];
const missingKeys = REQUIRED_KEYS.filter(key => !process.env[key]);
if (missingKeys.length > 0) {
  console.error(`❌ 起動エラー: 環境変数が不足しています: ${missingKeys.join(', ')}`);
  process.exit(1);
}

const BASE_URL = process.env.BASE_URL || 'https://sesesaba.net.com'; // 通知リンク用

/** ----------------------------------------------------------------
 * MongoDB 接続設定
 * ---------------------------------------------------------------- */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('🍃 MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// メッセージの保存スキーマ定義 (ステータス管理機能を追加)
const MessageSchema = new mongoose.Schema({
  userName: String,
  email: String,
  content: String,
  reply: { type: String, default: "" },
  // status: 'pending'(未対応), 'progress'(対応中), 'completed'(完了)
  status: { type: String, enum: ['pending', 'progress', 'completed'], default: 'pending' }, 
  timestamp: { type: Date, default: Date.now } // ソート用にDate型へ変更
});
const Message = mongoose.model('Message', MessageSchema);

/** ----------------------------------------------------------------
 * セキュリティ設定
 * ---------------------------------------------------------------- */
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://*.googleusercontent.com", "https:"],
      connectSrc: ["'self'", "https://discord.com"],
    },
  },
}));
app.use(hpp());
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static('public'));

/** ----------------------------------------------------------------
 * レート制限
 * ---------------------------------------------------------------- */
const apiBurstLimiter = rateLimit({
  windowMs: 1000, 
  max: 5,
  message: { error: 'リクエストが速すぎます。' }
});

const contactStrictLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, 
  max: 3,
  message: { error: '5分間に3回までしか送信できません。' }
});

/** ----------------------------------------------------------------
 * セッション & パスポート設定 (MongoDB保存に変更)
 * ---------------------------------------------------------------- */
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ 
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60 // 14日間保存
  }),
  cookie: { 
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 14 * 24 * 60 * 60 * 1000 
  }
}));

app.use(passport.initialize());
app.use(passport.session());

const ADMIN_EMAILS = (process.env.ADMIN_EMAIL || "").split(',').map(email => email.trim());

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL || "/auth/google/callback",
    proxy: true
  },
  (accessToken, refreshToken, profile, done) => {
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
 * ミドルウェア
 * ---------------------------------------------------------------- */
function requireAdmin(req, res, next) {
  if (req.isAuthenticated() && ADMIN_EMAILS.includes(req.user.email)) return next();
  return res.status(403).json({ error: '権限がありません' });
}

/** ----------------------------------------------------------------
 * API ルート定義
 * ---------------------------------------------------------------- */

app.use('/api/', apiBurstLimiter);

// お問い合わせ送信 (Discord通知強化・DB保存)
app.post('/api/contact', contactStrictLimiter, async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'ログインが必要です' });
  const { message } = req.body;
  if (!message || message.length > 5000) return res.status(400).json({ error: '内容が不正です' });

  try {
    const newMessage = new Message({
      userName: req.user.name,
      email: req.user.email,
      content: message,
      status: 'pending'
    });
    await newMessage.save();

    // Discord Webhook 通知 (管理画面へのリンク付き)
    if (process.env.DISCORD_WEBHOOK_URL) {
      await axios.post(process.env.DISCORD_WEBHOOK_URL, {
        embeds: [{
          title: "📩 新しいお問い合わせ",
          description: `管理パネルで確認・返信してください。\n[👉 管理パネルを開く](${BASE_URL}/#admin)`,
          color: 0xffaa00, // オレンジ
          thumbnail: { url: req.user.photo },
          fields: [
            { name: "ユーザー", value: `${req.user.name} (${req.user.email})`, inline: true },
            { name: "内容", value: message.length > 100 ? message.substring(0, 100) + '...' : message }
          ],
          footer: { text: "SESE SERVER Support System" }
        }]
      });
    }
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'サーバーエラーが発生しました' });
  }
});

// ログインユーザー情報
app.get('/api/user', (req, res) => {
  res.json(req.isAuthenticated() ? { 
    isLoggedIn: true, 
    user: req.user, 
    isAdmin: ADMIN_EMAILS.includes(req.user.email) 
  } : { isLoggedIn: false });
});

// 自分のメッセージ履歴取得
app.get('/api/my-messages', async (req, res) => {
  if (!req.isAuthenticated()) return res.json({ messages: [] });
  // 日付順にソートして返す
  const messages = await Message.find({ email: req.user.email }).sort({ timestamp: -1 });
  res.json({ messages });
});

/** ----------------------------------------------------------------
 * 管理者専用 API
 * ---------------------------------------------------------------- */

// 全メッセージ取得 (ページネーション対応)
app.get('/api/admin/messages', requireAdmin, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const skip = (page - 1) * limit;

  try {
    const total = await Message.countDocuments();
    const messages = await Message.find({})
      .sort({ timestamp: -1 }) // 新しい順
      .skip(skip)
      .limit(limit);

    res.json({ 
      messages, 
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch(e) {
    res.status(500).json({ error: 'DB Error' });
  }
});

// お問い合わせに回答する (ステータス更新付き)
app.post('/api/admin/reply', requireAdmin, async (req, res) => {
  const { messageId, replyContent } = req.body;
  try {
    const updated = await Message.findByIdAndUpdate(
      messageId, 
      { 
        reply: replyContent,
        status: 'completed' // 回答したら完了ステータスへ
      }, 
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'メッセージが見つかりません' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: '更新に失敗しました' });
  }
});

app.delete('/api/admin/message/:id', requireAdmin, async (req, res) => {
  try {
    const deleted = await Message.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'メッセージが見つかりません' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: '削除に失敗しました' });
  }
});

/** ----------------------------------------------------------------
 * 認証ルート
 * ---------------------------------------------------------------- */
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  res.redirect('/#contact');
});
app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🛡️ Full-Feature Server on port ${PORT}`));
