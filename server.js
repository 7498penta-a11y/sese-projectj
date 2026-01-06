// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');

const app = express();
// Renderなどのホスティング環境に対応するため、環境変数PORTを優先して使う
const PORT = process.env.PORT || 3001;
// JWTのシークレットも環境変数から取得するのが推奨（開発時はデフォルトが使われる）
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// データファイルのパス
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const CONTACTS_FILE = path.join(DATA_DIR, 'contacts.json');

app.use(cors());
app.use(express.json());

// データディレクトリの初期化
async function initDataDir() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });

    // ユーザーファイルの初期化
    try {
      await fs.access(USERS_FILE);
    } catch {
      await fs.writeFile(USERS_FILE, JSON.stringify([], null, 2));
    }

    // お問い合わせファイルの初期化
    try {
      await fs.access(CONTACTS_FILE);
    } catch {
      await fs.writeFile(CONTACTS_FILE, JSON.stringify([], null, 2));
    }
  } catch (error) {
    console.error('データディレクトリの初期化エラー:', error);
  }
}

// データ読み込み
async function readData(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('データ読み込みエラー:', error);
    return [];
  }
}

// データ書き込み
async function writeData(filePath, data) {
  try {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error('データ書き込みエラー:', error);
    return false;
  }
}

// ルート（トップ） - HTMLを触らない方針なのでJSONでステータスを返す
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    message: 'SESE API Server is running'
  });
});

// ユーザー登録
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ success: false, error: '全ての項目を入力してください' });
    }

    // メールアドレスの検証
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, error: '有効なメールアドレスを入力してください' });
    }

    // パスワードの検証（最低6文字）
    if (password.length < 6) {
      return res.status(400).json({ success: false, error: 'パスワードは6文字以上である必要があります' });
    }

    const users = await readData(USERS_FILE);

    // 既存ユーザーチェック
    if (users.find(u => u.email === email)) {
      return res.status(400).json({ success: false, error: 'このメールアドレスは既に登録されています' });
    }

    // パスワードのハッシュ化
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: Date.now().toString(),
      email,
      name,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await writeData(USERS_FILE, users);

    // JWTトークンの生成
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email, name: newUser.name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: { id: newUser.id, email: newUser.email, name: newUser.name }
    });
  } catch (error) {
    console.error('登録エラー:', error);
    res.status(500).json({ success: false, error: 'サーバーエラーが発生しました' });
  }
});

// ログイン
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'メールアドレスとパスワードを入力してください' });
    }

    const users = await readData(USERS_FILE);
    const user = users.find(u => u.email === email);

    if (!user) {
      return res.status(401).json({ success: false, error: 'メールアドレスまたはパスワードが正しくありません' });
    }

    // パスワードの検証
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ success: false, error: 'メールアドレスまたはパスワードが正しくありません' });
    }

    // JWTトークンの生成
    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: { id: user.id, email: user.email, name: user.name }
    });
  } catch (error) {
    console.error('ログインエラー:', error);
    res.status(500).json({ success: false, error: 'サーバーエラーが発生しました' });
  }
});

// トークン検証ミドルウェア
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, error: '認証が必要です' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, error: '無効なトークンです' });
    }
    req.user = user;
    next();
  });
};

// お問い合わせ送信
app.post('/api/contact', authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ success: false, error: 'お問い合わせ内容を入力してください' });
    }

    const contacts = await readData(CONTACTS_FILE);

    const newContact = {
      id: Date.now().toString(),
      userId: req.user.id,
      name: req.user.name,
      email: req.user.email,
      message,
      createdAt: new Date().toISOString(),
      status: 'pending'
    };

    contacts.push(newContact);
    await writeData(CONTACTS_FILE, contacts);

    res.json({ success: true, message: 'お問い合わせを受け付けました' });
  } catch (error) {
    console.error('お問い合わせ送信エラー:', error);
    res.status(500).json({ success: false, error: 'サーバーエラーが発生しました' });
  }
});

// ユーザー情報取得
app.get('/api/user', authenticateToken, (req, res) => {
  res.json({
    success: true,
    user: { id: req.user.id, email: req.user.email, name: req.user.name }
  });
});

// サーバー起動
app.listen(PORT, async () => {
  await initDataDir();
  console.log(`🚀 サーバーがポート${PORT}で起動しました`);
  console.log(`📁 データディレクトリ: ${DATA_DIR}`);
});