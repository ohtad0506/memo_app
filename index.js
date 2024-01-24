const bcrypt = require("bcrypt");
const cors = require("cors");
const express = require("express");
const mysql = require("mysql2/promise");
const session = require("express-session");

require("dotenv").config();

const app = express();

let connection;

async function initDatabase() {
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_DATABASE,
    });

    console.log("データベースに接続されました。");
  } catch (error) {
    console.error("データベース接続エラー: " + error.stack);
    process.exit(1);
  }
}

// データベース接続の初期化
initDatabase();

// 日時を 'YYYY-MM-DD HH:MM:SS' 形式に変換する関数
const formatDateToDateTime = (date) => {
  const twoDigits = (num) => num.toString().padStart(2, "0");

  const year = date.getFullYear();
  const month = twoDigits(date.getMonth() + 1);
  const day = twoDigits(date.getDate());
  const hours = twoDigits(date.getHours());
  const minutes = twoDigits(date.getMinutes());
  const seconds = twoDigits(date.getSeconds());

  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
};

app.use(
  cors({
    origin: "http://localhost:3000", // フロントエンドのURL
    credentials: true,
  })
);

app.use(express.json());

app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: false,
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

//  サインアップ ver2
app.post("/signup", async (req, res) => {
  try {
    //  クライアントからのデータ
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    // ユーザーの存在確認
    const [users] = await connection.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    // ユーザーが既に存在する場合の処理
    if (users.length > 0) {
      return res.status(409).send("This email address is already in use.");
    }

    // パスワードのハッシュ化
    const hash = await bcrypt.hash(password, 10);

    // ユーザーをデータベースに登録
    await connection.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hash]
    );

    // 登録されたユーザー情報を取得
    const [newUser] = await connection.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (newUser.length === 0) {
      // ユーザーが登録できなかった場合の処理
      return res.status(500).send("Error in registering user.");
    }

    // セッション情報の設定
    req.session.userId = newUser[0].id;
    req.session.name = newUser[0].name;
    req.session.email = newUser[0].email;

    //  レスポンスデータ
    const userData = {
      userId: newUser[0].id,
      name: newUser[0].name,
      email: newUser[0].email,
    };

    // 成功レスポンス
    console.log("サインアップ成功");
    return res.status(200).json(userData);
  } catch (error) {
    console.error("Error:", error);
    res.status(500).send("Error");
  }
});

//  ログイン ver2
app.post("/login", async (req, res) => {
  try {
    //  クライアントからのデータ
    const email = req.body.email;
    const plainPassword = req.body.password;

    // ユーザーの存在確認
    const [users] = await connection.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    //  存在しなかった場合の処理
    if (users.length === 0) {
      console.error("User not found");
      return res.status(404).send("User not found");
    }

    //  ハッシュ化したパスワード
    const hashedPassword = users[0].password;

    //  パスワード認証
    const isAuthenticated = await bcrypt.compare(plainPassword, hashedPassword);
    //  認証失敗
    if (isAuthenticated === false) {
      console.error("Invalid username or password.");
      return res.status(401).send("Invalid username or password.");
    }

    //  セッション情報の設定
    req.session.userId = users[0].id;
    req.session.name = users[0].name;
    req.session.email = users[0].email;

    //  レスポンスデータ
    const userData = {
      userId: users[0].id,
      name: users[0].name,
      email: users[0].email,
    };

    // 成功レスポンス
    console.log("ログイン成功");
    return res.status(200).json(userData);
  } catch (error) {
    console.error("Login Error", error);
    res.status(500).send("Error");
  }
});

//  ログアウト ver2
app.post("/logout", (req, res) => {
  try {
    req.session.destroy();
    console.log("ログアウト成功");
    return res.status(200).send("Logout successful.");
  } catch (error) {
    console.error("Logout Error", error);
    return res.status(500).send("Error");
  }
});

//  セッションデータ取得 ver2
app.get("/getUserData", (req, res) => {
  if (!req.session.name || !req.session.email) {
    console.log("Session data not found.");
    return res.status(404).send("Session data not found.");
  }

  const userData = {
    name: req.session.name,
    email: req.session.email,
  };

  console.log("Success");
  return res.status(200).json(userData);
});

//  セッション存在性確認 ver2
app.get("/checkSession", (req, res) => {
  if (req.session.name != null) {
    console.log("セッションが存在します");
    return res.status(200).send("ok");
  } else {
    console.log("セッションが存在しません");
    return res.status(404).send("There is no session");
  }
});

//  プロフィール編集 ver2
app.post("/editProfile", async (req, res) => {
  const userId = req.body.userId;
  const currentPassword = req.body.currentPassword;

  try {
    // ユーザーの存在確認
    const [users] = await connection.query("SELECT * FROM users WHERE id = ?", [
      userId,
    ]);
    if (users.length === 0) {
      console.log("ユーザーが存在しません");
      return res.status(404).send("User not found");
    }

    const newName =
      req.body.newName !== undefined ? req.body.newName : users[0].name;
    const newEmail =
      req.body.newEmail !== undefined ? req.body.newEmail : users[0].email;
    const newPassword =
      req.body.newPassword !== undefined
        ? req.body.newPassword
        : currentPassword;

    // パスワード認証
    const isAuthenticated = await bcrypt.compare(
      currentPassword,
      users[0].password
    );
    if (!isAuthenticated) {
      console.log("パスワードが一致しません");
      return res.status(401).send("Invalid password");
    }

    // パスワードハッシュ化
    const hash = await bcrypt.hash(newPassword, 10);

    // データベース更新処理
    await connection.query(
      "UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?",
      [newName, newEmail, hash, users[0].id]
    );

    // セッション情報更新
    req.session.name = newName;
    req.session.email = newEmail;
    console.log("セッション情報更新");

    const userData = {
      userId: userId,
      name: newName,
      email: newEmail,
    };

    //  成功処理
    console.log("プロフィール編集成功");
    return res.status(200).json(userData);
  } catch (error) {
    console.error("Error", error);
    return res.status(500).send("Error");
  }
});

//  アカウント削除 ver2
app.post("/deleteAccount", async (req, res) => {
  const userId = req.body.userId;
  try {
    //  メモ削除
    const [deleteMemoResult] = await connection.query(
      "DELETE FROM memos WHERE user_id = ?",
      [userId]
    );

    // アカウント削除処理
    const [deleteUserResult] = await connection.query(
      "DELETE FROM users WHERE id = ?",
      [userId]
    );

    if (deleteUserResult.affectedRows === 0) {
      console.error("User not found");
      return res.status(404).send("User not found");
    }

    // セッション破棄
    req.session.destroy();

    //  成功処理
    console.log("アカウント削除成功");
    return res.status(200).send("Delete complete");
  } catch (error) {
    console.error("Error", error);
    return res.status(500).send("Error");
  }
});

//  メモ作成
app.post("/createMemo", async (req, res) => {
  const now = new Date();

  const userId = req.body.userId;
  const title = req.body.title;
  const content = req.body.content;
  const createdAt = formatDateToDateTime(now); // 今
  const updatedAt = formatDateToDateTime(now); // 今
  try {
    //  データベースにメモを新規登録
    const [newMemo] = await connection.query(
      "INSERT INTO memos (user_id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
      [userId, title, content, createdAt, updatedAt]
    );
    //  登録したID
    const insertedMemoId = newMemo.insertId;

    //  登録情報の確認・取得
    const [result] = await connection.query(
      "SELECT * FROM memos WHERE memo_id = ?",
      [insertedMemoId]
    );
    //  登録情報のエラーハンドリング
    if (result.length === 0) {
      console.error("Memo create error");
      return res.status(500).send("Memo create error");
    }

    // メモの情報
    const memoData = {
      memo_id: result[0].memo_id,
      title: result[0].title,
      content: result[0].content,
      created_it: result[0].created_at,
      updated_it: result[0].updated_at,
    };

    //  成功
    console.log("メモ作成成功");
    return res.status(200).json(memoData);
  } catch (error) {
    console.error("Error", error);
    return res.status(500).send("Error");
  }
});

//  メモ編集
app.post("/editMemo", async (req, res) => {
  const now = new Date();
  //  受信データ
  const memoId = req.body.memoId;
  const title = req.body.title;
  const content = req.body.content;
  const updatedAt = formatDateToDateTime(now);

  try {
    //  データベースの確認
    const [result] = await connection.query(
      "SELECT * FROM memos WHERE memo_id = ?",
      [memoId]
    );
    if (result.length === 0) {
      console.error("Memo not found");
      return res.status(404).send("Memo not found");
    }

    //  更新
    await connection.query(
      "UPDATE memos SET title = ?, content = ?, updated_at = ? WHERE memo_id = ?",
      [title, content, updatedAt, memoId]
    );

    // メモ情報の構築（更新された情報を使用）
    const memoData = {
      memo_id: memoId,
      title: title,
      content: content,
      created_at: result[0].created_at, // 元の作成日時
      updated_at: updatedAt, // 更新日時
    };

    //  成功
    console.log("メモ編集成功");
    return res.status(200).json(memoData);
  } catch (error) {
    console.error("Error", error);
    return res.status(500).send("Error");
  }
});

//  メモ削除
app.post("/deleteMemo", async (req, res) => {
  //  受信データ
  const memoId = req.body.memoId;
  try {
    // レコードの削除
    const [deleteResult] = await connection.query(
      "DELETE FROM memos WHERE memo_id = ?",
      [memoId]
    );

    // 削除されたレコードがない場合
    if (deleteResult.affectedRows === 0) {
      console.error("Memo not found");
      return res.status(404).send("Memo not found");
    }

    //  成功
    console.log("削除成功");
    return res.status(200).send("Delete complete");
  } catch (error) {
    console.error("Error", error);
    return res.status(500).send("Error");
  }
});

//  メモデータ取得
app.post("/getMemo", async (req, res) => {
  const userId = req.body.userId;

  try {
    //  メモ取得
    const [results] = await connection.query(
      "SELECT * FROM memos WHERE user_id = ?",
      [userId]
    );
    if (results.length === 0) {
      console.error("Memo not found");
      return res.status(404).send("Memo not found");
    }

    //  成功
    console.log("取得成功");
    return res.status(200).json(results);
  } catch (error) {
    console.error("Error", error);
    return res.status(500).send("Error");
  }
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
