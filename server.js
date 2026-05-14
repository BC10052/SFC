const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3333;
const JWT_SECRET = process.env.JWT_SECRET || 'scf_super_secret_key_2024';

app.use(cors());
app.use(express.json());

// Logger simples
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    console.log(`${req.method} ${req.url} → ${res.statusCode} (${Date.now() - start}ms)`);
  });
  next();
});

// ============================================
// BANCO DE DADOS
// ============================================
const db = new sqlite3.Database('./scf_database.db');

db.serialize(() => {
  db.run('PRAGMA journal_mode = WAL');
  db.run('PRAGMA foreign_keys = ON');

  // Usuários
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    reset_code TEXT,
    reset_expires TEXT,
    active INTEGER DEFAULT 1,
    last_login TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  // Categorias
  db.run(`CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('income','expense')),
    icon TEXT DEFAULT 'bx-wallet',
    color TEXT DEFAULT '#3a7bd5',
    budget REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // Transações
  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    category_id INTEGER,
    type TEXT NOT NULL CHECK(type IN ('income','expense')),
    amount REAL NOT NULL,
    description TEXT DEFAULT '',
    date TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
  )`);

  // Notificações
  db.run(`CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    message TEXT DEFAULT '',
    type TEXT DEFAULT 'info',
    read INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // Configurações
  db.run(`CREATE TABLE IF NOT EXISTS user_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    theme TEXT DEFAULT 'dark',
    language TEXT DEFAULT 'pt-BR',
    currency TEXT DEFAULT 'BRL',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // Índices
  db.run('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
  db.run('CREATE INDEX IF NOT EXISTS idx_trans_user ON transactions(user_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_trans_date ON transactions(date)');
  db.run('CREATE INDEX IF NOT EXISTS idx_cat_user ON categories(user_id)');

  // Admin padrão
  const hash = bcrypt.hashSync('admin123', 10);
  db.run('INSERT OR IGNORE INTO users (name, email, password, role) VALUES (?,?,?,?)',
    ['Administrador', 'admin@scf.com', hash, 'admin'], function() {
      if (this.lastID) db.run('INSERT OR IGNORE INTO user_settings (user_id) VALUES (?)', [this.lastID]);
    });

  console.log('✅ Banco de dados pronto!');
  console.log('👑 admin@scf.com / admin123\n');
});

// ============================================
// MIDDLEWARE DE AUTENTICAÇÃO
// ============================================
function auth(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'Token não fornecido.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, error: 'Token inválido ou expirado.' });
    req.user = user;
    next();
  });
}

// ============================================
// ROTAS PÚBLICAS
// ============================================

app.get('/', (req, res) => {
  db.get('SELECT COUNT(*) as users FROM users', (err, u) => {
    db.get('SELECT COUNT(*) as trans FROM transactions', (err, t) => {
      res.json({ success: true, system: 'SCF', version: '12.0', stats: { users: u?.users||0, transactions: t?.trans||0 } });
    });
  });
});

// REGISTRO
app.post('/register', (req, res) => {
  const { name, email, password } = req.body;

  if (!name || name.length < 3) return res.status(400).json({ success: false, error: 'Nome deve ter no mínimo 3 caracteres.' });
  if (!email?.includes('@')) return res.status(400).json({ success: false, error: 'Email inválido.' });
  if (!password || password.length < 8) return res.status(400).json({ success: false, error: 'Senha deve ter no mínimo 8 caracteres.' });

  const hash = bcrypt.hashSync(password, 10);
  const cleanEmail = email.toLowerCase().trim();
  const cleanName = name.trim();

  db.run('INSERT INTO users (name, email, password) VALUES (?,?,?)', [cleanName, cleanEmail, hash], function(err) {
    if (err) {
      if (err.message.includes('UNIQUE')) return res.status(409).json({ success: false, error: 'Email já cadastrado.' });
      return res.status(500).json({ success: false, error: 'Erro ao criar conta.' });
    }

    const uid = this.lastID;
    db.run('INSERT OR IGNORE INTO user_settings (user_id) VALUES (?)', [uid]);

    // Categorias padrão
    const cats = [
      ['Salário', 'income', 'bx-money', '#00ff88'],
      ['Alimentação', 'expense', 'bx-food-menu', '#ffaa00'],
      ['Transporte', 'expense', 'bx-car', '#ff4444'],
      ['Moradia', 'expense', 'bx-home', '#ff6600'],
      ['Lazer', 'expense', 'bx-game', '#aa44ff']
    ];
    cats.forEach(c => db.run('INSERT INTO categories (user_id, name, type, icon, color) VALUES (?,?,?,?,?)', [uid, ...c]));

    console.log(`✅ Novo usuário: ${cleanName} (${cleanEmail})`);
    res.status(201).json({ success: true, message: '✅ Conta criada com sucesso!', user: { id: uid, name: cleanName, email: cleanEmail } });
  });
});

// LOGIN
app.post('/login', (req, res) => {
  const { email, password, rememberMe } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, error: 'Email e senha obrigatórios.' });

  db.get('SELECT * FROM users WHERE email = ? AND active = 1', [email.toLowerCase().trim()], async (err, user) => {
    if (!user) return res.status(401).json({ success: false, error: 'Email ou senha incorretos.' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ success: false, error: 'Email ou senha incorretos.' });

    const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: rememberMe ? '30d' : '24h' });
    db.run('UPDATE users SET last_login = datetime("now","localtime") WHERE id = ?', [user.id]);

    console.log(`✅ Login: ${user.name}`);
    res.json({ success: true, message: `✅ Bem-vindo, ${user.name}!`, token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  });
});

// ESQUECI SENHA
app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ success: false, error: 'Email obrigatório.' });

  db.get('SELECT id, name FROM users WHERE email = ? AND active = 1', [email.toLowerCase().trim()], (err, user) => {
    if (!user) return res.json({ success: true, message: 'Se existir, código enviado.', code: null });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 600000).toISOString();
    db.run('UPDATE users SET reset_code = ?, reset_expires = ? WHERE id = ?', [code, expires, user.id]);

    console.log(`\n🔑 CÓDIGO: ${code} → ${email}\n`);
    res.json({ success: true, message: '✅ Código gerado!', code });
  });
});

// REDEFINIR SENHA
app.post('/reset-password', (req, res) => {
  const { email, code, newPassword, confirmPassword } = req.body;
  if (!email || !code || !newPassword) return res.status(400).json({ success: false, error: 'Todos os campos obrigatórios.' });
  if (newPassword !== confirmPassword) return res.status(400).json({ success: false, error: 'Senhas não coincidem.' });
  if (newPassword.length < 8) return res.status(400).json({ success: false, error: 'Mínimo 8 caracteres.' });

  db.get('SELECT id FROM users WHERE email = ? AND reset_code = ? AND reset_expires > datetime("now","localtime")',
    [email.toLowerCase().trim(), code], (err, user) => {
      if (!user) return res.status(400).json({ success: false, error: 'Código inválido ou expirado.' });

      const hash = bcrypt.hashSync(newPassword, 10);
      db.run('UPDATE users SET password = ?, reset_code = NULL, reset_expires = NULL WHERE id = ?', [hash, user.id]);

      console.log(`✅ Senha redefinida: ${email}`);
      res.json({ success: true, message: '✅ Senha redefinida! Faça login.' });
    });
});

// ============================================
// ROTAS PROTEGIDAS
// ============================================

// Dashboard
app.get('/dashboard', auth, (req, res) => {
  const uid = req.user.id;
  const ms = new Date(); ms.setDate(1); ms.setHours(0,0,0,0);
  const msStr = ms.toISOString().split('T')[0];

  db.get(`SELECT COALESCE(SUM(CASE WHEN type='income' THEN amount ELSE 0 END),0) as inc, COALESCE(SUM(CASE WHEN type='expense' THEN amount ELSE 0 END),0) as exp FROM transactions WHERE user_id = ? AND date >= ?`, [uid, msStr], (err, m) => {
    db.get('SELECT COALESCE(SUM(amount),0) as total FROM transactions WHERE user_id = ? AND type=?', [uid, 'income'], (err, ai) => {
      db.get('SELECT COALESCE(SUM(amount),0) as total FROM transactions WHERE user_id = ? AND type=?', [uid, 'expense'], (err, ae) => {
        db.get('SELECT COUNT(*) as c FROM notifications WHERE user_id = ? AND read = 0', [uid], (err, n) => {
          db.all('SELECT t.*, c.name as cn, c.icon, c.color FROM transactions t LEFT JOIN categories c ON t.category_id = c.id WHERE t.user_id = ? ORDER BY t.date DESC LIMIT 10', [uid], (err, recent) => {
            const inc = m?.inc || 0, exp = m?.exp || 0;
            res.json({
              success: true,
              stats: {
                monthlyIncome: inc,
                monthlyExpense: exp,
                monthlyBalance: inc - exp,
                totalIncome: ai?.total || 0,
                totalExpense: ae?.total || 0,
                totalBalance: (ai?.total || 0) - (ae?.total || 0),
                unreadNotifications: n?.c || 0
              },
              recentTransactions: recent || []
            });
          });
        });
      });
    });
  });
});

// Transações
app.get('/transactions', auth, (req, res) => {
  const { type, limit = 100 } = req.query;
  let q = 'SELECT t.*, c.name as cn FROM transactions t LEFT JOIN categories c ON t.category_id = c.id WHERE t.user_id = ?';
  const p = [req.user.id];
  if (type) { q += ' AND t.type = ?'; p.push(type); }
  q += ' ORDER BY t.date DESC LIMIT ?'; p.push(parseInt(limit));
  db.all(q, p, (err, rows) => res.json({ success: true, transactions: rows || [] }));
});

app.post('/transactions', auth, (req, res) => {
  const { type, amount, description, date, category_id } = req.body;
  if (!type || !amount || !date) return res.status(400).json({ success: false, error: 'Preencha tipo, valor e data.' });
  const amt = parseFloat(amount);
  if (isNaN(amt) || amt <= 0) return res.status(400).json({ success: false, error: 'Valor inválido.' });

  db.run('INSERT INTO transactions (user_id, category_id, type, amount, description, date) VALUES (?,?,?,?,?,?)',
    [req.user.id, category_id || null, type, amt, description || '', date], function(err) {
      if (err) return res.status(500).json({ success: false, error: 'Erro.' });
      res.status(201).json({ success: true, message: '✅ Transação registrada!', id: this.lastID });
    });
});

app.delete('/transactions/:id', auth, (req, res) => {
  db.run('DELETE FROM transactions WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err) => {
    if (err) return res.status(500).json({ success: false, error: 'Erro.' });
    res.json({ success: true, message: '✅ Excluída!' });
  });
});

// Categorias
app.get('/categories', auth, (req, res) => {
  db.all('SELECT * FROM categories WHERE user_id = ? ORDER BY type, name', [req.user.id], (err, rows) => res.json({ success: true, categories: rows || [] }));
});

app.post('/categories', auth, (req, res) => {
  const { name, type, icon, color, budget } = req.body;
  if (!name || !type) return res.status(400).json({ success: false, error: 'Nome e tipo obrigatórios.' });
  db.run('INSERT INTO categories (user_id, name, type, icon, color, budget) VALUES (?,?,?,?,?,?)',
    [req.user.id, name, type, icon || 'bx-wallet', color || '#3a7bd5', parseFloat(budget) || 0], function(err) {
      if (err) return res.status(500).json({ success: false, error: 'Erro.' });
      res.status(201).json({ success: true, message: '✅ Categoria criada!', id: this.lastID });
    });
});

app.delete('/categories/:id', auth, (req, res) => {
  db.run('DELETE FROM categories WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err) => res.json({ success: true, message: '✅ Excluída!' }));
});

// Notificações
app.get('/notifications', auth, (req, res) => {
  db.all('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [req.user.id], (err, rows) => res.json({ success: true, notifications: rows || [] }));
});

app.put('/notifications/read-all', auth, (req, res) => {
  db.run('UPDATE notifications SET read = 1 WHERE user_id = ?', [req.user.id], (err) => res.json({ success: true, message: '✅ Todas lidas!' }));
});

// Configurações
app.get('/settings', auth, (req, res) => {
  db.get('SELECT * FROM user_settings WHERE user_id = ?', [req.user.id], (err, row) => res.json({ success: true, settings: row || {} }));
});

app.put('/settings', auth, (req, res) => {
  const { theme, language, currency } = req.body;
  db.run('UPDATE user_settings SET theme=COALESCE(?,theme), language=COALESCE(?,language), currency=COALESCE(?,currency) WHERE user_id=?',
    [theme, language, currency, req.user.id], (err) => res.json({ success: true, message: '✅ Salvo!' }));
});

// Perfil
app.get('/profile', auth, (req, res) => {
  db.get('SELECT id, name, email, role, created_at FROM users WHERE id = ?', [req.user.id], (err, row) => res.json({ success: true, user: row }));
});

app.put('/profile', auth, (req, res) => {
  const { name } = req.body;
  if (!name || name.length < 3) return res.status(400).json({ success: false, error: 'Nome inválido.' });
  db.run('UPDATE users SET name = ? WHERE id = ?', [name.trim(), req.user.id], (err) => res.json({ success: true, message: '✅ Perfil atualizado!' }));
});

// Logout
app.post('/logout', auth, (req, res) => res.json({ success: true, message: '✅ Logout!' }));

// ============================================
// INICIAR
// ============================================
app.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════╗`);
  console.log(`║  🚀 SCF rodando na porta ${PORT}   ║`);
  console.log(`║  http://localhost:${PORT}          ║`);
  console.log(`║  admin@scf.com / admin123        ║`);
  console.log(`╚══════════════════════════════════╝\n`);
});

process.on('SIGINT', () => { db.close(() => process.exit(0)); });