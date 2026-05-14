const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3333;
const JWT_SECRET = process.env.JWT_SECRET || 'scf_secret_key_2024';

app.use(cors());
app.use(express.json());

// Banco de dados JSON
const DB_FILE = './database.json';
let db = { users: [], categories: [], transactions: [], notifications: [], settings: [] };

// Carregar banco
if (fs.existsSync(DB_FILE)) {
  db = JSON.parse(fs.readFileSync(DB_FILE));
} else {
  // Criar admin
  db.users.push({
    id: 1,
    name: 'Administrador',
    email: 'admin@scf.com',
    password: bcrypt.hashSync('admin123', 10),
    role: 'admin',
    createdAt: new Date().toISOString()
  });
  saveDB();
}

function saveDB() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// Auth
function auth(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'Token não fornecido.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, error: 'Token inválido.' });
    req.user = user;
    next();
  });
}

// Rotas
app.get('/', (req, res) => res.json({ success: true, system: 'SCF', version: '1.0' }));

app.post('/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ success: false, error: 'Preencha todos os campos.' });
  if (db.users.find(u => u.email === email.toLowerCase())) return res.status(409).json({ success: false, error: 'Email já cadastrado.' });
  
  const user = {
    id: db.users.length + 1,
    name: name.trim(),
    email: email.toLowerCase().trim(),
    password: bcrypt.hashSync(password, 10),
    role: 'user',
    createdAt: new Date().toISOString()
  };
  db.users.push(user);
  saveDB();
  res.status(201).json({ success: true, message: '✅ Conta criada!', user: { id: user.id, name: user.name, email: user.email } });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, error: 'Email e senha obrigatórios.' });
  const user = db.users.find(u => u.email === email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, error: 'Email ou senha incorretos.' });
  
  const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ success: true, message: `✅ Bem-vindo, ${user.name}!`, token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  const user = db.users.find(u => u.email === email.toLowerCase().trim());
  if (!user) return res.json({ success: true, message: 'Se existir, código enviado.', code: null });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  user.resetCode = code;
  user.resetExpires = new Date(Date.now() + 600000).toISOString();
  saveDB();
  console.log(`🔑 CÓDIGO: ${code} para ${email}`);
  res.json({ success: true, message: '✅ Código gerado!', code });
});

app.post('/reset-password', (req, res) => {
  const { email, code, newPassword } = req.body;
  const user = db.users.find(u => u.email === email.toLowerCase().trim() && u.resetCode === code && new Date(u.resetExpires) > new Date());
  if (!user) return res.status(400).json({ success: false, error: 'Código inválido ou expirado.' });
  user.password = bcrypt.hashSync(newPassword, 10);
  delete user.resetCode;
  delete user.resetExpires;
  saveDB();
  res.json({ success: true, message: '✅ Senha redefinida!' });
});

app.get('/dashboard', auth, (req, res) => {
  const trans = db.transactions.filter(t => t.userId === req.user.id);
  const income = trans.filter(t => t.type === 'income').reduce((s, t) => s + t.amount, 0);
  const expense = trans.filter(t => t.type === 'expense').reduce((s, t) => s + t.amount, 0);
  res.json({ success: true, stats: { monthlyIncome: income, monthlyExpense: expense, totalBalance: income - expense, totalIncome: income, totalExpense: expense, unreadNotifications: 0 }, recentTransactions: trans.slice(-10).reverse() });
});

app.get('/transactions', auth, (req, res) => {
  const trans = db.transactions.filter(t => t.userId === req.user.id);
  res.json({ success: true, transactions: trans.reverse() });
});

app.post('/transactions', auth, (req, res) => {
  const { type, amount, description, date, category_id } = req.body;
  if (!type || !amount || !date) return res.status(400).json({ success: false, error: 'Preencha tipo, valor e data.' });
  const trans = { id: db.transactions.length + 1, userId: req.user.id, type, amount: parseFloat(amount), description: description || '', date, category_id: category_id || null, createdAt: new Date().toISOString() };
  db.transactions.push(trans);
  saveDB();
  res.status(201).json({ success: true, message: '✅ Transação registrada!', id: trans.id });
});

app.delete('/transactions/:id', auth, (req, res) => {
  const idx = db.transactions.findIndex(t => t.id == req.params.id && t.userId === req.user.id);
  if (idx === -1) return res.status(404).json({ success: false, error: 'Não encontrada.' });
  db.transactions.splice(idx, 1);
  saveDB();
  res.json({ success: true, message: '✅ Excluída!' });
});

app.get('/categories', auth, (req, res) => {
  const cats = db.categories.filter(c => c.userId === req.user.id);
  res.json({ success: true, categories: cats });
});

app.post('/categories', auth, (req, res) => {
  const { name, type } = req.body;
  if (!name || !type) return res.status(400).json({ success: false, error: 'Nome e tipo obrigatórios.' });
  const cat = { id: db.categories.length + 1, userId: req.user.id, name, type, icon: 'bx-wallet', color: '#3a7bd5' };
  db.categories.push(cat);
  saveDB();
  res.status(201).json({ success: true, message: '✅ Categoria criada!', id: cat.id });
});

app.delete('/categories/:id', auth, (req, res) => {
  const idx = db.categories.findIndex(c => c.id == req.params.id && c.userId === req.user.id);
  if (idx === -1) return res.status(404).json({ success: false, error: 'Não encontrada.' });
  db.categories.splice(idx, 1);
  saveDB();
  res.json({ success: true, message: '✅ Excluída!' });
});

app.get('/notifications', auth, (req, res) => res.json({ success: true, notifications: [] }));
app.put('/notifications/read-all', auth, (req, res) => res.json({ success: true, message: '✅ Todas lidas!' }));
app.get('/settings', auth, (req, res) => res.json({ success: true, settings: { theme: 'dark', language: 'pt-BR', currency: 'BRL' } }));
app.put('/settings', auth, (req, res) => res.json({ success: true, message: '✅ Salvo!' }));
app.get('/profile', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  res.json({ success: true, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});
app.put('/profile', auth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (req.body.name) user.name = req.body.name.trim();
  saveDB();
  res.json({ success: true, message: '✅ Perfil atualizado!' });
});
app.post('/logout', auth, (req, res) => res.json({ success: true, message: '✅ Logout!' }));

app.listen(PORT, () => console.log(`🚀 SCF rodando na porta ${PORT}`));