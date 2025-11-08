const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// MySQL connection pool
let db;
async function initDb() {
  db = await mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
  });
  console.log('✅ Connected to MySQL');
}
initDb();

// Auth middleware
async function auth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) return res.status(401).json({ error: 'Authorization header missing' });

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer')
    return res.status(401).json({ error: 'Authorization header malformed' });

  const token = parts[1];
  if (!token) return res.status(401).json({ error: 'Token missing' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    console.error('JWT verification error:', err.message);
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Register
app.post('/api/register', async (req, res) => {
  const { username, password, salary } = req.body;
  if (!username || !password || !salary)
    return res.status(400).json({ error: 'All fields required' });

  const [existing] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
  if (existing.length) return res.status(400).json({ error: 'User already exists' });

  const hashed = await bcrypt.hash(password, 10);
  await db.execute('INSERT INTO users (username, password, salary) VALUES (?, ?, ?)', [
    username, hashed, salary,
  ]);

  res.status(201).json({ message: 'User created successfully' });
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'All fields required' });

  const [rows] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
  const user = rows[0];
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id }, JWT_SECRET);
  res.json({ token });
});

// Get balance
app.get('/api/balance', auth, async (req, res) => {
  const [userRows] = await db.execute('SELECT * FROM users WHERE id = ?', [req.userId]);
  const user = userRows[0];

  const [expenseRows] = await db.execute(
    'SELECT SUM(amount) as totalSpent FROM expenses WHERE user_id = ?',
    [req.userId]
  );
  const totalSpent = expenseRows[0].totalSpent || 0;
  const remaining = user.salary - totalSpent;

  res.json({ salary: user.salary, spent: totalSpent, remaining });
});

// Add expense
app.post('/api/expenses', auth, async (req, res) => {
  const { amount, description } = req.body;
  if (!amount || !description) return res.status(400).json({ error: 'Amount and description required' });

  const [result] = await db.execute(
    'INSERT INTO expenses (user_id, amount, description) VALUES (?, ?, ?)',
    [req.userId, amount, description]
  );

  const [newExpense] = await db.execute('SELECT * FROM expenses WHERE id = ?', [result.insertId]);
  res.status(201).json(newExpense[0]);
});

// Get expenses
app.get('/api/expenses', auth, async (req, res) => {
  const [expenses] = await db.execute('SELECT * FROM expenses WHERE user_id = ?', [req.userId]);
  res.json(expenses);
});

// Update expense
app.put('/api/expenses/:id', auth, async (req, res) => {
  const { amount, description } = req.body;
  const expenseId = req.params.id;
  if (!amount || !description) return res.status(400).json({ error: 'Amount and description required' });

  const [rows] = await db.execute('SELECT * FROM expenses WHERE id = ? AND user_id = ?', [expenseId, req.userId]);
  if (!rows.length) return res.status(404).json({ error: 'Expense not found' });

  await db.execute('UPDATE expenses SET amount = ?, description = ? WHERE id = ?', [amount, description, expenseId]);
  const [updated] = await db.execute('SELECT * FROM expenses WHERE id = ?', [expenseId]);
  res.json(updated[0]);
});

// Delete expense
app.delete('/api/expenses/:id', auth, async (req, res) => {
  const expenseId = req.params.id;
  await db.execute('DELETE FROM expenses WHERE id = ? AND user_id = ?', [expenseId, req.userId]);
  res.status(204).send();
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
