const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors({
  origin: ['https://gamedaypickup.com', 'https://www.gamedaypickup.com'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'x-auth-token'],
  credentials: true
}));
app.use(express.json());

const crypto = require('crypto');
const mysql = require('mysql2/promise');

const db = mysql.createPool({ uri: process.env.DATABASE_URL });

function hashPassword(p) { return crypto.createHash('sha256').update(p).digest('hex'); }
function generateToken(userId) { return Buffer.from(JSON.stringify({ userId, exp: Date.now() + 7*24*60*60*1000 })).toString('base64'); }
function verifyToken(token) { try { const d = JSON.parse(Buffer.from(token, 'base64').toString()); return d.exp > Date.now() ? d.userId : null; } catch { return null; } }

async function auth(req, res, next) {
  const token = req.headers['x-auth-token'];
  const userId = token ? verifyToken(token) : null;
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  req.userId = userId;
  next();
}

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/trpc/auth.signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length) return res.status(400).json({ error: 'Email already exists' });
    const [result] = await db.query('INSERT INTO users (name, email, password, avatar_color) VALUES (?, ?, ?, ?)', [name, email, hashPassword(password), '#10b981']);
    const token = generateToken(result.insertId);
    res.json({ result: { data: { token, user: { id: result.insertId, name, email } } } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/trpc/auth.login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [users] = await db.query('SELECT * FROM users WHERE email = ? AND password = ?', [email, hashPassword(password)]);
    if (!users.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = users[0];
    const token = generateToken(user.id);
    res.json({ result: { data: { token, user: { id: user.id, name: user.name, email: user.email } } } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/trpc/auth.me', async (req, res) => {
  try {
    const token = req.headers['x-auth-token'];
    const userId = token ? verifyToken(token) : null;
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });
    const [users] = await db.query('SELECT id, name, email, avatar_color FROM users WHERE id = ?', [userId]);
    if (!users.length) return res.status(404).json({ error: 'User not found' });
    res.json({ result: { data: users[0] } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/trpc/game.list', async (req, res) => {
  try {
    const [games] = await db.query('SELECT * FROM games ORDER BY created_at DESC');
    res.json({ result: { data: games } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/trpc/game.create', async (req, res) => {
  try {
    const token = req.headers['x-auth-token'];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });
    const { title, sport, location, lat, lng, date, maxPlayers, description } = req.body;
    const [result] = await db.query('INSERT INTO games (title, sport, location, lat, lng, date, max_players, description, host_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [title, sport, location, lat, lng, date, maxPlayers, description, userId]);
    res.json({ result: { data: { id: result.insertId } } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
