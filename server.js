const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const { initTRPC, TRPCError } = require('@trpc/server');
const { createExpressMiddleware } = require('@trpc/server/adapters/express');
const { z } = require('zod');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors({
  origin: ['https://gamedaypickup.com', 'https://www.gamedaypickup.com'],
methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
allowedHeaders: ['Content-Type', 'x-auth-token'],

  credentials: true
}));
app.use(express.json());

const db = mysql.createPool({
  uri: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});


function hashPassword(p) {
  return crypto.createHash('sha256').update(p).digest('hex');
}
function generateToken(userId) {
  return Buffer.from(JSON.stringify({ userId, exp: Date.now() + 7*24*60*60*1000 })).toString('base64');
}
function verifyToken(token) {
  try {
    const d = JSON.parse(Buffer.from(token, 'base64').toString());
    if (d.exp < Date.now()) return null;
    return d.userId;
  } catch { return null; }
}

const t = initTRPC.context().create();
const router = t.router;
const publicProcedure = t.procedure;
const protectedProcedure = t.procedure.use(({ ctx, next }) => {
  if (!ctx.userId) throw new TRPCError({ code: 'UNAUTHORIZED' });
  return next();
});

const authRouter = router({
  signup: publicProcedure
.input(z.object({
  name: z.string(),
  email: z.string().email(),
  password: z.string(),
  avatar: z.string().optional(),
  avatar_color: z.string().optional(),
  age: z.number().optional(),
  birthdate: z.string().optional(),
  gender: z.string().optional(),
  favoriteSports: z.array(z.string()).optional(),
  allowChat: z.boolean().optional()
}))

    .mutation(async ({ input, ctx }) => {
      const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [input.email]);
      if (existing.length) throw new TRPCError({ code: 'BAD_REQUEST', message: 'Email already exists' });
      const hashed = hashPassword(input.password);
      const [result] = await db.query('INSERT INTO users (name, email, password, avatar_color) VALUES (?, ?, ?, ?)', [input.name, input.email, hashed, input.avatar_color || '#3B82F6']);
      const token = generateToken(result.insertId);
      return { token, user: { id: result.insertId, name: input.name, email: input.email } };
    }),

  login: publicProcedure
    .input(z.object({ email: z.string().email(), password: z.string() }))
    .mutation(async ({ input }) => {
      const hashed = hashPassword(input.password);
      const [users] = await db.query('SELECT * FROM users WHERE email = ? AND password = ?', [input.email, hashed]);
      if (!users.length) throw new TRPCError({ code: 'UNAUTHORIZED', message: 'Invalid credentials' });
      const user = users[0];
      const token = generateToken(user.id);
      return { token, user: { id: user.id, name: user.name, email: user.email } };
    }),

  me: publicProcedure.query(async ({ ctx }) => {
    if (!ctx.userId) throw new TRPCError({ code: 'UNAUTHORIZED' });
    const [users] = await db.query('SELECT id, name, email, avatar_color FROM users WHERE id = ?', [ctx.userId]);
    if (!users.length) throw new TRPCError({ code: 'NOT_FOUND', message: 'User not found' });
    return users[0];
  }),
});

const gameRouter = router({
  list: publicProcedure.query(async () => {
    const [games] = await db.query('SELECT * FROM games ORDER BY created_at DESC');
    return games;
  }),

  create: protectedProcedure
   .input(z.object({ name: z.string(), email: z.string().email(), password: z.string(), avatar_color: z.string().optional() }).passthrough())

    .mutation(async ({ input, ctx }) => {
      const [result] = await db.query(
        'INSERT INTO games (title, sport, location, lat, lng, date, max_players, description, creator_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [input.title, input.sport, input.location, input.lat, input.lng, input.date, input.maxPlayers, input.description || '', ctx.userId]
      );
      return { id: result.insertId };
    }),
});

const appRouter = router({
  auth: authRouter,
  game: gameRouter,
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/api/trpc', createExpressMiddleware({
  router: appRouter,
  createContext: ({ req }) => {
    const token = req.headers['x-auth-token'];
    const userId = token ? verifyToken(token) : null;
    return { userId };
  },
}));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
