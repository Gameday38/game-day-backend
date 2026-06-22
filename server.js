const express = require('express');
const cors = require('cors');
const { initTRPC } = require('@trpc/server');
const { createExpressMiddleware } = require('@trpc/server/adapters/express');
const { z } = require('zod');
const mysql = require('mysql2/promise');
const { SignJWT, jwtVerify } = require('jose');

// ==================== CONFIG ====================
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL || '';
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || '';
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET || '';
const APP_SECRET = new TextEncoder().encode(process.env.APP_SECRET || 'gameday-secret-key-change-in-production');

// ==================== DATABASE ====================
let dbPool = null;
function getDb() {
  if (!dbPool) {
    dbPool = mysql.createPool({
      uri: DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      waitForConnections: true,
      connectionLimit: 10,
    });
  }
  return dbPool;
}

async function query(sql, params) {
  const [rows] = await getDb().execute(sql, params);
  return rows;
}

// ==================== JWT ====================
async function createToken(userId) {
  return new SignJWT({ userId })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('30d')
    .sign(APP_SECRET);
}

async function verifyToken(token) {
  try {
    const { payload } = await jwtVerify(token, APP_SECRET, { clockTolerance: 60 });
    return payload?.userId || null;
  } catch {
    return null;
  }
}

// ==================== ID GENERATOR ====================
let idCounter = 0;
function generateId(prefix = '') {
  idCounter = (idCounter + 1) % 10000;
  return `${prefix}${Date.now()}_${Math.random().toString(36).slice(2, 8)}_${idCounter}`;
}

// ==================== tRPC SETUP ====================
const t = initTRPC.create();

const createRouter = t.router;
const publicProcedure = t.procedure;
const authedProcedure = t.procedure.use(async ({ ctx, next }) => {
  if (!ctx.user) throw new Error('Unauthorized');
  return next({ ctx: { ...ctx, user: ctx.user } });
});

// ==================== CONTEXT ====================
async function createContext({ req, res }) {
  const authHeader = req.headers['x-auth-token'] || req.headers['authorization'];
  let user = null;
  
  if (authHeader) {
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    const userId = await verifyToken(token);
    if (userId) {
      const rows = await query('SELECT * FROM users WHERE id = ?', [userId]);
      user = rows[0] || null;
    }
  }
  
  return { req, res, user };
}

// ==================== AUTH ROUTER ====================
const authRouter = createRouter({
  signup: publicProcedure
    .input(z.object({
      email: z.string().email(),
      password: z.string().min(1),
      name: z.string().min(1),
      avatar: z.string().optional(),
      age: z.number().optional(),
      birthdate: z.string().optional(),
      gender: z.enum(['male', 'female', 'other', 'prefer_not_to_say']).optional(),
      favoriteSports: z.array(z.string()).optional(),
      allowChat: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const existing = await query('SELECT id FROM users WHERE email = ?', [input.email.toLowerCase().trim()]);
      if (existing.length > 0) throw new Error('An account with this email already exists');
      
      const id = generateId('user_');
      await query(
        `INSERT INTO users (id, email, password, name, avatar, age, birthdate, gender, favoriteSports, allowChat) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [id, input.email.toLowerCase().trim(), input.password, input.name.trim(),
         input.avatar || null, input.age || null, input.birthdate || null,
         input.gender || null, JSON.stringify(input.favoriteSports || []),
         input.allowChat ? 'yes' : 'no']
      );
      
      const rows = await query('SELECT * FROM users WHERE id = ?', [id]);
      const token = await createToken(id);
      return { user: rows[0], token };
    }),

  login: publicProcedure
    .input(z.object({ email: z.string().email(), password: z.string() }))
    .mutation(async ({ input }) => {
      const rows = await query('SELECT * FROM users WHERE email = ?', [input.email.toLowerCase().trim()]);
      const user = rows[0];
      if (!user || user.password !== input.password) throw new Error('Invalid email or password');
      const token = await createToken(user.id);
      return { user, token };
    }),

  me: publicProcedure.query(async ({ ctx }) => {
    return ctx.user || null;
  }),

  userById: publicProcedure
    .input(z.object({ id: z.string() }))
    .query(async ({ input }) => {
      const rows = await query('SELECT id, email, name, avatar, bio, age, birthdate, gender, favoriteSports, allowChat, gamesHosted, gamesJoined, rating, reviewCount, subscriptionTier, createdAt FROM users WHERE id = ?', [input.id]);
      return rows[0] || null;
    }),
});

// ==================== GAME ROUTER ====================
const gameRouter = createRouter({
  list: publicProcedure.query(async () => {
    return query('SELECT * FROM games ORDER BY createdAt DESC');
  }),

  byId: publicProcedure
    .input(z.object({ id: z.string() }))
    .query(async ({ input }) => {
      const rows = await query('SELECT * FROM games WHERE id = ?', [input.id]);
      return rows[0] || null;
    }),

  byHost: publicProcedure
    .input(z.object({ hostId: z.string() }))
    .query(async ({ input }) => {
      return query('SELECT * FROM games WHERE hostId = ? ORDER BY createdAt DESC', [input.hostId]);
    }),

  create: authedProcedure
    .input(z.object({
      title: z.string(),
      sport: z.enum(['soccer', 'basketball', 'football', 'volleyball', 'tennis', 'baseball', 'hockey', 'other']),
      location: z.string(),
      latitude: z.number(),
      longitude: z.number(),
      date: z.string(),
      time: z.string(),
      duration: z.number(),
      skillLevel: z.enum(['beginner', 'intermediate', 'advanced', 'any']),
      maxPlayers: z.number().min(2),
      description: z.string().optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const id = generateId('game_');
      await query(
        `INSERT INTO games (id, title, sport, location, latitude, longitude, date, time, duration, skillLevel, maxPlayers, currentPlayers, status, hostId, hostName, hostAvatar, description)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'open', ?, ?, ?, ?)`,
        [id, input.title, input.sport, input.location, input.latitude, input.longitude,
         input.date, input.time, input.duration, input.skillLevel, input.maxPlayers,
         ctx.user.id, ctx.user.name, ctx.user.avatar, input.description || null]
      );
      const rows = await query('SELECT * FROM games WHERE id = ?', [id]);
      return rows[0];
    }),

  update: authedProcedure
    .input(z.object({ id: z.string(), data: z.any() }))
    .mutation(async ({ ctx, input }) => {
      const game = await query('SELECT * FROM games WHERE id = ?', [input.id]);
      if (!game[0] || game[0].hostId !== ctx.user.id) throw new Error('Not authorized');
      // Simple update - build SET clause
      const allowed = ['title', 'location', 'date', 'time', 'maxPlayers', 'description', 'status'];
      const sets = [];
      const vals = [];
      for (const key of allowed) {
        if (input.data[key] !== undefined) {
          sets.push(`${key} = ?`);
          vals.push(input.data[key]);
        }
      }
      if (sets.length > 0) {
        vals.push(input.id);
        await query(`UPDATE games SET ${sets.join(', ')} WHERE id = ?`, vals);
      }
      const rows = await query('SELECT * FROM games WHERE id = ?', [input.id]);
      return rows[0];
    }),

  delete: authedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const game = await query('SELECT * FROM games WHERE id = ?', [input.id]);
      if (!game[0] || game[0].hostId !== ctx.user.id) throw new Error('Not authorized');
      await query('DELETE FROM games WHERE id = ?', [input.id]);
      return { success: true };
    }),
});

// ==================== REQUEST ROUTER ====================
const requestRouter = createRouter({
  listByGame: publicProcedure
    .input(z.object({ gameId: z.string() }))
    .query(async ({ input }) => {
      return query('SELECT * FROM joinRequests WHERE gameId = ?', [input.gameId]);
    }),

  pendingByGame: publicProcedure
    .input(z.object({ gameId: z.string() }))
    .query(async ({ input }) => {
      return query('SELECT * FROM joinRequests WHERE gameId = ? AND status = ?', [input.gameId, 'pending']);
    }),

  pendingByHost: publicProcedure
    .input(z.object({ hostId: z.string() }))
    .query(async ({ input }) => {
      return query(
        `SELECT jr.* FROM joinRequests jr 
         INNER JOIN games g ON jr.gameId = g.id 
         WHERE g.hostId = ? AND jr.status = ?`,
        [input.hostId, 'pending']
      );
    }),

  myRequest: publicProcedure
    .input(z.object({ gameId: z.string(), userId: z.string() }))
    .query(async ({ input }) => {
      const rows = await query('SELECT * FROM joinRequests WHERE gameId = ? AND userId = ?', [input.gameId, input.userId]);
      return rows[0] || null;
    }),

  create: authedProcedure
    .input(z.object({ gameId: z.string(), message: z.string().optional() }))
    .mutation(async ({ ctx, input }) => {
      const existing = await query(
        'SELECT * FROM joinRequests WHERE gameId = ? AND userId = ? AND status = ?',
        [input.gameId, ctx.user.id, 'pending']
      );
      if (existing.length > 0) throw new Error('You already requested to join this game');
      
      const id = generateId('req_');
      await query(
        `INSERT INTO joinRequests (id, gameId, userId, userName, userAvatar, status, message) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [id, input.gameId, ctx.user.id, ctx.user.name, ctx.user.avatar, 'pending', input.message || null]
      );
      const rows = await query('SELECT * FROM joinRequests WHERE id = ?', [id]);
      return rows[0];
    }),

  approve: authedProcedure
    .input(z.object({ requestId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const req = await query('SELECT * FROM joinRequests WHERE id = ?', [input.requestId]);
      if (!req[0]) throw new Error('Request not found');
      
      const game = await query('SELECT * FROM games WHERE id = ?', [req[0].gameId]);
      if (!game[0] || game[0].hostId !== ctx.user.id) throw new Error('Not authorized');
      
      await query('UPDATE games SET currentPlayers = currentPlayers + 1 WHERE id = ?', [req[0].gameId]);
      await query('UPDATE users SET gamesJoined = gamesJoined + 1 WHERE id = ?', [req[0].userId]);
      await query("UPDATE joinRequests SET status = 'accepted' WHERE id = ?", [input.requestId]);
      
      const rows = await query('SELECT * FROM joinRequests WHERE id = ?', [input.requestId]);
      return rows[0];
    }),

  reject: authedProcedure
    .input(z.object({ requestId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const req = await query('SELECT * FROM joinRequests WHERE id = ?', [input.requestId]);
      if (!req[0]) throw new Error('Request not found');
      
      const game = await query('SELECT * FROM games WHERE id = ?', [req[0].gameId]);
      if (!game[0] || game[0].hostId !== ctx.user.id) throw new Error('Not authorized');
      
      await query("UPDATE joinRequests SET status = 'rejected' WHERE id = ?", [input.requestId]);
      const rows = await query('SELECT * FROM joinRequests WHERE id = ?', [input.requestId]);
      return rows[0];
    }),
});

// ==================== MESSAGE ROUTER ====================
const messageRouter = createRouter({
  myMessages: publicProcedure
    .input(z.object({ userId: z.string() }))
    .query(async ({ input }) => {
      return query(
        'SELECT * FROM messages WHERE senderId = ? OR recipientId = ? ORDER BY createdAt DESC LIMIT 200',
        [input.userId, input.userId]
      );
    }),

  conversation: publicProcedure
    .input(z.object({ userId1: z.string(), userId2: z.string() }))
    .query(async ({ input }) => {
      return query(
        `SELECT * FROM messages 
         WHERE (senderId = ? AND recipientId = ?) OR (senderId = ? AND recipientId = ?)
         ORDER BY createdAt ASC LIMIT 200`,
        [input.userId1, input.userId2, input.userId2, input.userId1]
      );
    }),

  send: authedProcedure
    .input(z.object({ recipientId: z.string(), content: z.string().min(1).max(2000) }))
    .mutation(async ({ ctx, input }) => {
      const id = generateId('msg_');
      await query(
        `INSERT INTO messages (id, senderId, senderName, senderAvatar, recipientId, content) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [id, ctx.user.id, ctx.user.name, ctx.user.avatar, input.recipientId, input.content]
      );
      const rows = await query('SELECT * FROM messages WHERE id = ?', [id]);
      return rows[0];
    }),

  markRead: authedProcedure
    .input(z.object({ senderId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      await query(
        "UPDATE messages SET read = 'yes' WHERE recipientId = ? AND senderId = ? AND read = 'no'",
        [ctx.user.id, input.senderId]
      );
      return { success: true };
    }),

  unreadCount: publicProcedure
    .input(z.object({ userId: z.string() }))
    .query(async ({ input }) => {
      const rows = await query(
        "SELECT COUNT(*) as count FROM messages WHERE recipientId = ? AND read = 'no'",
        [input.userId]
      );
      return rows[0]?.count || 0;
    }),
});

// ==================== REVIEW ROUTER ====================
const reviewRouter = createRouter({
  forUser: publicProcedure
    .input(z.object({ userId: z.string() }))
    .query(async ({ input }) => {
      return query('SELECT * FROM reviews WHERE revieweeId = ?', [input.userId]);
    }),

  average: publicProcedure
    .input(z.object({ userId: z.string() }))
    .query(async ({ input }) => {
      const rows = await query('SELECT AVG(rating) as avg FROM reviews WHERE revieweeId = ?', [input.userId]);
      return rows[0]?.avg ? parseFloat(rows[0].avg).toFixed(1) : 5.0;
    }),

  create: authedProcedure
    .input(z.object({
      revieweeId: z.string(),
      gameId: z.string(),
      rating: z.number().min(1).max(5),
      comment: z.string().optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      if (ctx.user.id === input.revieweeId) throw new Error('Cannot review yourself');
      
      const existing = await query(
        'SELECT * FROM reviews WHERE reviewerId = ? AND revieweeId = ?',
        [ctx.user.id, input.revieweeId]
      );
      if (existing.length > 0) throw new Error('You have already reviewed this user');
      
      const id = generateId('rev_');
      await query(
        `INSERT INTO reviews (id, reviewerId, reviewerName, reviewerAvatar, revieweeId, gameId, rating, comment) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [id, ctx.user.id, ctx.user.name, ctx.user.avatar, input.revieweeId, input.gameId, input.rating, input.comment || null]
      );
      const rows = await query('SELECT * FROM reviews WHERE id = ?', [id]);
      return rows[0];
    }),
});

// ==================== FRIEND ROUTER ====================
const friendRouter = createRouter({
  myFriends: publicProcedure
    .input(z.object({ userId: z.string() }))
    .query(async ({ input }) => {
      return query('SELECT * FROM friends WHERE userId = ? AND status = ?', [input.userId, 'accepted']);
    }),

  pendingRequests: publicProcedure
    .input(z.object({ userId: z.string() }))
    .query(async ({ input }) => {
      return query('SELECT * FROM friends WHERE friendId = ? AND status = ?', [input.userId, 'pending']);
    }),

  request: authedProcedure
    .input(z.object({ friendId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const existing = await query(
        'SELECT * FROM friends WHERE userId = ? AND friendId = ?',
        [ctx.user.id, input.friendId]
      );
      if (existing.length > 0) throw new Error('Friend request already exists');
      
      const friendUser = await query('SELECT name, avatar FROM users WHERE id = ?', [input.friendId]);
      const friendName = friendUser[0]?.name || 'User';
      
      const id = generateId('fr_');
      await query(
        `INSERT INTO friends (id, userId, friendId, friendName, friendAvatar, status) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [id, ctx.user.id, input.friendId, friendName, friendUser[0]?.avatar, 'pending']
      );
      const rows = await query('SELECT * FROM friends WHERE id = ?', [id]);
      return rows[0];
    }),

  accept: authedProcedure
    .input(z.object({ requestId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const req = await query('SELECT * FROM friends WHERE id = ?', [input.requestId]);
      if (!req[0] || req[0].friendId !== ctx.user.id) throw new Error('Not authorized');
      
      await query("UPDATE friends SET status = 'accepted' WHERE id = ?", [input.requestId]);
      const rows = await query('SELECT * FROM friends WHERE id = ?', [input.requestId]);
      return rows[0];
    }),

  remove: authedProcedure
    .input(z.object({ friendshipId: z.string() }))
    .mutation(async ({ input }) => {
      await query('DELETE FROM friends WHERE id = ?', [input.friendshipId]);
      return { success: true };
    }),
});

// ==================== PAYPAL ROUTER ====================
const PAYPAL_API = 'https://api-m.paypal.com';

const paypalRouter = createRouter({
  createOrder: publicProcedure
    .input(z.object({ planType: z.enum(['premium', 'pro']), isYearly: z.boolean() }))
    .mutation(async ({ input }) => {
      if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
        throw new Error('PayPal not configured on server');
      }

      const prices = {
        premium_monthly: '3.99', premium_yearly: '29.99',
        pro_monthly: '7.99', pro_yearly: '59.99',
      };
      const key = `${input.planType}_${input.isYearly ? 'yearly' : 'monthly'}`;
      const amount = prices[key];

      const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString('base64');
      const tokenRes = await fetch(`${PAYPAL_API}/v1/oauth2/token`, {
        method: 'POST',
        headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=client_credentials',
      });
      const { access_token } = await tokenRes.json();

      const orderRes = await fetch(`${PAYPAL_API}/v2/checkout/orders`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${access_token}` },
        body: JSON.stringify({
          intent: 'CAPTURE',
          purchase_units: [{ amount: { currency_code: 'USD', value: amount }, description: `GameDay ${input.planType}` }],
        }),
      });
      const order = await orderRes.json();
      return { orderId: order.id, status: order.status, amount: `$${amount}` };
    }),

  captureOrder: publicProcedure
    .input(z.object({ orderId: z.string() }))
    .mutation(async ({ input }) => {
      if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
        throw new Error('PayPal not configured on server');
      }

      const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString('base64');
      const tokenRes = await fetch(`${PAYPAL_API}/v1/oauth2/token`, {
        method: 'POST',
        headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=client_credentials',
      });
      const { access_token } = await tokenRes.json();

      const capRes = await fetch(`${PAYPAL_API}/v2/checkout/orders/${input.orderId}/capture`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${access_token}` },
      });
      const capture = await capRes.json();
      const captureData = capture.purchase_units?.[0]?.payments?.captures?.[0];
      return { status: capture.status, captureId: captureData?.id || '', amount: captureData?.amount?.value || '' };
    }),
});

// ==================== MAIN ROUTER ====================
const appRouter = createRouter({
  ping: publicProcedure.query(() => ({ ok: true, ts: Date.now() })),
  auth: authRouter,
  game: gameRouter,
  request: requestRouter,
  message: messageRouter,
  review: reviewRouter,
  friend: friendRouter,
  paypal: paypalRouter,
});

// ==================== EXPRESS APP ====================
const app = express();

// CORS for gamedaypickup.com
app.use(cors({
  origin: ['https://gamedaypickup.com', 'https://www.gamedaypickup.com', 'http://localhost:3000', 'http://localhost:5173'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-auth-token', 'Authorization'],
  credentials: true,
}));

app.use(express.json({ limit: '50mb' }));

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'GameDay Backend', ok: true, time: new Date().toISOString() });
});

// tRPC v11 middleware with createExpressMiddleware
// This properly handles batch requests with the {"0":{"json":{}}} format
app.use('/api/trpc', createExpressMiddleware({
  router: appRouter,
  createContext,
  batching: { enabled: true },
}));

// 404 handler
app.all('/api/*', (req, res) => {
  res.status(404).json({ error: 'Not Found', path: req.path });
});

// Start server
app.listen(PORT, () => {
  console.log(`========================================`);
  console.log(`  GameDay Backend Running`);
  console.log(`  Port: ${PORT}`);
  console.log(`  CORS: gamedaypickup.com`);
  console.log(`  tRPC: v11 with batch support`);
  console.log(`  Time: ${new Date().toISOString()}`);
  console.log(`========================================`);
});

module.exports = { app, appRouter };
