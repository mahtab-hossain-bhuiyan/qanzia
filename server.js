'use strict';
require('dotenv').config();

const fastify = require('fastify')({ logger: process.env.NODE_ENV !== 'production' });
const { Pool } = require('pg');
const path = require('path');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// ── Database ─────────────────────────────────────────────
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
});

// ── DO Spaces (S3-compatible) ────────────────────────────
const s3 = new S3Client({
  endpoint: process.env.SPACES_ENDPOINT,
  region: process.env.SPACES_REGION,
  credentials: {
    accessKeyId: process.env.SPACES_KEY,
    secretAccessKey: process.env.SPACES_SECRET,
  },
  forcePathStyle: false,
});

// ── JWT Secret ───────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'default-secret-change-me';

// ── Plugins ──────────────────────────────────────────────
fastify.register(require('@fastify/cors'), {
  origin: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
});
fastify.register(require('@fastify/multipart'), { limits: { fileSize: 5 * 1024 * 1024 } });
fastify.register(require('@fastify/static'), {
  root: path.join(__dirname, 'public'),
  prefix: '/',
  decorateReply: false,
  cacheControl: 'max-age=3600, s-maxage=3600',
});

// ── Auth helpers ─────────────────────────────────────────────
function requireAdmin(req, reply) {
  // Support both x-admin-pass header and JWT Bearer token
  const authHeader = req.headers['authorization'];
  const xAdminPass = req.headers['x-admin-pass'];

  if (xAdminPass && xAdminPass === process.env.ADMIN_PASS) {
    return true;
  }

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded && decoded.role === 'admin') {
        return true;
      }
    } catch (e) {
      // Token invalid
    }
  }

  reply.code(401).send({ error: 'Unauthorized' });
  return false;
}

// ── Auto-publish scheduled posts ─────────────────────────
async function publishDue() {
  await db.query(`
    UPDATE posts
    SET status = 'published', published_at = schedule_time
    WHERE status = 'scheduled' AND schedule_time <= NOW()
  `);
}
setInterval(publishDue, 60 * 1000); // check every minute

// ═══════════════════════════════════════════════════════
// Rate limiting storage (DISABLED for now)
// const loginAttempts = new Map();

// PUBLIC ROUTES
// ═══════════════════════════════════════════════════════

// POST /api/auth/login — login and get JWT token
fastify.post('/api/auth/login', async (req, reply) => {
  const { password, secret } = req.body || {};

  // Only check password - secret is optional for now
  if (password !== process.env.ADMIN_PASS) {
    console.log(`Login failed - wrong password`);
    return reply.code(401).send({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ role: 'admin', loginTime: Date.now() }, JWT_SECRET, { expiresIn: '7d' });
  console.log('Admin logged in successfully');
  return { token };
});

// GET /api/posts — all published, sorted newest first
fastify.get('/api/posts', async (req, reply) => {
  try {
    await publishDue();
    const { rows, error } = await db.query(`
      SELECT id, slug, title, excerpt, author, tags, cover_url, status,
             qa_pairs, published_at, created_at
      FROM posts WHERE status = 'published'
      ORDER BY published_at DESC
    `);

    if (error) {
      console.error('DB error in /api/posts:', error);
      return reply.code(500).send({ error: 'Database error' });
    }

    console.log('/api/posts returned', rows.length, 'posts');

    // Prevent Cloudflare from caching API responses
    reply.header('Cache-Control', 'no-cache, no-store, must-revalidate');
    reply.header('Pragma', 'no-cache');
    reply.header('Expires', '0');
    reply.header('Surrogate-Control', 'no-store');

    return rows;
  } catch (err) {
    console.error('Error in /api/posts:', err);
    return reply.code(500).send({ error: err.message });
  }
});

// GET /api/posts/:slug — single published post
fastify.get('/api/posts/:slug', async (req, reply) => {
  const { rows } = await db.query(
    `SELECT * FROM posts WHERE slug = $1 AND status = 'published'`,
    [req.params.slug]
  );
  if (!rows.length) return reply.code(404).send({ error: 'Not found' });

  // Prevent Cloudflare from caching this response
  reply.header('Cache-Control', 'no-cache, no-store, must-revalidate');
  reply.header('Pragma', 'no-cache');
  reply.header('Expires', '0');

  return rows[0];
});

// GET /sitemap.xml — auto-generated sitemap
fastify.get('/sitemap.xml', async (req, reply) => {
  const { rows } = await db.query(
    `SELECT slug, updated_at FROM posts WHERE status = 'published' ORDER BY updated_at DESC`
  );
  const urls = rows.map(r =>
    `  <url><loc>https://qnaxia.com/post/${r.slug}</loc>` +
    `<lastmod>${new Date(r.updated_at).toISOString().split('T')[0]}</lastmod>` +
    `<changefreq>weekly</changefreq><priority>0.8</priority></url>`
  ).join('\n');
  reply.header('Content-Type', 'application/xml');
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://qnaxia.com/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>
${urls}
</urlset>`;
});

// ═══════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════

// GET /api/admin/posts — all posts any status
fastify.get('/api/admin/posts', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const { rows } = await db.query(
    `SELECT * FROM posts ORDER BY created_at DESC`
  );
  return rows;
});

// POST /api/admin/posts — create
fastify.post('/api/admin/posts', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const b = req.body;
  const { rows } = await db.query(`
    INSERT INTO posts
      (slug, title, content, qa_pairs, excerpt, author, tags, cover_url,
       status, schedule_time, published_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
    RETURNING *`,
    [
      b.slug, b.title, b.content,
      JSON.stringify(b.qa_pairs || []),
      b.excerpt, b.author || 'Editor', b.tags, b.cover_url || '',
      b.status || 'draft',
      b.schedule_time || null,
      b.status === 'published' ? new Date() : null
    ]
  );
  return rows[0];
});

// PUT /api/admin/posts/:slug — update
fastify.put('/api/admin/posts/:slug', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const b = req.body;
  const { rows } = await db.query(`
    UPDATE posts SET
      title=$1, content=$2, qa_pairs=$3, excerpt=$4, author=$5,
      tags=$6, cover_url=$7, status=$8, schedule_time=$9,
      published_at = CASE
        WHEN $8='published' AND published_at IS NULL THEN NOW()
        ELSE published_at
      END
    WHERE slug=$10 RETURNING *`,
    [
      b.title, b.content, JSON.stringify(b.qa_pairs || []),
      b.excerpt, b.author || 'Editor', b.tags, b.cover_url || '',
      b.status, b.schedule_time || null, req.params.slug
    ]
  );
  if (!rows.length) return reply.code(404).send({ error: 'Not found' });
  return rows[0];
});

// DELETE /api/admin/posts/:slug
fastify.delete('/api/admin/posts/:slug', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  await db.query(`DELETE FROM posts WHERE slug = $1`, [req.params.slug]);
  return { success: true };
});

// POST /api/upload — image upload to DO Spaces
fastify.post('/api/upload', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const data = await req.file();
  if (!data) return reply.code(400).send({ error: 'No file' });
  const ext = data.filename.split('.').pop().toLowerCase();
  if (!['jpg','jpeg','png','webp','gif'].includes(ext))
    return reply.code(400).send({ error: 'Invalid file type' });
  const key = `posts/${Date.now()}-${crypto.randomBytes(6).toString('hex')}.${ext}`;
  const buf = await data.toBuffer();
  await s3.send(new PutObjectCommand({
    Bucket: process.env.SPACES_BUCKET,
    Key: key,
    Body: buf,
    ContentType: data.mimetype,
    ACL: 'public-read',
  }));
  return { url: `${process.env.SPACES_CDN}/${key}` };
});

// ── Catch-all: serve index.html for SPA routing ──────────
fastify.setNotFoundHandler((req, reply) => {
  reply.sendFile('index.html');
});

// ── Start ────────────────────────────────────────────────
fastify.listen({ port: process.env.PORT || 3000, host: '0.0.0.0' }, err => {
  if (err) { console.error(err); process.exit(1); }
  console.log(`Qnaxia running on port ${process.env.PORT}`);
});