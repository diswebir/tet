const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const APP_DIR = __dirname;
const DATA_DIR = path.join(APP_DIR, 'data');
const DB_PATH = path.join(DATA_DIR, 'app.db');
const BASE_PATH = process.env.BASE_PATH || '/tet';

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'pending',
    priority INTEGER DEFAULT 0,
    due_date DATETIME,
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS subtasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    completed BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS timers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    duration INTEGER DEFAULT 0,
    is_running BOOLEAN DEFAULT 0,
    started_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT,
    related_id INTEGER,
    is_read BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
  CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
  CREATE INDEX IF NOT EXISTS idx_tasks_user ON tasks(user_id);
  CREATE INDEX IF NOT EXISTS idx_subtasks_task ON subtasks(task_id);
  CREATE INDEX IF NOT EXISTS idx_timers_task ON timers(task_id);
  CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
`);

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const verifyHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return hash === verifyHash;
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function createSession(userId) {
  const token = generateToken();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)').run(userId, token, expiresAt);
  return token;
}

function getSession(token) {
  if (!token) return null;
  const session = db.prepare('SELECT s.*, u.username, u.email FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ? AND s.expires_at > datetime("now")').get(token);
  return session;
}

function deleteSession(token) {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

function cleanupExpiredSessions() {
  db.prepare('DELETE FROM sessions WHERE expires_at <= datetime("now")').run();
}

const app = express();
app.disable('x-powered-by');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

const cookieParser = (req, res, next) => {
  req.cookies = {};
  if (req.headers.cookie) {
    req.headers.cookie.split(';').forEach(cookie => {
      const [name, ...rest] = cookie.trim().split('=');
      req.cookies[name] = rest.join('=');
    });
  }
  next();
};

app.use(cookieParser);

const authMiddleware = (req, res, next) => {
  const token = req.cookies.session_token;
  const session = getSession(token);
  if (session) {
    req.user = { id: session.user_id, username: session.username, email: session.email };
    req.sessionToken = token;
  }
  next();
};

app.use(authMiddleware);

const requireAuth = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'احراز هویت مورد نیاز است', code: 'UNAUTHORIZED' });
  }
  next();
};

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function createNotification(userId, type, title, message, relatedId = null) {
  db.prepare('INSERT INTO notifications (user_id, type, title, message, related_id) VALUES (?, ?, ?, ?, ?)').run(userId, type, title, message, relatedId);
}

function notifyTaskDue(task) {
  createNotification(task.user_id, 'task_due', 'موعد تسک نزدیک است', `تسک "${task.title}" موعد انقضا دارد`, task.id);
}

function notifyTimerComplete(taskId, userId) {
  const task = db.prepare('SELECT title FROM tasks WHERE id = ?').get(taskId);
  if (task) {
    createNotification(userId, 'timer_complete', 'تایمر تکمیل شد', `تایمر برای "${task.title}" به پایان رسید`, taskId);
  }
}

app.get(`${BASE_PATH}/api/health`, (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post(`${BASE_PATH}/api/auth/register`, asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'تمام فیلدها الزامی هستند' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'رمز عبور باید حداقل ۸ کاراکتر باشد' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
  if (existing) {
    return res.status(409).json({ error: 'نام کاربری یا ایمیل قبلاً ثبت شده است' });
  }
  const passwordHash = hashPassword(password);
  const result = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)').run(username, email, passwordHash);
  const token = createSession(result.lastInsertRowid);
  res.cookie('session_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000,
    path: BASE_PATH
  });
  res.status(201).json({ user: { id: result.lastInsertRowid, username, email } });
}));

app.post(`${BASE_PATH}/api/auth/login`, asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'ایمیل و رمز عبور الزامی هستند' });
  }
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: 'ایمیل یا رمز عبور نادرست است' });
  }
  const token = createSession(user.id);
  res.cookie('session_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000,
    path: BASE_PATH
  });
  res.json({ user: { id: user.id, username: user.username, email: user.email } });
}));

app.post(`${BASE_PATH}/api/auth/logout`, (req, res) => {
  if (req.sessionToken) {
    deleteSession(req.sessionToken);
  }
  res.clearCookie('session_token', { path: BASE_PATH });
  res.json({ success: true });
});

app.get(`${BASE_PATH}/api/auth/me`, (req, res) => {
  if (req.user) {
    res.json({ user: req.user });
  } else {
    res.status(401).json({ error: 'احراز هویت نشده' });
  }
});

app.get(`${BASE_PATH}/api/tasks`, requireAuth, asyncHandler(async (req, res) => {
  const { status, priority, search, sort = 'created_at', order = 'DESC' } = req.query;
  let query = 'SELECT t.*, (SELECT COUNT(*) FROM subtasks WHERE task_id = t.id) as subtask_count, (SELECT COUNT(*) FROM subtasks WHERE task_id = t.id AND completed = 1) as completed_subtasks FROM tasks t WHERE t.user_id = ?';
  const params = [req.user.id];
  if (status) {
    query += ' AND t.status = ?';
    params.push(status);
  }
  if (priority !== undefined) {
    query += ' AND t.priority = ?';
    params.push(parseInt(priority));
  }
  if (search) {
    query += ' AND (t.title LIKE ? OR t.description LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }
  const validSort = ['created_at', 'updated_at', 'due_date', 'priority', 'title'];
  const validOrder = ['ASC', 'DESC'];
  const sortCol = validSort.includes(sort) ? sort : 'created_at';
  const orderDir = validOrder.includes(order.toUpperCase()) ? order.toUpperCase() : 'DESC';
  query += ` ORDER BY t.${sortCol} ${orderDir}`;
  const tasks = db.prepare(query).all(...params);
  res.json({ tasks });
}));

app.post(`${BASE_PATH}/api/tasks`, requireAuth, asyncHandler(async (req, res) => {
  const { title, description, priority = 0, due_date } = req.body;
  if (!title || !title.trim()) {
    return res.status(400).json({ error: 'عنوان تسک الزامی است' });
  }
  const result = db.prepare('INSERT INTO tasks (user_id, title, description, priority, due_date) VALUES (?, ?, ?, ?, ?)').run(req.user.id, title.trim(), description?.trim() || null, parseInt(priority), due_date || null);
  const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(result.lastInsertRowid);
  if (task.due_date) {
    notifyTaskDue(task);
  }
  res.status(201).json({ task });
}));

app.get(`${BASE_PATH}/api/tasks/:id`, requireAuth, asyncHandler(async (req, res) => {
  const task = db.prepare('SELECT t.*, (SELECT COUNT(*) FROM subtasks WHERE task_id = t.id) as subtask_count, (SELECT COUNT(*) FROM subtasks WHERE task_id = t.id AND completed = 1) as completed_subtasks FROM tasks t WHERE t.id = ? AND t.user_id = ?').get(req.params.id, req.user.id);
  if (!task) {
    return res.status(404).json({ error: 'تسک یافت نشد' });
  }
  const subtasks = db.prepare('SELECT * FROM subtasks WHERE task_id = ? ORDER BY created_at').all(task.id);
  res.json({ task, subtasks });
}));

app.put(`${BASE_PATH}/api/tasks/:id`, requireAuth, asyncHandler(async (req, res) => {
  const { title, description, status, priority, due_date } = req.body;
  const task = db.prepare('SELECT * FROM tasks WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!task) {
    return res.status(404).json({ error: 'تسک یافت نشد' });
  }
  const updates = [];
  const params = [];
  if (title !== undefined) { updates.push('title = ?'); params.push(title.trim()); }
  if (description !== undefined) { updates.push('description = ?'); params.push(description.trim() || null); }
  if (status !== undefined) { updates.push('status = ?'); params.push(status); }
  if (priority !== undefined) { updates.push('priority = ?'); params.push(parseInt(priority)); }
  if (due_date !== undefined) { updates.push('due_date = ?'); params.push(due_date || null); }
  if (updates.length === 0) {
    return res.status(400).json({ error: 'هیچ تغییری مشخص نشده' });
  }
  updates.push('updated_at = datetime("now")');
  params.push(req.params.id, req.user.id);
  db.prepare(`UPDATE tasks SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`).run(...params);
  const updated = db.prepare('SELECT * FROM tasks WHERE id = ?').get(req.params.id);
  if (updated.due_date && updated.status !== 'completed') {
    notifyTaskDue(updated);
  }
  if (status === 'completed' && task.status !== 'completed') {
    db.prepare('UPDATE tasks SET completed_at = datetime("now") WHERE id = ?').run(req.params.id);
  }
  res.json({ task: updated });
}));

app.delete(`${BASE_PATH}/api/tasks/:id`, requireAuth, asyncHandler(async (req, res) => {
  const result = db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (result.changes === 0) {
    return res.status(404).json({ error: 'تسک یافت نشد' });
  }
  res.json({ success: true });
}));

app.post(`${BASE_PATH}/api/tasks/:id/subtasks`, requireAuth, asyncHandler(async (req, res) => {
  const { title } = req.body;
  if (!title || !title.trim()) {
    return res.status(400).json({ error: 'عنوان زیرتسک الزامی است' });
  }
  const task = db.prepare('SELECT id FROM tasks WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!task) {
    return res.status(404).json({ error: 'تسک یافت نشد' });
  }
  const result = db.prepare('INSERT INTO subtasks (task_id, title) VALUES (?, ?)').run(req.params.id, title.trim());
  const subtask = db.prepare('SELECT * FROM subtasks WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ subtask });
}));

app.put(`${BASE_PATH}/api/subtasks/:id`, requireAuth, asyncHandler(async (req, res) => {
  const { title, completed } = req.body;
  const subtask = db.prepare('SELECT s.*, t.user_id FROM subtasks s JOIN tasks t ON s.task_id = t.id WHERE s.id = ?').get(req.params.id);
  if (!subtask || subtask.user_id !== req.user.id) {
    return res.status(404).json({ error: 'زیرتسک یافت نشد' });
  }
  const updates = [];
  const params = [];
  if (title !== undefined) { updates.push('title = ?'); params.push(title.trim()); }
  if (completed !== undefined) { updates.push('completed = ?'); params.push(completed ? 1 : 0); updates.push('completed_at = ?'); params.push(completed ? new Date().toISOString() : null); }
  if (updates.length === 0) {
    return res.status(400).json({ error: 'هیچ تغییری مشخص نشده' });
  }
  params.push(req.params.id);
  db.prepare(`UPDATE subtasks SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  const updated = db.prepare('SELECT * FROM subtasks WHERE id = ?').get(req.params.id);
  res.json({ subtask: updated });
}));

app.delete(`${BASE_PATH}/api/subtasks/:id`, requireAuth, asyncHandler(async (req, res) => {
  const subtask = db.prepare('SELECT s.*, t.user_id FROM subtasks s JOIN tasks t ON s.task_id = t.id WHERE s.id = ?').get(req.params.id);
  if (!subtask || subtask.user_id !== req.user.id) {
    return res.status(404).json({ error: 'زیرتسک یافت نشد' });
  }
  db.prepare('DELETE FROM subtasks WHERE id = ?').run(req.params.id);
  res.json({ success: true });
}));

app.get(`${BASE_PATH}/api/timers/task/:taskId`, requireAuth, asyncHandler(async (req, res) => {
  const timer = db.prepare('SELECT * FROM timers WHERE task_id = ? AND user_id = ?').get(req.params.taskId, req.user.id);
  res.json({ timer: timer || null });
}));

app.post(`${BASE_PATH}/api/timers`, requireAuth, asyncHandler(async (req, res) => {
  const { task_id } = req.body;
  if (!task_id) {
    return res.status(400).json({ error: 'شناسه تسک الزامی است' });
  }
  const task = db.prepare('SELECT id FROM tasks WHERE id = ? AND user_id = ?').get(task_id, req.user.id);
  if (!task) {
    return res.status(404).json({ error: 'تسک یافت نشد' });
  }
  let timer = db.prepare('SELECT * FROM timers WHERE task_id = ? AND user_id = ?').get(task_id, req.user.id);
  if (!timer) {
    const result = db.prepare('INSERT INTO timers (task_id, user_id) VALUES (?, ?)').run(task_id, req.user.id);
    timer = db.prepare('SELECT * FROM timers WHERE id = ?').get(result.lastInsertRowid);
  }
  res.json({ timer });
}));

app.post(`${BASE_PATH}/api/timers/:id/start`, requireAuth, asyncHandler(async (req, res) => {
  const timer = db.prepare('SELECT * FROM timers WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!timer) {
    return res.status(404).json({ error: 'تایمر یافت نشد' });
  }
  if (timer.is_running) {
    return res.status(400).json({ error: 'تایمر در حال اجرا است' });
  }
  const now = new Date().toISOString();
  db.prepare('UPDATE timers SET is_running = 1, started_at = ?, updated_at = datetime("now") WHERE id = ?').run(now, req.params.id);
  const updated = db.prepare('SELECT * FROM timers WHERE id = ?').get(req.params.id);
  res.json({ timer: updated });
}));

app.post(`${BASE_PATH}/api/timers/:id/stop`, requireAuth, asyncHandler(async (req, res) => {
  const timer = db.prepare('SELECT * FROM timers WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!timer) {
    return res.status(404).json({ error: 'تایمر یافت نشد' });
  }
  if (!timer.is_running) {
    return res.status(400).json({ error: 'تایمر در حال اجرا نیست' });
  }
  const now = new Date();
  const started = new Date(timer.started_at);
  const elapsed = Math.floor((now - started) / 1000);
  const newDuration = timer.duration + elapsed;
  db.prepare('UPDATE timers SET is_running = 0, duration = ?, started_at = NULL, updated_at = datetime("now") WHERE id = ?').run(newDuration, req.params.id);
  const updated = db.prepare('SELECT * FROM timers WHERE id = ?').get(req.params.id);
  notifyTimerComplete(timer.task_id, req.user.id);
  res.json({ timer: updated });
}));

app.post(`${BASE_PATH}/api/timers/:id/reset`, requireAuth, asyncHandler(async (req, res) => {
  const timer = db.prepare('SELECT * FROM timers WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!timer) {
    return res.status(404).json({ error: 'تایمر یافت نشد' });
  }
  db.prepare('UPDATE timers SET duration = 0, is_running = 0, started_at = NULL, updated_at = datetime("now") WHERE id = ?').run(req.params.id);
  const updated = db.prepare('SELECT * FROM timers WHERE id = ?').get(req.params.id);
  res.json({ timer: updated });
}));

app.get(`${BASE_PATH}/api/notifications`, requireAuth, asyncHandler(async (req, res) => {
  const { unread_only } = req.query;
  let query = 'SELECT * FROM notifications WHERE user_id = ?';
  const params = [req.user.id];
  if (unread_only === 'true') {
    query += ' AND is_read = 0';
  }
  query += ' ORDER BY created_at DESC LIMIT 50';
  const notifications = db.prepare(query).all(...params);
  res.json({ notifications });
}));

app.put(`${BASE_PATH}/api/notifications/:id/read`, requireAuth, asyncHandler(async (req, res) => {
  const result = db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (result.changes === 0) {
    return res.status(404).json({ error: 'اعلان یافت نشد' });
  }
  res.json({ success: true });
}));

app.put(`${BASE_PATH}/api/notifications/read-all`, requireAuth, asyncHandler(async (req, res) => {
  db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(req.user.id);
  res.json({ success: true });
}));

app.get(`${BASE_PATH}/api/stats`, requireAuth, asyncHandler(async (req, res) => {
  const stats = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
      SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
      SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
      SUM(CASE WHEN due_date IS NOT NULL AND due_date <= datetime("now") AND status != 'completed' THEN 1 ELSE 0 END) as overdue
    FROM tasks WHERE user_id = ?
  `).get(req.user.id);
  const unreadNotifications = db.prepare('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0').get(req.user.id);
  res.json({ stats, unreadNotifications: unreadNotifications.count });
}));

const publicDir = path.join(APP_DIR, 'public');
app.use(`${BASE_PATH}/assets`, express.static(publicDir, { maxAge: '1d', etag: true }));

const indexHtml = fs.readFileSync(path.join(publicDir, 'index.html'), 'utf-8');

function sendIndex(req, res) {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(indexHtml.replace(/__BASE_PATH__/g, BASE_PATH));
}

app.get('/', (req, res) => {
  res.redirect(302, `${BASE_PATH}/`);
});

app.get(BASE_PATH, sendIndex);
app.get(`${BASE_PATH}/`, sendIndex);
app.get(`${BASE_PATH}/*`, sendIndex);

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'خطای سرور داخلی', code: 'INTERNAL_ERROR' });
});

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, HOST, () => {
  console.log(`Server running on http://${HOST}:${PORT}${BASE_PATH}`);
  setInterval(cleanupExpiredSessions, 60 * 60 * 1000);
});

process.on('SIGTERM', () => {
  db.close();
  process.exit(0);
});