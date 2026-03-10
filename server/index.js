require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const cors = require('cors');
const path = require('path');
const multer = require('multer');

const app = express();

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 минута
  max: 5,
  message: { error: 'Слишком много попыток. Подождите минуту.' },
  standardHeaders: true,
  legacyHeaders: false,
});
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 час
  max: 10,
  message: { error: 'Слишком много регистраций с этого IP.' },
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  message: { error: 'Слишком много запросов. Подождите.' },
});
app.use('/api/', apiLimiter);
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const JWT_SECRET = process.env.JWT_SECRET || 'xorze_secret_key_2024';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

const ADMIN_USERNAME = 'дима';
const adminMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { data: user } = await supabase.from('profiles').select('username').eq('id', decoded.id).single();
    if (!user || user.username !== ADMIN_USERNAME) return res.status(403).json({ error: 'Not admin' });
    req.user = decoded;
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// Auth middleware
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

// ========== AUTH ==========

app.post('/api/register', registerLimiter, async (req, res) => {
  const { username, password, display_name, phone, birthday } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const { data: existing } = await supabase.from('profiles').select('id').eq('username', username).single();
  if (existing) return res.status(400).json({ error: 'Username already taken' });

  const hash = await bcrypt.hash(password, 10);
  const { data, error } = await supabase.from('profiles').insert({
    username, password_hash: hash, display_name: display_name || username, status: 'online',
    phone: phone || null, birthday: birthday || null
  }).select().single();

  if (error) return res.status(500).json({ error: error.message });
  const token = jwt.sign({ id: data.id, username }, JWT_SECRET);
  res.json({ token, user: { id: data.id, username, display_name: data.display_name } });
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const { data: user } = await supabase.from('profiles').select('*').eq('username', username).single();
  if (!user) return res.status(400).json({ error: 'User not found' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(400).json({ error: 'Wrong password' });

  await supabase.from('profiles').update({ status: 'online' }).eq('id', user.id);
  const token = jwt.sign({ id: user.id, username }, JWT_SECRET);
  res.json({ token, user: { id: user.id, username, display_name: user.display_name, avatar_url: user.avatar_url } });
});

// ========== USERS ==========

app.get('/api/users/search', authMiddleware, async (req, res) => {
  const { q } = req.query;
  const { data } = await supabase.from('profiles').select('id, username, display_name, avatar_url, status')
    .ilike('username', `%${q}%`).neq('id', req.user.id).limit(10);
  res.json(data || []);
});

app.get('/api/users/me', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('profiles').select('id, username, display_name, avatar_url, status').eq('id', req.user.id).single();
  res.json(data);
});

// ========== CHATS ==========

app.get('/api/chats', authMiddleware, async (req, res) => {
  const { data: memberRows } = await supabase.from('chat_members').select('chat_id').eq('user_id', req.user.id);
  if (!memberRows?.length) return res.json([]);

  const chatIds = memberRows.map(r => r.chat_id);
  const { data: chats } = await supabase.from('chats').select('*').in('id', chatIds);

  const result = await Promise.all((chats || []).map(async chat => {
    const { data: members } = await supabase.from('chat_members')
      .select('user_id, profiles(id, username, display_name, avatar_url, status)').eq('chat_id', chat.id);
    const { data: lastMsg } = await supabase.from('messages').select('*, profiles(username, display_name)')
      .eq('chat_id', chat.id).order('created_at', { ascending: false }).limit(1);
    return { ...chat, members, last_message: lastMsg?.[0] || null };
  }));

  res.json(result);
});

app.post('/api/chats', authMiddleware, async (req, res) => {
  const { user_id, name, is_group, member_ids } = req.body;

  if (!is_group) {
    // Check if DM already exists
    const { data: myChats } = await supabase.from('chat_members').select('chat_id').eq('user_id', req.user.id);
    const { data: theirChats } = await supabase.from('chat_members').select('chat_id').eq('user_id', user_id);
    if (myChats && theirChats) {
      const myIds = myChats.map(c => c.chat_id);
      const theirIds = theirChats.map(c => c.chat_id);
      const common = myIds.find(id => theirIds.includes(id));
      if (common) {
        const { data: existingChat } = await supabase.from('chats').select('*').eq('id', common).eq('is_group', false).single();
        if (existingChat) return res.json(existingChat);
      }
    }
  }

  const { data: chat, error } = await supabase.from('chats').insert({ name: name || null, is_group: is_group || false }).select().single();
  if (error) return res.status(500).json({ error: error.message });

  const members = is_group ? [req.user.id, ...(member_ids || [])] : [req.user.id, user_id];
  await supabase.from('chat_members').insert(members.map(uid => ({ chat_id: chat.id, user_id: uid })));

  res.json(chat);
});

// ========== MESSAGES ==========

app.get('/api/chats/:chatId/messages', authMiddleware, async (req, res) => {
  const { chatId } = req.params;
  const { data } = await supabase.from('messages')
    .select('*, profiles(id, username, display_name, avatar_url), reactions(*)')
    .eq('chat_id', chatId).order('created_at', { ascending: true }).limit(100);
  res.json(data || []);
});

app.post('/api/chats/:chatId/messages', authMiddleware, async (req, res) => {
  const { content, file_url, file_type } = req.body;
  const { chatId } = req.params;

  const { data: msg, error } = await supabase.from('messages').insert({
    chat_id: chatId, sender_id: req.user.id, content, file_url, file_type
  }).select('*, profiles(id, username, display_name, avatar_url)').single();

  if (error) return res.status(500).json({ error: error.message });

  io.to(chatId).emit('new_message', msg);
  res.json(msg);
});

// ========== FILE UPLOAD ==========

app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });

  const ext = req.file.originalname.split('.').pop();
  const filename = `${Date.now()}_${Math.random().toString(36).slice(2)}.${ext}`;

  const { data, error } = await supabase.storage.from('xorze-files').upload(filename, req.file.buffer, {
    contentType: req.file.mimetype,
    upsert: true,
    cacheControl: '3600'
  });

  if (error) {
    console.error('Upload error:', error);
    return res.status(500).json({ error: error.message });
  }

  const { data: urlData } = supabase.storage.from('xorze-files').getPublicUrl(filename);
  const publicUrl = urlData.publicUrl;
  console.log('Uploaded file URL:', publicUrl);
  res.json({ url: publicUrl, type: req.file.mimetype.startsWith('image') ? 'image' : 'file', name: req.file.originalname });
});

// ========== UPDATE PROFILE ==========

app.patch('/api/users/me', authMiddleware, async (req, res) => {
  const { display_name, avatar_url, phone, birthday, current_password, new_password } = req.body;
  // Handle password change
  if (new_password) {
    const { data: user } = await supabase.from('profiles').select('password_hash').eq('id', req.user.id).single();
    const valid = await bcrypt.compare(current_password || '', user.password_hash);
    if (!valid) return res.status(400).json({ error: 'Неверный текущий пароль' });
    const hash = await bcrypt.hash(new_password, 10);
    await supabase.from('profiles').update({ password_hash: hash }).eq('id', req.user.id);
    return res.json({ success: true });
  }
  const updates = {};
  if (display_name) updates.display_name = display_name;
  if (avatar_url) updates.avatar_url = avatar_url;
  if (phone !== undefined) updates.phone = phone;
  if (birthday !== undefined) updates.birthday = birthday;
  const { data, error } = await supabase.from('profiles').update(updates).eq('id', req.user.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ========== DELETE ACCOUNT ==========

app.delete('/api/users/me', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  await supabase.from('reactions').delete().eq('user_id', userId);
  await supabase.from('messages').delete().eq('sender_id', userId);
  await supabase.from('chat_members').delete().eq('user_id', userId);
  await supabase.from('profiles').delete().eq('id', userId);
  res.json({ success: true });
});

// ========== EDIT MESSAGE ==========

app.patch('/api/messages/:msgId', authMiddleware, async (req, res) => {
  const { msgId } = req.params;
  const { content } = req.body;
  const { data: msg } = await supabase.from('messages').select('*').eq('id', msgId).single();
  if (!msg) return res.status(404).json({ error: 'Not found' });
  if (msg.sender_id !== req.user.id) return res.status(403).json({ error: 'Not your message' });
  const { data, error } = await supabase.from('messages').update({ content, edited: true }).eq('id', msgId).select().single();
  if (error) return res.status(500).json({ error: error.message });
  io.to(msg.chat_id).emit('message_edited', { message_id: msgId, content, chat_id: msg.chat_id });
  res.json(data);
});

// ========== DELETE MESSAGE ==========

app.delete('/api/messages/:msgId', authMiddleware, async (req, res) => {
  const { msgId } = req.params;
  const { data: msg, error } = await supabase.from('messages').select('*').eq('id', msgId).single();
  if (error || !msg) return res.status(404).json({ error: 'Message not found' });
  if (msg.sender_id !== req.user.id) return res.status(403).json({ error: 'Not your message' });
  await supabase.from('reactions').delete().eq('message_id', msgId);
  await supabase.from('messages').delete().eq('id', msgId);
  io.to(msg.chat_id).emit('message_deleted', { message_id: msgId, chat_id: msg.chat_id });
  res.json({ success: true });
});

// ========== REACTIONS ==========

app.post('/api/messages/:msgId/reactions', authMiddleware, async (req, res) => {
  const { emoji } = req.body;
  const { msgId } = req.params;

  const { data: existing } = await supabase.from('reactions').select('*').eq('message_id', msgId).eq('user_id', req.user.id).eq('emoji', emoji).single();

  if (existing) {
    await supabase.from('reactions').delete().eq('id', existing.id);
  } else {
    await supabase.from('reactions').insert({ message_id: msgId, user_id: req.user.id, emoji });
  }

  const { data: msg } = await supabase.from('messages').select('chat_id').eq('id', msgId).single();
  if (msg) {
    const { data: reactions } = await supabase.from('reactions').select('*').eq('message_id', msgId);
    io.to(msg.chat_id).emit('reactions_updated', { message_id: msgId, reactions });
  }
  res.json({ ok: true });
});

// ========== SOCKET.IO ==========

const onlineUsers = {};

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { next(new Error('Unauthorized')); }
});

io.on('connection', (socket) => {
  const userId = socket.user.id;
  onlineUsers[userId] = socket.id;

  supabase.from('profiles').update({ status: 'online' }).eq('id', userId);
  io.emit('user_status', { user_id: userId, status: 'online' });

  socket.on('join_chat', (chatId) => socket.join(chatId));
  socket.on('leave_chat', (chatId) => socket.leave(chatId));

  socket.on('typing', ({ chatId }) => socket.to(chatId).emit('typing', { user_id: userId, chatId }));
  socket.on('stop_typing', ({ chatId }) => socket.to(chatId).emit('stop_typing', { user_id: userId, chatId }));

  // WebRTC signaling
  socket.on('call_offer', async ({ to, offer, chatId, callType }) => {
    const { data: fromUser } = await supabase.from('profiles')
      .select('username, display_name, avatar_url').eq('id', userId).single();
    const targetSocket = onlineUsers[to];
    if (targetSocket) io.to(targetSocket).emit('call_offer', { from: userId, offer, chatId, callType, fromUser });
  });
  socket.on('call_answer', ({ to, answer }) => {
    const targetSocket = onlineUsers[to];
    if (targetSocket) io.to(targetSocket).emit('call_answer', { from: userId, answer });
  });
  socket.on('ice_candidate', ({ to, candidate }) => {
    const targetSocket = onlineUsers[to];
    if (targetSocket) io.to(targetSocket).emit('ice_candidate', { from: userId, candidate });
  });
  socket.on('call_end', ({ to }) => {
    const targetSocket = onlineUsers[to];
    if (targetSocket) io.to(targetSocket).emit('call_end', { from: userId });
  });

  socket.on('disconnect', () => {
    delete onlineUsers[userId];
    supabase.from('profiles').update({ status: 'offline' }).eq('id', userId);
    io.emit('user_status', { user_id: userId, status: 'offline' });
  });
});

// Serve frontend
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));

const PORT = process.env.PORT || 3000;
// ========== ADMIN ==========

app.get('/api/admin/users', adminMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('profiles')
    .select('id, username, display_name, avatar_url, status, phone, birthday, created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

app.get('/api/admin/stats', adminMiddleware, async (req, res) => {
  const { count: messages } = await supabase.from('messages').select('*', { count: 'exact', head: true });
  const { count: chats } = await supabase.from('chats').select('*', { count: 'exact', head: true });
  res.json({ messages, chats });
});

app.delete('/api/admin/users/:userId', adminMiddleware, async (req, res) => {
  const { userId } = req.params;
  await supabase.from('reactions').delete().eq('user_id', userId);
  await supabase.from('messages').delete().eq('sender_id', userId);
  await supabase.from('chat_members').delete().eq('user_id', userId);
  await supabase.from('profiles').delete().eq('id', userId);
  res.json({ success: true });
});

server.listen(PORT, () => console.log(`XORZE running on port ${PORT}`));
