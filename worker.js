// ============================================================
// رفيق API - المرحلة 5: Auth + Users + Posts + Friends + Messages
// ============================================================

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status: status,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
    });
}

function generateId(length = 10) {
    const chars = '0123456789';
    let id = '';
    for (let i = 0; i < length; i++) {
        id += chars[Math.floor(Math.random() * chars.length)];
    }
    return id;
}

function generateToken() {
    return crypto.randomUUID();
}

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + 'rafeeq-salt-2025');
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyToken(request, env) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
    const token = authHeader.replace('Bearer ', '');
    const session = await env.DB.prepare(
        'SELECT * FROM sessions WHERE token = ? AND expires_at > ?'
    ).bind(token, Math.floor(Date.now() / 1000)).first();
    if (!session) return null;
    const user = await env.DB.prepare(
        'SELECT * FROM users WHERE uid = ?'
    ).bind(session.user_uid).first();
    return user || null;
}

function formatUser(user) {
    return {
        uid: user.uid, email: user.email, name: user.name,
        shareableId: user.shareable_id, avatarType: user.avatar_type,
        bio: user.bio, walletBalance: user.wallet_balance,
        isVerified: user.is_verified === 1, isBanned: user.is_banned === 1,
        friendsCount: user.friends_count, createdAt: user.created_at,
        lastSeen: user.last_seen
    };
}

function formatPost(post) {
    return {
        id: post.id, type: post.type, userId: post.user_id,
        name: post.name, age: post.age, country: post.country,
        countryCode: post.country_code, category: post.category,
        jobTitle: post.job_title, bio: post.bio, married: post.married,
        children: post.children, image: post.image,
        contactMethod: post.contact_method, contactValue: post.contact_value,
        isPaid: post.is_paid === 1, isPriority: post.is_priority === 1,
        views: post.views, clicks: post.clicks, createdAt: post.created_at
    };
}

function formatMessage(m) {
    return {
        id: m.id, fromUid: m.from_uid, toUid: m.to_uid,
        package: m.package, isRead: m.is_read === 1,
        createdAt: m.created_at, expiresAt: m.expires_at
    };
}

export default {
    async fetch(request, env) {
        if (request.method === 'OPTIONS') {
            return new Response(null, {
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
                }
            });
        }
        
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;
        const now = Math.floor(Date.now() / 1000);
        
        try {
            // ==================== AUTH ROUTES ====================
            
            if (path === '/api/auth/register' && method === 'POST') {
                const { email, password, name } = await request.json();
                if (!email || !password || !name) return jsonResponse({ error: 'جميع الحقول مطلوبة' }, 400);
                if (name.length > 15) return jsonResponse({ error: 'الاسم لا يزيد عن 15 حرف' }, 400);
                
                const existing = await env.DB.prepare('SELECT uid FROM users WHERE email = ?').bind(email).first();
                if (existing) return jsonResponse({ error: 'الإيميل مستخدم مسبقاً' }, 400);
                
                const uid = generateToken();
                const shareableId = generateId(10);
                await env.DB.prepare(
                    `INSERT INTO users (uid, email, name, shareable_id, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?)`
                ).bind(uid, email, name, shareableId, now, now).run();
                
                const token = generateToken();
                const expiresAt = now + (30 * 24 * 60 * 60);
                await env.DB.prepare(
                    `INSERT INTO sessions (token, user_uid, created_at, expires_at) VALUES (?, ?, ?, ?)`
                ).bind(token, uid, now, expiresAt).run();
                
                await env.DB.prepare(`UPDATE stats SET value = value + 1, updated_at = ? WHERE key = 'total_users'`).bind(now).run();
                
                return jsonResponse({ success: true, token: token, user: { uid, email, name, shareableId } });
            }
            
            if (path === '/api/auth/login' && method === 'POST') {
                const { email, password } = await request.json();
                if (!email || !password) return jsonResponse({ error: 'الإيميل وكلمة المرور مطلوبان' }, 400);
                
                const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
                if (!user) return jsonResponse({ error: 'الإيميل أو كلمة المرور غير صحيحة' }, 401);
                
                await env.DB.prepare('UPDATE users SET last_seen = ? WHERE uid = ?').bind(now, user.uid).run();
                
                const token = generateToken();
                const expiresAt = now + (30 * 24 * 60 * 60);
                await env.DB.prepare(
                    `INSERT INTO sessions (token, user_uid, created_at, expires_at) VALUES (?, ?, ?, ?)`
                ).bind(token, user.uid, now, expiresAt).run();
                
                return jsonResponse({ success: true, token: token, user: formatUser(user) });
            }
            
            if (path === '/api/auth/google' && method === 'POST') {
                const { googleId, email, name } = await request.json();
                if (!googleId || !email) return jsonResponse({ error: 'بيانات Google مطلوبة' }, 400);
                
                let user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
                
                if (!user) {
                    const uid = generateToken();
                    const shareableId = generateId(10);
                    const shortName = (name || 'مستخدم').substring(0, 15);
                    await env.DB.prepare(
                        `INSERT INTO users (uid, email, name, shareable_id, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?)`
                    ).bind(uid, email, shortName, shareableId, now, now).run();
                    user = await env.DB.prepare('SELECT * FROM users WHERE uid = ?').bind(uid).first();
                    await env.DB.prepare(`UPDATE stats SET value = value + 1, updated_at = ? WHERE key = 'total_users'`).bind(now).run();
                } else {
                    await env.DB.prepare('UPDATE users SET last_seen = ? WHERE uid = ?').bind(now, user.uid).run();
                }
                
                const token = generateToken();
                const expiresAt = now + (30 * 24 * 60 * 60);
                await env.DB.prepare(
                    `INSERT INTO sessions (token, user_uid, created_at, expires_at) VALUES (?, ?, ?, ?)`
                ).bind(token, user.uid, now, expiresAt).run();
                
                return jsonResponse({ success: true, token: token, user: formatUser(user) });
            }
            
            if (path === '/api/auth/me' && method === 'GET') {
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                return jsonResponse({ success: true, user: formatUser(user) });
            }
            
            if (path === '/api/auth/logout' && method === 'POST') {
                const authHeader = request.headers.get('Authorization');
                if (authHeader && authHeader.startsWith('Bearer ')) {
                    const token = authHeader.replace('Bearer ', '');
                    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
                }
                return jsonResponse({ success: true });
            }
            
            // ==================== USERS ROUTES ====================
            
            if (path.startsWith('/api/users/search/') && method === 'GET') {
                const shareableId = path.replace('/api/users/search/', '');
                const user = await env.DB.prepare('SELECT * FROM users WHERE shareable_id = ?').bind(shareableId).first();
                if (!user) return jsonResponse({ error: 'لا يوجد مستخدم بهذا ID' }, 404);
                return jsonResponse({ success: true, user: formatUser(user) });
            }
            
            if (path === '/api/users/me/friends' && method === 'GET') {
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                
                const friends = await env.DB.prepare(
                    `SELECT u.uid, u.name, u.shareable_id, u.avatar_type, u.bio, u.last_seen
                     FROM friends f JOIN users u ON f.friend_uid = u.uid
                     WHERE f.user_uid = ? ORDER BY u.name`
                ).bind(user.uid).all();
                
                return jsonResponse({
                    success: true,
                    friends: friends.results.map(f => ({
                        uid: f.uid, name: f.name, shareableId: f.shareable_id,
                        avatarType: f.avatar_type, bio: f.bio, lastSeen: f.last_seen
                    }))
                });
            }
            
            if (path === '/api/users/me' && method === 'DELETE') {
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                await env.DB.prepare('DELETE FROM users WHERE uid = ?').bind(user.uid).run();
                await env.DB.prepare('DELETE FROM sessions WHERE user_uid = ?').bind(user.uid).run();
                return jsonResponse({ success: true });
            }
            
            if (path.startsWith('/api/users/') && method === 'GET' && !path.includes('/search') && !path.includes('/me')) {
                const uid = path.replace('/api/users/', '');
                const user = await env.DB.prepare('SELECT * FROM users WHERE uid = ?').bind(uid).first();
                if (!user) return jsonResponse({ error: 'المستخدم غير موجود' }, 404);
                return jsonResponse({ success: true, user: formatUser(user) });
            }
            
            if (path.startsWith('/api/users/') && method === 'PUT') {
                const uid = path.replace('/api/users/', '');
                const currentUser = await verifyToken(request, env);
                if (!currentUser) return jsonResponse({ error: 'غير مصرح' }, 401);
                if (currentUser.uid !== uid && currentUser.is_admin !== 1) return jsonResponse({ error: 'لا يمكنك تعديل مستخدم آخر' }, 403);
                
                const { name, bio, avatarType } = await request.json();
                const updates = [];
                const values = [];
                
                if (name && name.length <= 15) { updates.push('name = ?'); values.push(name); }
                if (bio !== undefined) { updates.push('bio = ?'); values.push(bio); }
                if (avatarType) { updates.push('avatar_type = ?'); values.push(avatarType); }
                if (updates.length === 0) return jsonResponse({ error: 'لا توجد تغييرات' }, 400);
                
                values.push(uid);
                await env.DB.prepare(`UPDATE users SET ${updates.join(', ')} WHERE uid = ?`).bind(...values).run();
                return jsonResponse({ success: true });
            }
            
            // ==================== POSTS ROUTES ====================
            
            if (path === '/api/posts' && method === 'GET') {
                const type = url.searchParams.get('type') || '';
                const country = url.searchParams.get('country') || '';
                const category = url.searchParams.get('category') || '';
                const limit = Math.min(parseInt(url.searchParams.get('limit')) || 20, 50);
                const offset = parseInt(url.searchParams.get('offset')) || 0;
                
                let query = 'SELECT * FROM posts WHERE 1=1';
                const params = [];
                if (type) { query += ' AND type = ?'; params.push(type); }
                if (country) { query += ' AND country_code = ?'; params.push(country); }
                if (category && category !== 'all') { query += ' AND category = ?'; params.push(category); }
                query += ' ORDER BY is_priority DESC, created_at DESC LIMIT ? OFFSET ?';
                params.push(limit, offset);
                
                const posts = await env.DB.prepare(query).bind(...params).all();
                
                let countQuery = 'SELECT COUNT(*) as total FROM posts WHERE 1=1';
                const countParams = [];
                if (type) { countQuery += ' AND type = ?'; countParams.push(type); }
                if (country) { countQuery += ' AND country_code = ?'; countParams.push(country); }
                if (category && category !== 'all') { countQuery += ' AND category = ?'; countParams.push(category); }
                const countResult = await env.DB.prepare(countQuery).bind(...countParams).first();
                
                return jsonResponse({
                    success: true, posts: posts.results.map(formatPost),
                    total: countResult.total, hasMore: (offset + limit) < countResult.total
                });
            }
            
            if (path === '/api/posts' && method === 'POST') {
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                
                const body = await request.json();
                const { type, name, age, country, countryCode, category, jobTitle, bio, married, children, contactMethod, contactValue, image } = body;
                
                if (!type || !name || !age || !countryCode) return jsonResponse({ error: 'الحقول الأساسية مطلوبة' }, 400);
                if (type !== 'job' && type !== 'marriage') return jsonResponse({ error: 'نوع المنشور غير صحيح' }, 400);
                if (age < 18 || age > 99) return jsonResponse({ error: 'العمر بين 18 و 99' }, 400);
                if (name.length > 15) return jsonResponse({ error: 'الاسم لا يزيد عن 15 حرف' }, 400);
                if (type === 'job' && (!jobTitle || !category)) return jsonResponse({ error: 'العنوان والقسم مطلوبان للوظيفة' }, 400);
                
                const postId = generateToken();
                await env.DB.prepare(
                    `INSERT INTO posts (id, type, user_id, name, age, country, country_code, category, job_title, bio, married, children, image, contact_method, contact_value, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
                ).bind(postId, type, user.uid, name, age, country || '', countryCode, category || '', jobTitle || '', bio || '', married || '', children || '', image || '', contactMethod || 'none', contactValue || '', now).run();
                
                await env.DB.prepare(`UPDATE stats SET value = value + 1, updated_at = ? WHERE key = 'total_posts'`).bind(now).run();
                return jsonResponse({ success: true, postId: postId, message: 'تم نشر المنشور بنجاح' });
            }
            
            if (path === '/api/posts/my/posts' && method === 'GET') {
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                const posts = await env.DB.prepare('SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC').bind(user.uid).all();
                return jsonResponse({ success: true, posts: posts.results.map(formatPost) });
            }
            
            if (path.startsWith('/api/posts/') && method === 'GET' && !path.includes('/my/')) {
                const postId = path.replace('/api/posts/', '');
                const post = await env.DB.prepare('SELECT * FROM posts WHERE id = ?').bind(postId).first();
                if (!post) return jsonResponse({ error: 'المنشور غير موجود' }, 404);
                return jsonResponse({ success: true, post: formatPost(post) });
            }
            
            if (path.startsWith('/api/posts/') && method === 'DELETE') {
                const postId = path.replace('/api/posts/', '');
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                
                const post = await env.DB.prepare('SELECT * FROM posts WHERE id = ?').bind(postId).first();
                if (!post) return jsonResponse({ error: 'المنشور غير موجود' }, 404);
                if (post.user_id !== user.uid && user.is_admin !== 1) return jsonResponse({ error: 'لا يمكنك حذف هذا المنشور' }, 403);
                
                await env.DB.prepare('DELETE FROM posts WHERE id = ?').bind(postId).run();
                return jsonResponse({ success: true, message: 'تم حذف المنشور' });
            }
            
            if (path.startsWith('/api/posts/') && path.endsWith('/view') && method === 'POST') {
                const postId = path.replace('/api/posts/', '').replace('/view', '');
                const post = await env.DB.prepare('SELECT * FROM posts WHERE id = ?').bind(postId).first();
                if (!post) return jsonResponse({ error: 'المنشور غير موجود' }, 404);
                await env.DB.prepare('UPDATE posts SET views = views + 1 WHERE id = ?').bind(postId).run();
                return jsonResponse({ success: true, views: (post.views || 0) + 1 });
            }
            
            // ==================== FRIENDS ROUTES ====================
            
            if (path === '/api/friends/request' && method === 'POST') {
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                
                const { targetId } = await request.json();
                if (!targetId) return jsonResponse({ error: 'targetId مطلوب' }, 400);
                if (targetId === user.uid) return jsonResponse({ error: 'لا يمكنك إرسال طلب لنفسك' }, 400);
                
                const target = await env.DB.prepare('SELECT uid FROM users WHERE uid = ?').bind(targetId).first();
                if (!target) return jsonResponse({ error: 'المستخدم غير موجود' }, 404);
                
                const alreadyFriends = await env.DB.prepare('SELECT 1 FROM friends WHERE user_uid = ? AND friend_uid = ?').bind(user.uid, targetId).first();
                if (alreadyFriends) return jsonResponse({ error: 'أنتم أصدقاء بالفعل' }, 400);
                
                const existingRequest = await env.DB.prepare(
                    `SELECT id FROM friend_requests WHERE from_uid = ? AND to_uid = ? AND status = 'pending'`
                ).bind(user.uid, targetId).first();
                if (existingRequest) return jsonResponse({ error: 'أرسلت طلباً مسبقاً' }, 400);
                
                const reverseRequest = await env.DB.prepare(
                    `SELECT id FROM friend_requests WHERE from_uid = ? AND to_uid = ? AND status = 'pending'`
                ).bind(targetId, user.uid).first();
                if (reverseRequest) return jsonResponse({ error: 'لديك طلب من هذا المستخدم' }, 400);
                
                const requestId = generateToken();
                const expiresAt = now + (24 * 60 * 60);
                await env.DB.prepare(
                    `INSERT INTO friend_requests (id, from_uid, to_uid, status, created_at, expires_at) VALUES (?, ?, ?, 'pending', ?, ?)`
                ).bind(requestId, user.uid, targetId, now, expiresAt).run();
                
                return jsonResponse({ success: true, requestId: requestId, message: 'تم إرسال طلب الصداقة' });
            }
            
            if (path === '/api/friends/requests' && method === 'GET') {
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                
                const requests = await env.DB.prepare(
                    `SELECT fr.id, fr.from_uid, fr.created_at, u.name, u.shareable_id, u.avatar_type, u.bio
                     FROM friend_requests fr JOIN users u ON fr.from_uid = u.uid
                     WHERE fr.to_uid = ? AND fr.status = 'pending' ORDER BY fr.created_at DESC`
                ).bind(user.uid).all();
                
                return jsonResponse({
                    success: true,
                    requests: requests.results.map(r => ({
                        id: r.id, fromUid: r.from_uid, name: r.name,
                        shareableId: r.shareable_id, avatarType: r.avatar_type,
                        bio: r.bio, createdAt: r.created_at
                    }))
                });
            }
            
            if (path === '/api/friends/requests/sent' && method === 'GET') {
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                
                const requests = await env.DB.prepare(
                    `SELECT fr.id, fr.to_uid, fr.created_at, u.name, u.shareable_id, u.avatar_type
                     FROM friend_requests fr JOIN users u ON fr.to_uid = u.uid
                     WHERE fr.from_uid = ? AND fr.status = 'pending' ORDER BY fr.created_at DESC`
                ).bind(user.uid).all();
                
                return jsonResponse({
                    success: true,
                    requests: requests.results.map(r => ({
                        id: r.id, toUid: r.to_uid, name: r.name,
                        shareableId: r.shareable_id, avatarType: r.avatar_type,
                        createdAt: r.created_at
                    }))
                });
            }
            
            if (path.startsWith('/api/friends/accept/') && method === 'POST') {
                const requestId = path.replace('/api/friends/accept/', '');
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                
                const request = await env.DB.prepare(
                    'SELECT * FROM friend_requests WHERE id = ? AND to_uid = ?'
                ).bind(requestId, user.uid).first();
                
                if (!request) return jsonResponse({ error: 'الطلب غير موجود' }, 404);
                if (request.status !== 'pending') return jsonResponse({ error: 'الطلب ليس معلقاً' }, 400);
                
                await env.DB.prepare('DELETE FROM friend_requests WHERE id = ?').bind(requestId).run();
                await env.DB.prepare('INSERT INTO friends (user_uid, friend_uid, created_at) VALUES (?, ?, ?)').bind(user.uid, request.from_uid, now).run();
                await env.DB.prepare('INSERT INTO friends (user_uid, friend_uid, created_at) VALUES (?, ?, ?)').bind(request.from_uid, user.uid, now).run();
                await env.DB.prepare('UPDATE users SET friends_count = friends_count + 1 WHERE uid IN (?, ?)').bind(user.uid, request.from_uid).run();
                
                return jsonResponse({ success: true, message: 'تم قبول طلب الصداقة' });
            }
            
            if (path.startsWith('/api/friends/reject/') && method === 'POST') {
                const requestId = path.replace('/api/friends/reject/', '');
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                
                const request = await env.DB.prepare(
                    'SELECT * FROM friend_requests WHERE id = ? AND to_uid = ?'
                ).bind(requestId, user.uid).first();
                if (!request) return jsonResponse({ error: 'الطلب غير موجود' }, 404);
                
                await env.DB.prepare('DELETE FROM friend_requests WHERE id = ?').bind(requestId).run();
                return jsonResponse({ success: true, message: 'تم رفض الطلب' });
            }
            
            if (path.startsWith('/api/friends/') && method === 'DELETE' && !path.includes('/requests')) {
                const friendUid = path.replace('/api/friends/', '');
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                if (!friendUid) return jsonResponse({ error: 'friendUid مطلوب' }, 400);
                
                await env.DB.prepare('DELETE FROM friends WHERE user_uid = ? AND friend_uid = ?').bind(user.uid, friendUid).run();
                await env.DB.prepare('DELETE FROM friends WHERE user_uid = ? AND friend_uid = ?').bind(friendUid, user.uid).run();
                await env.DB.prepare('UPDATE users SET friends_count = MAX(0, friends_count - 1) WHERE uid IN (?, ?)').bind(user.uid, friendUid).run();
                
                return jsonResponse({ success: true, message: 'تم حذف الصديق' });
            }
            
            // ==================== MESSAGES ROUTES ====================
            
            // 23. Get Conversations List
            if (path === '/api/messages/conversations' && method === 'GET') {
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                
                const conversations = await env.DB.prepare(
                    `SELECT 
                        CASE WHEN from_uid = ? THEN to_uid ELSE from_uid END as friend_uid,
                        MAX(created_at) as last_message_at,
                        COUNT(*) as message_count
                     FROM messages
                     WHERE (from_uid = ? OR to_uid = ?) 
                       AND (expires_at IS NULL OR expires_at > ?)
                     GROUP BY friend_uid
                     ORDER BY last_message_at DESC
                     LIMIT 50`
                ).bind(user.uid, user.uid, user.uid, now).all();
                
                const conversationsWithUsers = [];
                for (const conv of conversations.results) {
                    const friend = await env.DB.prepare(
                        'SELECT uid, name, shareable_id, avatar_type FROM users WHERE uid = ?'
                    ).bind(conv.friend_uid).first();
                    
                    if (friend) {
                        const unread = await env.DB.prepare(
                            'SELECT COUNT(*) as count FROM messages WHERE from_uid = ? AND to_uid = ? AND is_read = 0'
                        ).bind(conv.friend_uid, user.uid).first();
                        
                        conversationsWithUsers.push({
                            friendUid: conv.friend_uid,
                            friendName: friend.name,
                            friendShareableId: friend.shareable_id,
                            friendAvatarType: friend.avatar_type,
                            lastMessageAt: conv.last_message_at,
                            messageCount: conv.message_count,
                            unreadCount: unread?.count || 0
                        });
                    }
                }
                
                return jsonResponse({ success: true, conversations: conversationsWithUsers });
            }
            
            // 24. Get Messages with Friend
            if (path.startsWith('/api/messages/') && method === 'GET' && !path.includes('/conversations') && !path.includes('/mark-read')) {
                const friendId = path.replace('/api/messages/', '');
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                if (!friendId) return jsonResponse({ error: 'friendId مطلوب' }, 400);
                
                const limit = Math.min(parseInt(url.searchParams.get('limit')) || 50, 100);
                const offset = parseInt(url.searchParams.get('offset')) || 0;
                
                const messages = await env.DB.prepare(
                    `SELECT * FROM messages 
                     WHERE ((from_uid = ? AND to_uid = ?) OR (from_uid = ? AND to_uid = ?))
                       AND (expires_at IS NULL OR expires_at > ?)
                     ORDER BY created_at DESC
                     LIMIT ? OFFSET ?`
                ).bind(user.uid, friendId, friendId, user.uid, now, limit, offset).all();
                
                return jsonResponse({
                    success: true,
                    messages: messages.results.map(formatMessage).reverse()
                });
            }
            
            // 25. Send Message
            if (path === '/api/messages' && method === 'POST') {
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                
                const { toUid, package: pkg } = await request.json();
                if (!toUid || !pkg) return jsonResponse({ error: 'toUid و package مطلوبان' }, 400);
                
                const isFriend = await env.DB.prepare(
                    'SELECT 1 FROM friends WHERE user_uid = ? AND friend_uid = ?'
                ).bind(user.uid, toUid).first();
                
                if (!isFriend) return jsonResponse({ error: 'يمكنك المراسلة مع الأصدقاء فقط' }, 403);
                
                const target = await env.DB.prepare('SELECT uid FROM users WHERE uid = ?').bind(toUid).first();
                if (!target) return jsonResponse({ error: 'المستخدم غير موجود' }, 404);
                
                const messageId = generateToken();
                const expiresAt = now + (24 * 60 * 60);
                
                await env.DB.prepare(
                    `INSERT INTO messages (id, from_uid, to_uid, package, is_read, created_at, expires_at) VALUES (?, ?, ?, ?, 0, ?, ?)`
                ).bind(messageId, user.uid, toUid, pkg, now, expiresAt).run();
                
                await env.DB.prepare(`UPDATE stats SET value = value + 1, updated_at = ? WHERE key = 'total_messages'`).bind(now).run();
                
                return jsonResponse({ success: true, messageId: messageId, message: 'تم إرسال الرسالة' });
            }
            
            // 26. Mark Messages as Read
            if (path === '/api/messages/mark-read' && method === 'POST') {
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                
                const { friendId } = await request.json();
                if (!friendId) return jsonResponse({ error: 'friendId مطلوب' }, 400);
                
                const result = await env.DB.prepare(
                    `UPDATE messages SET is_read = 1 WHERE from_uid = ? AND to_uid = ? AND is_read = 0`
                ).bind(friendId, user.uid).run();
                
                return jsonResponse({ success: true, updatedCount: result.meta?.changes || 0 });
            }
            
            // 27. Delete Message
            if (path.startsWith('/api/messages/') && method === 'DELETE') {
                const messageId = path.replace('/api/messages/', '');
                const user = await verifyToken(request, env);
                if (!user) return jsonResponse({ error: 'غير مصرح' }, 401);
                
                const message = await env.DB.prepare('SELECT * FROM messages WHERE id = ?').bind(messageId).first();
                if (!message) return jsonResponse({ error: 'الرسالة غير موجودة' }, 404);
                
                if (message.from_uid !== user.uid && message.to_uid !== user.uid) {
                    return jsonResponse({ error: 'لا يمكنك حذف هذه الرسالة' }, 403);
                }
                
                await env.DB.prepare('DELETE FROM messages WHERE id = ?').bind(messageId).run();
                return jsonResponse({ success: true, message: 'تم حذف الرسالة' });
            }
            
            // ==================== DEFAULT ====================
            return jsonResponse({
                message: 'رفيق API',
                version: '1.0',
                endpoints: [
                    'POST /api/auth/register', 'POST /api/auth/login',
                    'POST /api/auth/google', 'GET /api/auth/me', 'POST /api/auth/logout',
                    'GET /api/users/:uid', 'PUT /api/users/:uid',
                    'GET /api/users/search/:id', 'GET /api/users/me/friends', 'DELETE /api/users/me',
                    'GET /api/posts', 'POST /api/posts', 'GET /api/posts/my/posts',
                    'GET /api/posts/:id', 'DELETE /api/posts/:id', 'POST /api/posts/:id/view',
                    'POST /api/friends/request', 'GET /api/friends/requests',
                    'GET /api/friends/requests/sent', 'POST /api/friends/accept/:id',
                    'POST /api/friends/reject/:id', 'DELETE /api/friends/:uid',
                    'GET  /api/messages/conversations', 'GET  /api/messages/:friendId',
                    'POST /api/messages', 'POST /api/messages/mark-read',
                    'DELETE /api/messages/:id'
                ]
            });
            
        } catch (error) {
            console.error('Error:', error);
            return jsonResponse({ error: 'حدث خطأ في السيرفر', details: error.message }, 500);
        }
    }
};
