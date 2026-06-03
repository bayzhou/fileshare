# -*- coding: utf-8 -*-
"""
内网文件传输工具 - 主应用程序
支持加密传输、文件/文本类型、群组管理、文件可视化浏览
"""

import os
import json
import uuid
import time
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import quote

from flask import (
    Flask, request, jsonify, send_file, redirect,
    url_for, render_template, session, flash, abort
)
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# ──────────────────────────── 配置加载 ────────────────────────────

def load_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)

CONFIG = load_config()

# ──────────────────────────── Flask 应用初始化 ────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, CONFIG['storage']['base_dir'])
DB_PATH = os.path.join(BASE_DIR, 'data.db')
MAX_FILE_SIZE = CONFIG['storage']['max_file_size_mb'] * 1024 * 1024

app = Flask(__name__)
app.secret_key = CONFIG['security']['secret_key']
app.permanent_session_lifetime = timedelta(hours=CONFIG['security']['session_lifetime_hours'])
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

os.makedirs(STORAGE_DIR, exist_ok=True)

def ensure_user_dir(username):
    """确保用户目录存在，返回用户目录路径"""
    # 使用用户名创建子目录，过滤非法字符
    safe_name = "".join(c for c in username if c.isalnum() or c in '-_').strip()
    if not safe_name:
        safe_name = username
    user_dir = os.path.join(STORAGE_DIR, safe_name)
    os.makedirs(user_dir, exist_ok=True)
    return '/' + safe_name + '/'

# ──────────────────────────── 数据库初始化 ────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            auto_download INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS groups (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            owner_id TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS group_members (
            group_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            joined_at TEXT DEFAULT (datetime('now','localtime')),
            PRIMARY KEY (group_id, user_id),
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            file_type TEXT DEFAULT 'file',
            content_text TEXT,
            upload_dir TEXT DEFAULT '/',
            uploader_id TEXT NOT NULL,
            is_encrypted INTEGER DEFAULT 0,
            encryption_key_hash TEXT,
            upload_time TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (uploader_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS file_visibility (
            file_id TEXT NOT NULL,
            user_id TEXT,
            group_id TEXT,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS download_logs (
            id TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            download_time TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS directories (
            id TEXT PRIMARY KEY,
            path TEXT UNIQUE NOT NULL,
            owner_id TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS dir_visibility (
            dir_path TEXT NOT NULL,
            user_id TEXT,
            group_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS upload_chunks (
            upload_id TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            chunk_data BLOB,
            PRIMARY KEY (upload_id, chunk_index)
        );

        CREATE INDEX IF NOT EXISTS idx_files_uploader ON files(uploader_id);
        CREATE INDEX IF NOT EXISTS idx_files_dir ON files(upload_dir);
        CREATE INDEX IF NOT EXISTS idx_fv_user ON file_visibility(user_id);
        CREATE INDEX IF NOT EXISTS idx_fv_group ON file_visibility(group_id);
        CREATE INDEX IF NOT EXISTS idx_fv_file ON file_visibility(file_id);
        CREATE INDEX IF NOT EXISTS idx_dv_path ON dir_visibility(dir_path);
    """)
    conn.commit()

    # 确保管理员账户存在
    admin_cfg = CONFIG['admin']
    existing = conn.execute("SELECT id FROM users WHERE username=?", (admin_cfg['username'],)).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO users (id, username, password_hash, is_admin) VALUES (?, ?, ?, 1)",
            (str(uuid.uuid4()), admin_cfg['username'], bcrypt.hashpw(admin_cfg['password'].encode(), bcrypt.gensalt()).decode())
        )
        conn.commit()
    conn.close()
    # 创建管理员目录
    ensure_user_dir(admin_cfg['username'])

# ──────────────────────────── 辅助函数 ────────────────────────────

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({"error": "请先登录"}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "请先登录"}), 401
        if not user['is_admin']:
            return jsonify({"error": "需要管理员权限"}), 403
        return f(*args, **kwargs)
    return decorated

def encrypt_data(data: bytes, password: str) -> bytes:
    """使用密码加密数据"""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    encrypted = f.encrypt(data)
    return salt + encrypted  # 前16字节是salt

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    """使用密码解密数据"""
    salt = encrypted_data[:16]
    actual_data = encrypted_data[16:]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    return f.decrypt(actual_data)

def hash_encryption_key(password: str) -> str:
    """生成加密密钥的哈希，用于验证密码"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_encryption_key(password: str, key_hash: str) -> bool:
    """验证加密密码"""
    return bcrypt.checkpw(password.encode(), key_hash.encode())

def safe_path(base: str, user_path: str) -> str:
    """防止路径遍历攻击"""
    target = os.path.normpath(os.path.join(base, user_path.lstrip('/')))
    if not target.startswith(os.path.normpath(base)):
        abort(403, "禁止访问")
    return target

def get_file_path(stored_name: str) -> str:
    return os.path.join(STORAGE_DIR, stored_name)

# ──────────────────────────── 页面路由 ────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('send_page'))
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('send_page'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    if not CONFIG['features']['allow_registration']:
        flash('注册功能已关闭', 'error')
        return redirect(url_for('login_page'))
    if 'user_id' in session:
        return redirect(url_for('send_page'))
    return render_template('register.html')

@app.route('/send')
@login_required
def send_page():
    return render_template('send.html', config={'max_size': CONFIG['storage']['max_file_size_mb']})

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/files')
@login_required
def files_page():
    return render_template('files.html')

@app.route('/groups')
@login_required
def groups_page():
    return render_template('groups.html')

@app.route('/admin')
@login_required
@admin_required
def admin_page():
    return render_template('admin.html')

# ──────────────────────────── API: 认证 ────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    if not user or not check_password(password, user['password_hash']):
        return jsonify({"error": "用户名或密码错误"}), 401

    session.permanent = True
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['is_admin'] = bool(user['is_admin'])

    return jsonify({
        "message": "登录成功",
        "user": {
            "id": user['id'],
            "username": user['username'],
            "is_admin": bool(user['is_admin'])
        }
    })

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    if not CONFIG['features']['allow_registration']:
        return jsonify({"error": "注册功能已关闭"}), 403

    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    confirm = data.get('confirm_password', '')

    if not username or len(username) < 2:
        return jsonify({"error": "用户名至少2个字符"}), 400
    if not password or len(password) < 4:
        return jsonify({"error": "密码至少4个字符"}), 400
    if password != confirm:
        return jsonify({"error": "两次密码不一致"}), 400

    conn = get_db()
    if conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
        conn.close()
        return jsonify({"error": "用户名已存在"}), 409

    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
        (user_id, username, hash_password(password))
    )
    conn.commit()
    conn.close()

    # 创建用户专属目录
    ensure_user_dir(username)

    return jsonify({"message": "注册成功，请登录"})

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({"message": "已退出登录"})

@app.route('/api/auth/me')
@login_required
def api_me():
    user = get_current_user()
    if not user:
        return jsonify({"error": "用户不存在"}), 404
    user_home = ensure_user_dir(user['username'])
    return jsonify({
        "id": user['id'],
        "username": user['username'],
        "is_admin": bool(user['is_admin']),
        "auto_download": bool(user['auto_download']),
        "home_dir": user_home
    })

# ──────────────────────────── API: 文件传输 ────────────────────────────

@app.route('/api/files/upload', methods=['POST'])
@login_required
def api_upload():
    user = get_current_user()
    file_type = request.form.get('file_type', 'file')
    encrypt_password = request.form.get('encrypt_password', '').strip()
    visible_to = request.form.get('visible_to', 'all')
    visible_users = request.form.get('visible_users', '')
    visible_groups = request.form.get('visible_groups', '')
    upload_dir = request.form.get('upload_dir', '/')

    if upload_dir and not upload_dir.startswith('/'):
        upload_dir = '/' + upload_dir

    conn = get_db()
    file_id = str(uuid.uuid4())
    stored_name = f"{file_id}_{int(time.time())}"

    if file_type == 'text':
        text_content = request.form.get('text_content', '')
        if not text_content:
            return jsonify({"error": "文本内容不能为空"}), 400

        original_name = request.form.get('text_title', '未命名文本') + '.txt'
        file_size = len(text_content.encode('utf-8'))

        actual_stored = stored_name + '.txt'
        file_path = get_file_path(actual_stored)

        data_to_write = text_content.encode('utf-8')
        is_encrypted = False
        enc_key_hash = None

        if encrypt_password:
            data_to_write = encrypt_data(data_to_write, encrypt_password)
            is_encrypted = True
            enc_key_hash = hash_encryption_key(encrypt_password)

        with open(file_path, 'wb') as f:
            f.write(data_to_write)

        conn.execute(
            """INSERT INTO files (id, original_name, stored_name, file_size, file_type,
               content_text, upload_dir, uploader_id, is_encrypted, encryption_key_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (file_id, original_name, actual_stored, file_size, 'text',
             text_content if not is_encrypted else '[加密内容]',
             upload_dir, user['id'], int(is_encrypted), enc_key_hash)
        )
    else:
        if 'file' not in request.files:
            return jsonify({"error": "请选择文件"}), 400

        uploaded = request.files['file']
        if not uploaded.filename:
            return jsonify({"error": "文件名为空"}), 400

        original_name = uploaded.filename
        ext = os.path.splitext(original_name)[1]
        actual_stored = stored_name + ext
        file_path = get_file_path(actual_stored)

        file_data = uploaded.read()
        file_size = len(file_data)
        is_encrypted = False
        enc_key_hash = None

        if encrypt_password:
            file_data = encrypt_data(file_data, encrypt_password)
            is_encrypted = True
            enc_key_hash = hash_encryption_key(encrypt_password)

        with open(file_path, 'wb') as f:
            f.write(file_data)

        conn.execute(
            """INSERT INTO files (id, original_name, stored_name, file_size, file_type,
               upload_dir, uploader_id, is_encrypted, encryption_key_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (file_id, original_name, actual_stored, file_size, 'file',
             upload_dir, user['id'], int(is_encrypted), enc_key_hash)
        )

    # 设置可见性
    if visible_to == 'all':
        # 对所有用户可见（不插入记录 = 所有人可见）
        pass
    elif visible_to == 'users' and visible_users:
        user_ids = [u.strip() for u in visible_users.split(',') if u.strip()]
        for uid in user_ids:
            conn.execute("INSERT OR IGNORE INTO file_visibility (file_id, user_id) VALUES (?, ?)",
                        (file_id, uid))
    elif visible_to == 'groups' and visible_groups:
        group_ids = [g.strip() for g in visible_groups.split(',') if g.strip()]
        for gid in group_ids:
            conn.execute("INSERT OR IGNORE INTO file_visibility (file_id, group_id) VALUES (?, ?)",
                        (file_id, gid))

    # 自动下载通知：标记需要自动下载的用户
    # （前端通过轮询 /api/files/new 检测新文件）

    conn.commit()
    conn.close()

    return jsonify({"message": "上传成功", "file_id": file_id, "file_name": original_name})

@app.route('/api/files/download/<file_id>', methods=['POST'])
@login_required
def api_download(file_id):
    user = get_current_user()
    conn = get_db()

    file_info = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not file_info:
        conn.close()
        return jsonify({"error": "文件不存在"}), 404

    # 检查权限
    if file_info['uploader_id'] != user['id']:
        visible = conn.execute(
            """SELECT 1 FROM file_visibility WHERE file_id=?
               AND (user_id=? OR group_id IN (SELECT group_id FROM group_members WHERE user_id=?))""",
            (file_id, user['id'], user['id'])
        ).fetchone()
        if not visible:
            # 检查是否是公开文件（无visibility记录）
            any_vis = conn.execute("SELECT 1 FROM file_visibility WHERE file_id=?", (file_id,)).fetchone()
            if any_vis:
                conn.close()
                return jsonify({"error": "无权下载此文件"}), 403

    # 记录下载
    conn.execute(
        "INSERT INTO download_logs (id, file_id, user_id) VALUES (?, ?, ?)",
        (str(uuid.uuid4()), file_id, user['id'])
    )
    conn.commit()
    conn.close()

    file_path = get_file_path(file_info['stored_name'])
    if not os.path.exists(file_path):
        return jsonify({"error": "文件不存在于服务器"}), 404

    # 处理加密文件
    if file_info['is_encrypted']:
        password = request.json.get('password', '') if request.is_json else request.form.get('password', '')
        if not password:
            return jsonify({"error": "此文件已加密，请提供解密密码", "need_password": True}), 400

        if not verify_encryption_key(password, file_info['encryption_key_hash']):
            return jsonify({"error": "解密密码错误"}), 403

        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = decrypt_data(encrypted_data, password)

            # 写入临时文件发送
            temp_path = file_path + '.tmp'
            with open(temp_path, 'wb') as f:
                f.write(decrypted_data)

            response = send_file(
                temp_path,
                as_attachment=True,
                download_name=file_info['original_name']
            )
            # 确保中文文件名正确编码
            encoded_name = quote(file_info['original_name'])
            response.headers['Content-Disposition'] = f"attachment; filename*=UTF-8''{encoded_name}"

            @response.call_on_close
            def cleanup():
                try:
                    os.remove(temp_path)
                except:
                    pass

            return response
        except Exception as e:
            return jsonify({"error": f"解密失败: {str(e)}"}), 500
    else:
        if file_info['file_type'] == 'text':
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return jsonify({"content": content, "filename": file_info['original_name']})
        else:
            response = send_file(
                file_path,
                as_attachment=True,
                download_name=file_info['original_name']
            )
            encoded_name = quote(file_info['original_name'])
            response.headers['Content-Disposition'] = f"attachment; filename*=UTF-8''{encoded_name}"
            return response

@app.route('/api/files/preview/<file_id>')
@login_required
def api_preview(file_id):
    """预览文件内容（文本类型）"""
    user = get_current_user()
    conn = get_db()

    file_info = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not file_info:
        conn.close()
        return jsonify({"error": "文件不存在"}), 404

    if file_info['file_type'] != 'text':
        conn.close()
        return jsonify({"error": "只能预览文本文件"}), 400

    if file_info['is_encrypted']:
        conn.close()
        return jsonify({"error": "加密文件需要下载后查看", "is_encrypted": True}), 403

    conn.close()
    return jsonify({
        "content": file_info['content_text'],
        "filename": file_info['original_name']
    })

@app.route('/api/files/delete/<file_id>', methods=['DELETE'])
@login_required
def api_delete_file(file_id):
    user = get_current_user()
    conn = get_db()

    file_info = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not file_info:
        conn.close()
        return jsonify({"error": "文件不存在"}), 404

    if file_info['uploader_id'] != user['id'] and not user['is_admin']:
        conn.close()
        return jsonify({"error": "无权删除此文件"}), 403

    # 删除物理文件
    file_path = get_file_path(file_info['stored_name'])
    if os.path.exists(file_path):
        os.remove(file_path)

    conn.execute("DELETE FROM files WHERE id=?", (file_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "文件已删除"})

@app.route('/api/dirs/delete', methods=['POST'])
@login_required
def api_delete_dir():
    """删除目录及其下所有文件和子目录"""
    user = get_current_user()
    data = request.get_json()
    dir_path = data.get('dir_path', '')

    if not dir_path or not dir_path.startswith('/'):
        return jsonify({"error": "无效的目录路径"}), 400

    if not dir_path.endswith('/'):
        dir_path += '/'

    conn = get_db()

    # 递归查找该目录及所有子目录下的文件
    all_files = conn.execute(
        "SELECT * FROM files WHERE upload_dir = ? OR upload_dir LIKE ?",
        (dir_path, dir_path + '%')
    ).fetchall()

    deleted_count = 0
    for f in all_files:
        # 检查权限
        if f['uploader_id'] != user['id'] and not user['is_admin']:
            continue
        # 删除物理文件
        file_path = get_file_path(f['stored_name'])
        if os.path.exists(file_path):
            os.remove(file_path)
        conn.execute("DELETE FROM files WHERE id=?", (f['id'],))
        conn.execute("DELETE FROM file_visibility WHERE file_id=?", (f['id'],))
        deleted_count += 1

    # 删除目录可见性记录
    conn.execute("DELETE FROM dir_visibility WHERE dir_path = ? OR dir_path LIKE ?",
                 (dir_path, dir_path + '%'))

    # 删除目录记录
    conn.execute("DELETE FROM directories WHERE path = ? OR path LIKE ?",
                 (dir_path, dir_path + '%'))

    conn.commit()
    conn.close()

    return jsonify({"message": f"目录已删除，共删除 {deleted_count} 个文件", "deleted_count": deleted_count})

@app.route('/api/files/list')
@login_required
def api_list_files():
    user = get_current_user()
    view_type = request.args.get('view', 'visible')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))

    conn = get_db()

    if view_type == 'sent':
        rows = conn.execute(
            """SELECT f.*, u.username as uploader_name
               FROM files f JOIN users u ON f.uploader_id = u.id
               WHERE f.uploader_id = ?
               ORDER BY f.upload_time DESC LIMIT ? OFFSET ?""",
            (user['id'], per_page, (page - 1) * per_page)
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT DISTINCT f.*, u.username as uploader_name
               FROM files f
               JOIN users u ON f.uploader_id = u.id
               WHERE f.uploader_id = ?
                  OR NOT EXISTS (SELECT 1 FROM file_visibility WHERE file_id = f.id)
                  OR f.id IN (SELECT file_id FROM file_visibility WHERE user_id = ?)
                  OR f.id IN (
                      SELECT fv.file_id FROM file_visibility fv
                      JOIN group_members gm ON fv.group_id = gm.group_id
                      WHERE gm.user_id = ?
                  )
               ORDER BY f.upload_time DESC LIMIT ? OFFSET ?""",
            (user['id'], user['id'], user['id'], per_page, (page - 1) * per_page)
        ).fetchall()

    files = []
    for row in rows:
        vis = conn.execute(
            "SELECT user_id, group_id FROM file_visibility WHERE file_id=?", (row['id'],)
        ).fetchall()

        vis_desc = "所有人"
        if vis:
            parts = []
            for v in vis:
                if v['user_id']:
                    u = conn.execute("SELECT username FROM users WHERE id=?", (v['user_id'],)).fetchone()
                    parts.append(f"@{u['username']}" if u else "@未知")
                elif v['group_id']:
                    g = conn.execute("SELECT name FROM groups WHERE id=?", (v['group_id'],)).fetchone()
                    parts.append(f"#{g['name']}" if g else "#未知")
            vis_desc = ", ".join(parts)

        files.append({
            "id": row['id'],
            "original_name": row['original_name'],
            "file_size": row['file_size'],
            "file_type": row['file_type'],
            "upload_dir": row['upload_dir'],
            "uploader_name": row['uploader_name'],
            "is_encrypted": bool(row['is_encrypted']),
            "upload_time": row['upload_time'],
            "visibility": vis_desc,
            "is_mine": row['uploader_id'] == user['id']
        })

    conn.close()
    return jsonify({"files": files, "page": page})

@app.route('/api/items/list')
@login_required
def api_list_items():
    """列出用户可见的顶层项目：单个文件 + 文件夹（不展开内部）"""
    user = get_current_user()
    view_type = request.args.get('view', 'visible')

    conn = get_db()
    user_home = ensure_user_dir(user['username'])  # e.g. /admin/

    items = []

    if view_type == 'sent':
        # 我发送的：我的目录下直接存储的文件 + 我创建的目录
        # 1) 直接存储在用户目录下的文件（不是子目录里的）
        files = conn.execute(
            """SELECT f.*, u.username as uploader_name
               FROM files f JOIN users u ON f.uploader_id = u.id
               WHERE f.uploader_id = ? AND f.upload_dir = ?
               ORDER BY f.upload_time DESC""",
            (user['id'], user_home)
        ).fetchall()

        # 2) 我创建的顶层目录
        dirs = conn.execute(
            """SELECT d.path, d.created_at
               FROM directories d
               WHERE d.owner_id = ?
               ORDER BY d.created_at DESC""",
            (user['id'],)
        ).fetchall()
    else:
        # 我可见的：直接存储在用户目录下的文件 + 可见的目录
        files = conn.execute(
            """SELECT DISTINCT f.*, u.username as uploader_name
               FROM files f JOIN users u ON f.uploader_id = u.id
               WHERE f.upload_dir = ?
                 AND (
                     f.uploader_id = ?
                     OR NOT EXISTS (SELECT 1 FROM file_visibility WHERE file_id = f.id)
                     OR f.id IN (SELECT file_id FROM file_visibility WHERE user_id = ?)
                     OR f.id IN (
                         SELECT fv.file_id FROM file_visibility fv
                         JOIN group_members gm ON fv.group_id = gm.group_id
                         WHERE gm.user_id = ?
                     )
                 )
               ORDER BY f.upload_time DESC""",
            (user_home, user['id'], user['id'], user['id'])
        ).fetchall()

        dirs = conn.execute(
            """SELECT DISTINCT d.path, d.created_at
               FROM directories d
               WHERE d.owner_id = ?
                  OR NOT EXISTS (SELECT 1 FROM dir_visibility WHERE dir_path = d.path)
                  OR d.path IN (SELECT dir_path FROM dir_visibility WHERE user_id = ?)
                  OR d.path IN (
                      SELECT dv.dir_path FROM dir_visibility dv
                      JOIN group_members gm ON dv.group_id = gm.group_id
                      WHERE gm.user_id = ?
                  )
               ORDER BY d.created_at DESC""",
            (user['id'], user['id'], user['id'])
        ).fetchall()

    # 处理文件
    for f in files:
        vis = conn.execute(
            "SELECT user_id, group_id FROM file_visibility WHERE file_id=?", (f['id'],)
        ).fetchall()
        vis_desc = "所有人"
        if vis:
            parts = []
            for v in vis:
                if v['user_id']:
                    u = conn.execute("SELECT username FROM users WHERE id=?", (v['user_id'],)).fetchone()
                    parts.append(f"@{u['username']}" if u else "@未知")
                elif v['group_id']:
                    g = conn.execute("SELECT name FROM groups WHERE id=?", (v['group_id'],)).fetchone()
                    parts.append(f"#{g['name']}" if g else "#未知")
            vis_desc = ", ".join(parts)

        items.append({
            "type": "file",
            "id": f['id'],
            "name": f['original_name'],
            "file_size": f['file_size'],
            "file_type": f['file_type'],
            "is_encrypted": bool(f['is_encrypted']),
            "uploader_name": f['uploader_name'],
            "visibility": vis_desc,
            "is_mine": f['uploader_id'] == user['id'],
            "upload_time": f['upload_time']
        })

    # 处理目录
    for d in dirs:
        dp = d['path']
        # 只取直接位于用户目录下的顶层目录（path 形如 /admin/xxx/）
        # 排除用户目录本身
        if dp == user_home:
            continue
        # 只取一级子目录（不包含更深的）
        rel = dp[len(user_home):].strip('/')
        if '/' in rel:
            continue

        stats = conn.execute(
            "SELECT COUNT(*) as cnt, COALESCE(SUM(file_size), 0) as total FROM files WHERE upload_dir = ? OR upload_dir LIKE ?",
            (dp, dp + '%')
        ).fetchone()

        vis = conn.execute(
            "SELECT user_id, group_id FROM dir_visibility WHERE dir_path=?", (dp,)
        ).fetchall()
        vis_desc = "所有人"
        if vis:
            parts = []
            for v in vis:
                if v['user_id']:
                    u = conn.execute("SELECT username FROM users WHERE id=?", (v['user_id'],)).fetchone()
                    parts.append(f"@{u['username']}" if u else "@未知")
                elif v['group_id']:
                    g = conn.execute("SELECT name FROM groups WHERE id=?", (v['group_id'],)).fetchone()
                    parts.append(f"#{g['name']}" if g else "#未知")
            vis_desc = ", ".join(parts)

        items.append({
            "type": "dir",
            "path": dp,
            "name": rel,
            "file_count": stats['cnt'],
            "total_size": stats['total'],
            "visibility": vis_desc,
            "is_mine": True,  # 目录创建者
            "created_at": d['created_at']
        })

    conn.close()
    return jsonify({"items": items})

@app.route('/api/files/download-batch', methods=['POST'])
@login_required
def api_download_batch():
    """批量下载文件，打包为 zip，保留目录结构"""
    import zipfile
    import io

    user = get_current_user()
    data = request.get_json()
    file_ids = data.get('file_ids', [])
    dir_paths = data.get('dir_paths', [])

    if not file_ids and not dir_paths:
        return jsonify({"error": "请选择文件或目录"}), 400

    conn = get_db()
    files_to_zip = []

    # 收集直接选中的文件
    for fid in file_ids:
        f = conn.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
        if f:
            files_to_zip.append({
                "stored_name": f['stored_name'],
                "original_name": f['original_name'],
                "archive_path": f['original_name'],  # 顶层文件不带目录
                "is_encrypted": bool(f['is_encrypted'])
            })

    # 收集目录下的文件
    for dp in dir_paths:
        dir_files = conn.execute(
            "SELECT * FROM files WHERE upload_dir = ? OR upload_dir LIKE ?",
            (dp, dp + '%')
        ).fetchall()
        dir_base = dp.rstrip('/')
        for f in dir_files:
            # 计算相对路径，保留目录结构
            file_dir = f['upload_dir']
            if file_dir.startswith(dir_base):
                rel_dir = file_dir[len(dir_base):].strip('/')
                if rel_dir:
                    archive_path = rel_dir + '/' + f['original_name']
                else:
                    archive_path = f['original_name']
            else:
                archive_path = f['original_name']

            # 用目录名作为顶层文件夹
            dir_name = dp.rstrip('/').split('/')[-1]
            archive_path = dir_name + '/' + archive_path

            files_to_zip.append({
                "stored_name": f['stored_name'],
                "original_name": f['original_name'],
                "archive_path": archive_path,
                "is_encrypted": bool(f['is_encrypted'])
            })

    conn.close()

    if not files_to_zip:
        return jsonify({"error": "没有可下载的文件"}), 400

    # 创建 zip
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for item in files_to_zip:
            file_path = get_file_path(item['stored_name'])
            if os.path.exists(file_path):
                zf.write(file_path, item['archive_path'])

    zip_buffer.seek(0)

    # 生成文件名
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    zip_name = f"download_{timestamp}.zip"

    from flask import Response
    response = Response(
        zip_buffer.getvalue(),
        mimetype='application/zip',
        headers={'Content-Disposition': f'attachment; filename={zip_name}'}
    )

    return response

@app.route('/api/files/new')
@login_required
def api_new_files():
    """检查新文件（用于自动下载通知）"""
    user = get_current_user()
    since = request.args.get('since', '')

    conn = get_db()
    query = """
        SELECT DISTINCT f.id, f.original_name, f.file_type, f.is_encrypted,
               f.upload_time, u.username as uploader_name
        FROM files f
        JOIN users u ON f.uploader_id = u.id
        WHERE f.uploader_id != ?
          AND f.upload_time > ?
          AND (
              NOT EXISTS (SELECT 1 FROM file_visibility WHERE file_id = f.id)
              OR f.id IN (SELECT file_id FROM file_visibility WHERE user_id = ?)
              OR f.id IN (
                  SELECT fv.file_id FROM file_visibility fv
                  JOIN group_members gm ON fv.group_id = gm.group_id
                  WHERE gm.user_id = ?
              )
          )
        ORDER BY f.upload_time DESC
    """
    rows = conn.execute(query, (user['id'], since, user['id'], user['id'])).fetchall()
    conn.close()

    new_files = [dict(r) for r in rows]
    return jsonify({"new_files": new_files, "count": len(new_files)})

@app.route('/api/files/move', methods=['POST'])
@login_required
def api_move_file():
    data = request.get_json()
    file_id = data.get('file_id')
    new_dir = data.get('new_dir', '/')

    if not new_dir.startswith('/'):
        new_dir = '/' + new_dir

    conn = get_db()
    file_info = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not file_info:
        conn.close()
        return jsonify({"error": "文件不存在"}), 404

    user = get_current_user()
    if file_info['uploader_id'] != user['id'] and not user['is_admin']:
        conn.close()
        return jsonify({"error": "无权移动此文件"}), 403

    conn.execute("UPDATE files SET upload_dir=? WHERE id=?", (new_dir, file_id))
    conn.commit()
    conn.close()

    return jsonify({"message": "移动成功"})

@app.route('/api/files/visibility', methods=['POST'])
@login_required
def api_update_visibility():
    """批量修改文件/目录的可见范围"""
    user = get_current_user()
    data = request.get_json()
    file_ids = data.get('file_ids', [])
    visible_to = data.get('visible_to', 'all')
    visible_users = data.get('visible_users', [])
    visible_groups = data.get('visible_groups', [])

    if not file_ids:
        return jsonify({"error": "请选择文件"}), 400

    conn = get_db()
    updated = 0

    for fid in file_ids:
        file_info = conn.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
        if not file_info:
            continue
        # 只有本人或管理员可修改
        if file_info['uploader_id'] != user['id'] and not user['is_admin']:
            continue

        # 删除旧的可见性记录
        conn.execute("DELETE FROM file_visibility WHERE file_id=?", (fid,))

        # 插入新的可见性记录
        if visible_to == 'users' and visible_users:
            for uid in visible_users:
                conn.execute("INSERT OR IGNORE INTO file_visibility (file_id, user_id) VALUES (?, ?)", (fid, uid))
        elif visible_to == 'groups' and visible_groups:
            for gid in visible_groups:
                conn.execute("INSERT OR IGNORE INTO file_visibility (file_id, group_id) VALUES (?, ?)", (fid, gid))
        # 'all' 不插入记录 = 所有人可见

        updated += 1

    conn.commit()
    conn.close()

    return jsonify({"message": f"已更新 {updated} 个文件的可见范围", "updated": updated})

@app.route('/api/files/visibility/<file_id>')
@login_required
def api_get_visibility(file_id):
    """获取单个文件的可见范围"""
    conn = get_db()
    vis = conn.execute(
        "SELECT user_id, group_id FROM file_visibility WHERE file_id=?", (file_id,)
    ).fetchall()
    conn.close()

    if not vis:
        return jsonify({"visible_to": "all", "users": [], "groups": []})

    users = [v['user_id'] for v in vis if v['user_id']]
    groups = [v['group_id'] for v in vis if v['group_id']]
    visible_to = 'users' if users else 'groups' if groups else 'all'

    return jsonify({"visible_to": visible_to, "users": users, "groups": groups})

# ──────────────────────────── API: 文件浏览 ────────────────────────────

@app.route('/api/browse')
@login_required
def api_browse():
    user = get_current_user()
    path = request.args.get('path', '/')

    if not path.startswith('/'):
        path = '/' + path

    conn = get_db()

    # 获取当前目录下的文件（包括当前目录本身存储的文件）
    files = conn.execute(
        """SELECT f.*, u.username as uploader_name
           FROM files f JOIN users u ON f.uploader_id = u.id
           WHERE f.upload_dir = ? OR f.upload_dir = ?
           ORDER BY f.upload_time DESC""",
        (path, path.rstrip('/') + '/')
    ).fetchall()

    # 获取子目录：从 directories 表 + 文件路径推导
    subdirs = set()
    norm_path = path.rstrip('/')  # 不带尾斜杠的路径

    # 从 directories 表获取
    db_dirs = conn.execute(
        "SELECT path FROM directories WHERE (path LIKE ? OR path LIKE ?) AND path != ? AND path != ?",
        (norm_path + '/%', norm_path + '/%/', path, path.rstrip('/') + '/')
    ).fetchall()
    for d in db_dirs:
        dp = d['path']
        if not dp.startswith(norm_path + '/'):
            continue
        relative = dp[len(norm_path):].strip('/')
        if relative and '/' not in relative:
            subdirs.add(relative)

    # 从文件路径推导
    file_dirs = conn.execute(
        "SELECT DISTINCT upload_dir FROM files WHERE (upload_dir LIKE ? OR upload_dir LIKE ?) AND upload_dir != ? AND upload_dir != ?",
        (norm_path + '/%', norm_path + '/%/', path, path.rstrip('/') + '/')
    ).fetchall()
    for d in file_dirs:
        ud = d['upload_dir']
        if not ud.startswith(norm_path + '/'):
            continue
        relative = ud[len(norm_path):].strip('/')
        if relative and '/' not in relative:
            subdirs.add(relative)

    # 获取子目录的可见性信息
    subdirs_info = []
    for sd in sorted(subdirs):
        sd_path = path.rstrip('/') + '/' + sd + '/'
        vis = conn.execute(
            "SELECT user_id, group_id FROM dir_visibility WHERE dir_path=?", (sd_path,)
        ).fetchall()
        vis_desc = "所有人"
        if vis:
            parts = []
            for v in vis:
                if v['user_id']:
                    u = conn.execute("SELECT username FROM users WHERE id=?", (v['user_id'],)).fetchone()
                    parts.append(f"@{u['username']}" if u else "@未知")
                elif v['group_id']:
                    g = conn.execute("SELECT name FROM groups WHERE id=?", (v['group_id'],)).fetchone()
                    parts.append(f"#{g['name']}" if g else "#未知")
            vis_desc = ", ".join(parts)
        subdirs_info.append({"name": sd, "visibility": vis_desc})

    # 获取当前目录自身的可见性
    cur_vis = conn.execute(
        "SELECT user_id, group_id FROM dir_visibility WHERE dir_path=?", (path,)
    ).fetchall()
    cur_vis_desc = "所有人"
    if cur_vis:
        parts = []
        for v in cur_vis:
            if v['user_id']:
                u = conn.execute("SELECT username FROM users WHERE id=?", (v['user_id'],)).fetchone()
                parts.append(f"@{u['username']}" if u else "@未知")
            elif v['group_id']:
                g = conn.execute("SELECT name FROM groups WHERE id=?", (v['group_id'],)).fetchone()
                parts.append(f"#{g['name']}" if g else "#未知")
        cur_vis_desc = ", ".join(parts)

    result = {
        "current_path": path,
        "current_visibility": cur_vis_desc,
        "subdirs": subdirs_info,
        "files": [{
            "id": f['id'],
            "original_name": f['original_name'],
            "file_size": f['file_size'],
            "file_type": f['file_type'],
            "is_encrypted": bool(f['is_encrypted']),
            "uploader_name": f['uploader_name'],
            "upload_time": f['upload_time']
        } for f in files]
    }

    conn.close()
    return jsonify(result)

@app.route('/api/browse/mkdir', methods=['POST'])
@login_required
def api_mkdir():
    user = get_current_user()
    data = request.get_json()
    parent = data.get('parent', '/')
    dirname = data.get('name', '').strip()

    if not dirname or '/' in dirname:
        return jsonify({"error": "无效的目录名"}), 400

    full_path = parent.rstrip('/') + '/' + dirname + '/'

    conn = get_db()
    # 写入 directories 表
    existing = conn.execute("SELECT id FROM directories WHERE path=?", (full_path,)).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO directories (id, path, owner_id) VALUES (?, ?, ?)",
            (str(uuid.uuid4()), full_path, user['id'])
        )
        conn.commit()
    conn.close()

    return jsonify({"message": "目录已创建", "path": full_path})

# ──────────────────────────── API: 目录可见性 ────────────────────────────

@app.route('/api/dirs/visibility', methods=['POST'])
@login_required
def api_update_dir_visibility():
    """设置目录可见范围"""
    user = get_current_user()
    data = request.get_json()
    dir_paths = data.get('dir_paths', [])
    visible_to = data.get('visible_to', 'all')
    visible_users = data.get('visible_users', [])
    visible_groups = data.get('visible_groups', [])

    if not dir_paths:
        return jsonify({"error": "请选择目录"}), 400

    conn = get_db()
    updated = 0

    for dp in dir_paths:
        # 确保目录记录存在
        existing = conn.execute("SELECT id FROM directories WHERE path=?", (dp,)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO directories (id, path, owner_id) VALUES (?, ?, ?)",
                (str(uuid.uuid4()), dp, user['id'])
            )

        # 删除旧的可见性
        conn.execute("DELETE FROM dir_visibility WHERE dir_path=?", (dp,))

        # 插入新的
        if visible_to == 'users' and visible_users:
            for uid in visible_users:
                conn.execute("INSERT OR IGNORE INTO dir_visibility (dir_path, user_id) VALUES (?, ?)", (dp, uid))
        elif visible_to == 'groups' and visible_groups:
            for gid in visible_groups:
                conn.execute("INSERT OR IGNORE INTO dir_visibility (dir_path, group_id) VALUES (?, ?)", (dp, gid))

        updated += 1

    conn.commit()
    conn.close()

    return jsonify({"message": f"已更新 {updated} 个目录的可见范围", "updated": updated})

@app.route('/api/dirs/visibility/<path:dir_path>')
@login_required
def api_get_dir_visibility(dir_path):
    """获取目录可见范围"""
    if not dir_path.startswith('/'):
        dir_path = '/' + dir_path
    if not dir_path.endswith('/'):
        dir_path += '/'

    conn = get_db()
    vis = conn.execute(
        "SELECT user_id, group_id FROM dir_visibility WHERE dir_path=?", (dir_path,)
    ).fetchall()
    conn.close()

    if not vis:
        return jsonify({"visible_to": "all", "users": [], "groups": []})

    users = [v['user_id'] for v in vis if v['user_id']]
    groups = [v['group_id'] for v in vis if v['group_id']]
    visible_to = 'users' if users else 'groups' if groups else 'all'

    return jsonify({"visible_to": visible_to, "users": users, "groups": groups})

# ──────────────────────────── API: 分片上传 ────────────────────────────

@app.route('/api/files/upload/init', methods=['POST'])
@login_required
def api_upload_init():
    """初始化分片上传，返回 upload_id"""
    data = request.get_json()
    filename = data.get('filename', '')
    total_size = data.get('total_size', 0)
    total_chunks = data.get('total_chunks', 1)

    if not filename:
        return jsonify({"error": "文件名为空"}), 400

    upload_id = str(uuid.uuid4())
    return jsonify({
        "upload_id": upload_id,
        "filename": filename,
        "total_chunks": total_chunks,
        "total_size": total_size
    })

@app.route('/api/files/upload/chunk', methods=['POST'])
@login_required
def api_upload_chunk():
    """上传单个分片"""
    upload_id = request.form.get('upload_id', '')
    chunk_index = int(request.form.get('chunk_index', 0))
    chunk_data = request.files.get('chunk')

    if not upload_id or chunk_data is None:
        return jsonify({"error": "参数缺失"}), 400

    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO upload_chunks (upload_id, chunk_index, chunk_data) VALUES (?, ?, ?)",
        (upload_id, chunk_index, chunk_data.read())
    )
    conn.commit()
    conn.close()

    return jsonify({"upload_id": upload_id, "chunk_index": chunk_index, "status": "ok"})

@app.route('/api/files/upload/complete', methods=['POST'])
@login_required
def api_upload_complete():
    """合并分片，完成上传"""
    user = get_current_user()
    data = request.get_json()
    upload_id = data.get('upload_id', '')
    filename = data.get('filename', '')
    total_chunks = data.get('total_chunks', 1)
    upload_dir = data.get('upload_dir', '/')
    visible_to = data.get('visible_to', 'all')
    visible_users = data.get('visible_users', '')
    visible_groups = data.get('visible_groups', '')
    encrypt_password = data.get('encrypt_password', '').strip()

    if not upload_dir.startswith('/'):
        upload_dir = '/' + upload_dir

    conn = get_db()

    # 读取所有分片并合并
    chunks = conn.execute(
        "SELECT chunk_data FROM upload_chunks WHERE upload_id=? ORDER BY chunk_index",
        (upload_id,)
    ).fetchall()

    if len(chunks) != total_chunks:
        conn.execute("DELETE FROM upload_chunks WHERE upload_id=?", (upload_id,))
        conn.commit()
        conn.close()
        return jsonify({"error": f"分片不完整: 收到 {len(chunks)}/{total_chunks}"}), 400

    file_data = b''.join(c['chunk_data'] for c in chunks)

    # 清理分片
    conn.execute("DELETE FROM upload_chunks WHERE upload_id=?", (upload_id,))

    # 存储文件
    file_id = str(uuid.uuid4())
    ext = os.path.splitext(filename)[1]
    stored_name = f"{file_id}_{int(time.time())}{ext}"
    file_path = get_file_path(stored_name)

    is_encrypted = False
    enc_key_hash = None

    if encrypt_password:
        file_data = encrypt_data(file_data, encrypt_password)
        is_encrypted = True
        enc_key_hash = hash_encryption_key(encrypt_password)

    with open(file_path, 'wb') as f:
        f.write(file_data)

    file_size = len(file_data)

    conn.execute(
        """INSERT INTO files (id, original_name, stored_name, file_size, file_type,
           upload_dir, uploader_id, is_encrypted, encryption_key_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (file_id, filename, stored_name, file_size, 'file',
         upload_dir, user['id'], int(is_encrypted), enc_key_hash)
    )

    # 设置可见性
    if visible_to == 'users' and visible_users:
        user_ids = [u.strip() for u in visible_users.split(',') if u.strip()]
        for uid in user_ids:
            conn.execute("INSERT OR IGNORE INTO file_visibility (file_id, user_id) VALUES (?, ?)", (file_id, uid))
    elif visible_to == 'groups' and visible_groups:
        group_ids = [g.strip() for g in visible_groups.split(',') if g.strip()]
        for gid in group_ids:
            conn.execute("INSERT OR IGNORE INTO file_visibility (file_id, group_id) VALUES (?, ?)", (file_id, gid))

    conn.commit()
    conn.close()

    return jsonify({"message": "上传成功", "file_id": file_id, "file_name": filename, "file_size": file_size})

@app.route('/api/files/upload/folder', methods=['POST'])
@login_required
def api_upload_folder():
    """文件夹上传：接收带相对路径的文件，自动创建目录结构"""
    user = get_current_user()
    files = request.files.getlist('files')
    relative_paths = request.form.get('relative_paths', '').split('|||')
    base_dir = request.form.get('upload_dir', '/')
    visible_to = request.form.get('visible_to', 'all')
    visible_users = request.form.get('visible_users', '')
    visible_groups = request.form.get('visible_groups', '')
    encrypt_password = request.form.get('encrypt_password', '').strip()

    if not base_dir.startswith('/'):
        base_dir = '/' + base_dir

    if not files:
        return jsonify({"error": "无文件"}), 400

    conn = get_db()
    created = []
    folder_name = ''

    for i, f in enumerate(files):
        rel_path = relative_paths[i] if i < len(relative_paths) else f.filename
        # 解析目录结构
        parts = rel_path.replace('\\', '/').split('/')
        if len(parts) > 1:
            folder_name = parts[0]
            # 创建所有中间目录（从顶层到底层）
            current = base_dir.rstrip('/')
            for j in range(len(parts) - 1):
                current = current + '/' + parts[j]
                dir_path = current + '/'
                existing = conn.execute("SELECT id FROM directories WHERE path=?", (dir_path,)).fetchone()
                if not existing:
                    conn.execute(
                        "INSERT INTO directories (id, path, owner_id) VALUES (?, ?, ?)",
                        (str(uuid.uuid4()), dir_path, user['id'])
                    )
            file_dir = current + '/'
        else:
            file_dir = base_dir

        # 存储文件
        file_id = str(uuid.uuid4())
        ext = os.path.splitext(f.filename)[1]
        stored_name = f"{file_id}_{int(time.time())}{ext}"
        file_path = get_file_path(stored_name)

        file_data = f.read()
        is_encrypted = False
        enc_key_hash = None

        if encrypt_password:
            file_data = encrypt_data(file_data, encrypt_password)
            is_encrypted = True
            enc_key_hash = hash_encryption_key(encrypt_password)

        with open(file_path, 'wb') as fp:
            fp.write(file_data)

        conn.execute(
            """INSERT INTO files (id, original_name, stored_name, file_size, file_type,
               upload_dir, uploader_id, is_encrypted, encryption_key_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (file_id, os.path.basename(f.filename), stored_name, len(file_data), 'file',
             file_dir, user['id'], int(is_encrypted), enc_key_hash)
        )

        # 设置可见性
        if visible_to == 'users' and visible_users:
            for uid in visible_users.split(','):
                uid = uid.strip()
                if uid:
                    conn.execute("INSERT OR IGNORE INTO file_visibility (file_id, user_id) VALUES (?, ?)", (file_id, uid))
        elif visible_to == 'groups' and visible_groups:
            for gid in visible_groups.split(','):
                gid = gid.strip()
                if gid:
                    conn.execute("INSERT OR IGNORE INTO file_visibility (file_id, group_id) VALUES (?, ?)", (file_id, gid))

        created.append(file_id)

    conn.commit()
    conn.close()

    return jsonify({
        "message": f"文件夹上传成功，共 {len(created)} 个文件",
        "file_count": len(created),
        "folder_name": folder_name
    })

# ──────────────────────────── API: 群组管理 ────────────────────────────

@app.route('/api/groups')
@login_required
def api_list_groups():
    user = get_current_user()
    conn = get_db()

    groups = conn.execute("""
        SELECT g.*, u.username as owner_name,
               (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count
        FROM groups g
        JOIN users u ON g.owner_id = u.id
        WHERE g.owner_id = ?
           OR g.id IN (SELECT group_id FROM group_members WHERE user_id = ?)
        ORDER BY g.created_at DESC
    """, (user['id'], user['id'])).fetchall()

    result = []
    for g in groups:
        members = conn.execute("""
            SELECT u.id, u.username
            FROM group_members gm JOIN users u ON gm.user_id = u.id
            WHERE gm.group_id = ?
        """, (g['id'],)).fetchall()

        result.append({
            "id": g['id'],
            "name": g['name'],
            "description": g['description'],
            "owner_name": g['owner_name'],
            "member_count": g['member_count'],
            "is_owner": g['owner_id'] == user['id'],
            "members": [{"id": m['id'], "username": m['username']} for m in members]
        })

    conn.close()
    return jsonify({"groups": result})

@app.route('/api/groups/create', methods=['POST'])
@login_required
def api_create_group():
    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    member_ids = data.get('member_ids', [])

    if not name:
        return jsonify({"error": "群组名称不能为空"}), 400

    user = get_current_user()
    conn = get_db()

    group_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO groups (id, name, description, owner_id) VALUES (?, ?, ?, ?)",
        (group_id, name, description, user['id'])
    )

    # 添加成员
    for mid in member_ids:
        conn.execute(
            "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)",
            (group_id, mid)
        )

    conn.commit()
    conn.close()

    return jsonify({"message": "群组创建成功", "group_id": group_id})

@app.route('/api/groups/<group_id>/update', methods=['POST'])
@login_required
def api_update_group(group_id):
    data = request.get_json()
    user = get_current_user()
    conn = get_db()

    group = conn.execute("SELECT * FROM groups WHERE id=?", (group_id,)).fetchone()
    if not group:
        conn.close()
        return jsonify({"error": "群组不存在"}), 404

    if group['owner_id'] != user['id'] and not user['is_admin']:
        conn.close()
        return jsonify({"error": "无权修改此群组"}), 403

    name = data.get('name', group['name']).strip()
    desc = data.get('description', group['description']).strip()

    conn.execute(
        "UPDATE groups SET name=?, description=? WHERE id=?",
        (name, desc, group_id)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "群组已更新"})

@app.route('/api/groups/<group_id>/delete', methods=['DELETE'])
@login_required
def api_delete_group(group_id):
    user = get_current_user()
    conn = get_db()

    group = conn.execute("SELECT * FROM groups WHERE id=?", (group_id,)).fetchone()
    if not group:
        conn.close()
        return jsonify({"error": "群组不存在"}), 404

    if group['owner_id'] != user['id'] and not user['is_admin']:
        conn.close()
        return jsonify({"error": "无权删除此群组"}), 403

    conn.execute("DELETE FROM groups WHERE id=?", (group_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "群组已删除"})

@app.route('/api/groups/<group_id>/members', methods=['POST'])
@login_required
def api_add_members(group_id):
    data = request.get_json()
    user_ids = data.get('user_ids', [])
    user = get_current_user()

    conn = get_db()
    group = conn.execute("SELECT * FROM groups WHERE id=?", (group_id,)).fetchone()
    if not group:
        conn.close()
        return jsonify({"error": "群组不存在"}), 404

    if group['owner_id'] != user['id'] and not user['is_admin']:
        conn.close()
        return jsonify({"error": "无权修改成员"}), 403

    for uid in user_ids:
        conn.execute(
            "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)",
            (group_id, uid)
        )

    conn.commit()
    conn.close()
    return jsonify({"message": "成员已添加"})

@app.route('/api/groups/<group_id>/members/<user_id>', methods=['DELETE'])
@login_required
def api_remove_member(group_id, user_id):
    user = get_current_user()
    conn = get_db()

    group = conn.execute("SELECT * FROM groups WHERE id=?", (group_id,)).fetchone()
    if not group:
        conn.close()
        return jsonify({"error": "群组不存在"}), 404

    if group['owner_id'] != user['id'] and not user['is_admin']:
        conn.close()
        return jsonify({"error": "无权移除成员"}), 403

    conn.execute(
        "DELETE FROM group_members WHERE group_id=? AND user_id=?",
        (group_id, user_id)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "成员已移除"})

# ──────────────────────────── API: 用户管理 ────────────────────────────

@app.route('/api/users')
@login_required
def api_list_users():
    conn = get_db()
    users = conn.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY created_at").fetchall()
    conn.close()
    return jsonify({"users": [dict(u) for u in users]})

@app.route('/api/users/me/settings', methods=['POST'])
@login_required
def api_update_settings():
    data = request.get_json()
    user = get_current_user()

    conn = get_db()
    if 'auto_download' in data:
        conn.execute(
            "UPDATE users SET auto_download=? WHERE id=?",
            (int(data['auto_download']), user['id'])
        )
    conn.commit()
    conn.close()

    return jsonify({"message": "设置已更新"})

# ──────────────────────────── API: 管理员 ────────────────────────────

@app.route('/api/admin/stats')
@admin_required
def api_admin_stats():
    conn = get_db()
    stats = {
        "total_users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_files": conn.execute("SELECT COUNT(*) FROM files").fetchone()[0],
        "total_groups": conn.execute("SELECT COUNT(*) FROM groups").fetchone()[0],
        "total_size": conn.execute("SELECT COALESCE(SUM(file_size), 0) FROM files").fetchone()[0],
        "today_uploads": conn.execute(
            "SELECT COUNT(*) FROM files WHERE date(upload_time) = date('now','localtime')"
        ).fetchone()[0],
        "recent_files": [dict(r) for r in conn.execute(
            """SELECT f.*, u.username as uploader_name
               FROM files f JOIN users u ON f.uploader_id = u.id
               ORDER BY f.upload_time DESC LIMIT 10"""
        ).fetchall()],
        "recent_downloads": [dict(r) for r in conn.execute(
            """SELECT dl.*, f.original_name, u.username
               FROM download_logs dl
               JOIN files f ON dl.file_id = f.id
               JOIN users u ON dl.user_id = u.id
               ORDER BY dl.download_time DESC LIMIT 10"""
        ).fetchall()]
    }
    conn.close()
    return jsonify(stats)

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_user(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "用户不存在"}), 404
    if user['is_admin']:
        conn.close()
        return jsonify({"error": "不能删除管理员"}), 403

    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "用户已删除"})

@app.route('/api/admin/config', methods=['GET', 'POST'])
@admin_required
def api_admin_config():
    config_path = os.path.join(BASE_DIR, 'config.json')

    if request.method == 'GET':
        safe_config = {
            "server": CONFIG['server'],
            "storage": {"max_file_size_mb": CONFIG['storage']['max_file_size_mb']},
            "features": CONFIG['features']
        }
        return jsonify(safe_config)

    data = request.get_json()
    if 'features' in data:
        CONFIG['features'].update(data['features'])
    if 'server' in data:
        CONFIG['server'].update(data['server'])

    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(CONFIG, f, ensure_ascii=False, indent=4)

    return jsonify({"message": "配置已更新"})

# ──────────────────────────── 启动 ────────────────────────────

if __name__ == '__main__':
    init_db()
    print(f"文件存储目录: {STORAGE_DIR}")
    print(f"数据库路径: {DB_PATH}")
    print(f"服务启动于: http://{CONFIG['server']['host']}:{CONFIG['server']['port']}")
    app.run(
        host=CONFIG['server']['host'],
        port=CONFIG['server']['port'],
        debug=CONFIG['server']['debug']
    )
