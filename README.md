# 内网文件传输工具 / Intranet File Transfer Tool

[中文](#中文) | [English](#english)

---

## 中文

### 功能特性

- **文件传输**：支持文件和文本两种类型，可选择加密传输（AES）
- **接收方管理**：可指定发送给所有人、特定用户或群组
- **用户系统**：管理员（固定账号）和普通用户（可注册）两种角色
- **文件浏览**：可视化目录结构，支持拖拽上传
- **自动下载**：开启后自动下载新收到的非加密文件
- **用户目录**：每个用户拥有专属存储子目录

### 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 启动服务
python app.py
```

访问 `http://localhost:5000`，默认管理员账号：`admin` / `admin123`

### 配置说明

编辑 `config.json`：

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `admin.username` | 管理员用户名 | `admin` |
| `admin.password` | 管理员密码 | `admin123` |
| `server.host` | 监听地址 | `0.0.0.0` |
| `server.port` | 监听端口 | `5000` |
| `storage.base_dir` | 文件存储目录 | `./storage` |
| `storage.max_file_size_mb` | 最大文件大小(MB) | `500` |
| `features.allow_registration` | 允许用户注册 | `true` |

### 页面说明

| 页面 | 路径 | 功能 |
|------|------|------|
| 发送文件 | `/send` | 上传文件/文本，选择接收方，可加密 |
| 控制面板 | `/dashboard` | 收发统计，文件列表，用户配置 |
| 文件管理 | `/files` | 目录浏览，文件管理 |
| 群组管理 | `/groups` | 创建/编辑群组，管理成员 |
| 管理后台 | `/admin` | 用户管理，系统统计，配置（仅管理员） |

### 项目结构

```
dataupdate/
├── app.py              # 主程序
├── config.json         # 配置文件
├── requirements.txt    # 依赖列表
├── data.db            # SQLite 数据库（自动创建）
├── storage/           # 文件存储目录（自动创建）
├── templates/         # HTML 模板
│   ├── base.html      # 基础布局
│   ├── login.html     # 登录页
│   ├── register.html  # 注册页
│   ├── send.html      # 发送文件
│   ├── dashboard.html # 控制面板
│   ├── files.html     # 文件管理
│   ├── groups.html    # 群组管理
│   └── admin.html     # 管理后台
└── static/
    └── css/
        └── style.css  # 样式文件
```

### 生产部署

```bash
# 使用 gunicorn
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

---

## English

### Features

- **File Transfer**: Supports file and text types with optional AES encryption
- **Recipient Management**: Send to everyone, specific users, or groups
- **User System**: Admin (fixed account) and regular users (can register)
- **File Browser**: Visual directory structure with drag-and-drop upload
- **Auto Download**: Automatically download new unencrypted files when enabled
- **User Directories**: Each user gets a dedicated storage subdirectory

### Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start the server
python app.py
```

Visit `http://localhost:5000`, default admin account: `admin` / `admin123`

### Configuration

Edit `config.json`:

| Key | Description | Default |
|-----|-------------|---------|
| `admin.username` | Admin username | `admin` |
| `admin.password` | Admin password | `admin123` |
| `server.host` | Listen address | `0.0.0.0` |
| `server.port` | Listen port | `5000` |
| `storage.base_dir` | File storage directory | `./storage` |
| `storage.max_file_size_mb` | Max file size (MB) | `500` |
| `features.allow_registration` | Allow user registration | `true` |

### Pages

| Page | Path | Function |
|------|------|----------|
| Send File | `/send` | Upload files/text, select recipients, optional encryption |
| Dashboard | `/dashboard` | Send/receive stats, file list, user settings |
| File Manager | `/files` | Directory browsing, file management |
| Group Manager | `/groups` | Create/edit groups, manage members |
| Admin Panel | `/admin` | User management, system stats, config (admin only) |

### Project Structure

```
dataupdate/
├── app.py              # Main application
├── config.json         # Configuration file
├── requirements.txt    # Python dependencies
├── data.db            # SQLite database (auto-created)
├── storage/           # File storage directory (auto-created)
├── templates/         # HTML templates
│   ├── base.html      # Base layout
│   ├── login.html     # Login page
│   ├── register.html  # Registration page
│   ├── send.html      # Send file
│   ├── dashboard.html # Dashboard
│   ├── files.html     # File manager
│   ├── groups.html    # Group manager
│   └── admin.html     # Admin panel
└── static/
    └── css/
        └── style.css  # Stylesheet
```

### Production Deployment

```bash
# Using gunicorn
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```
