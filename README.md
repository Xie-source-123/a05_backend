# a05-backend

AI 模拟面试平台的**后端服务**（Python / FastAPI），为前端 `AI_Vue` 提供接口。

## 环境要求

- **Python 3.12+**
- Windows / macOS / Linux 均可

## 快速启动

```bash
# 1) 创建虚拟环境
python -m venv venv

# 2) 激活（Windows）
venv\Scripts\activate
#    macOS / Linux:  source venv/bin/activate

# 3) 安装依赖
pip install -r requirements.txt

# 4) 配置环境变量
copy .env.example .env        # Windows
cp   .env.example .env        # macOS / Linux
# 然后用编辑器打开 .env，把自己的密钥填进去

# 5) 启动
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

启动后：

- 服务地址：http://127.0.0.1:8000
- 接口文档：http://127.0.0.1:8000/docs

> **前端依赖这个服务**。后端没起来时，前端页面会是一片空白。

## 环境变量说明

把 `.env.example` 复制成 `.env` 后按下表填写：

| 变量 | 用途 | 获取方式 |
|---|---|---|
| `DIFY_API_URL` / `DIFY_API_KEY` | AI 面试对话、追问 | [dify.ai](https://dify.ai) 注册后在「访问 API」页获取 |
| `DIFY_WORKFLOW_URL` / `DIFY_WORKFLOW_KEY` | 面试报告工作流 | 同上 |
| `REPORT_API_URL` | 报告生成接口 | 同上 |
| `DASHSCOPE_API_KEY` | 题库练习的 AI 评分 | [阿里云百炼](https://bailian.console.aliyun.com/) 控制台创建 API Key |
| `TTS_URL` / `TTS_MODEL` / `TTS_VOICE` | 语音合成 | 由 TTS 服务提供方给出 |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | 管理员账号，**首次启动时自动创建** | 自己设定 |

**`.env` 已被 `.gitignore` 忽略，不会被提交。** 请不要把 `.env` 发到群里或贴进仓库。

管理员密码要求：**至少 8 位，字母和数字都要有，且只能用字母和数字**（`admin_pro` / `7539518462` 这种纯数字的旧密码在新版本里无法登录）。

## 数据文件

服务用 JSON 文件当存储，首次启动会自动创建。**分两类**：

**会随仓库一起分发（内容与配置）**

| 文件 | 说明 |
|---|---|
| `question_banks.json` | 题库与题目（含 2 个岗位题库、各 300 题） |
| `positions.json` | 岗位定义 |
| `announcements.json` | 站内公告 |
| `ui_theme.json` | 界面配色主题 |

**不入库（各人本机独立）**

| 文件 | 说明 |
|---|---|
| `.env` | 密钥 |
| `users.json` | 用户账号（含密码哈希） |
| `resumes.json` | 简历 |
| `practice_records.json` | 题库练习与考试记录 |
| `interview_records.json` | 面试记录 |

这些文件已被 `.gitignore` 排除。**换电脑 / 新同事不会继承你的个人数据**，这是有意的。

## 常见问题

**换了一台机器 / 端口被占用**
如果 8000 被占用，换端口启动时要同时改前端的接口地址（前端里硬编码了 `http://localhost:8000`），否则前端连不上。

**前端报跨域（CORS）错误**
后端只放行了 `http://localhost:5173`、`http://127.0.0.1:5173`、`http://localhost:5174`。
如果前端启动后端口变了（比如 5175），需要去 `main.py` 的 `CORSMiddleware` 里加上那个地址。

**题库练习的 AI 评分报错**
检查 `.env` 里的 `DASHSCOPE_API_KEY` 是否填写、是否有余额。

## 技术栈

FastAPI + Uvicorn + Pydantic，数据用 JSON 文件持久化（原子写入），密码用 PBKDF2 哈希（20 万次迭代）。