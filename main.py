import asyncio
import hashlib
import hmac
import json
import logging
import os
import re  # [新增] 用于从 AI 回复文本中解析评分
import secrets
import sys
import time
import uuid
from datetime import datetime, timedelta

import requests
import websockets  # [新增] ASR 实时流：作为客户端连阿里云百炼的 WebSocket
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse  # [修改] 导入 SSE 流式响应 / [新增] Response 用于返回音频字节
from pydantic import BaseModel

# ============================================================
# [新增] 把标准输出 / 标准错误强制为 UTF-8
# ============================================================
# Windows 控制台的默认编码不是 UTF-8（中文环境常是 cp936，英文环境常是 cp1252）。
# 只要日志里出现一个中文字符，就可能抛 UnicodeEncodeError —— 而且这个异常是在
# 「记录异常」这一步抛出的，于是症状是：接口返回 500 但响应体为空、
# 服务端连错误栈都打不出来，极难定位。
# 显式改掉后，日志不再依赖运行环境（有没有设 PYTHONIOENCODING、用什么终端启动）。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # 非 TextIOWrapper 等特殊情况直接跳过
        pass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
DIFY_API_URL = os.getenv("DIFY_API_URL")
DIFY_API_KEY = os.getenv("DIFY_API_KEY")

# ============================================================
# [新增] 评分系统相关配置（依据《api接口.docx》文档）
# DIFY_WORKFLOW_URL —— Dify 打分工作流地址（打分 + 生成评价）
# DIFY_WORKFLOW_KEY —— 打分工作流的 API Key
# REPORT_API_URL —— ECharts 可视化报告接口（重点，内部已调用 Dify 打分）
# ============================================================
DIFY_WORKFLOW_URL = os.getenv("DIFY_WORKFLOW_URL")
DIFY_WORKFLOW_KEY = os.getenv("DIFY_WORKFLOW_KEY")
REPORT_API_URL = os.getenv("REPORT_API_URL")


APP_VERSION = "1.0.0"
APP_NAME = "AI 模拟面试平台"
BUILD_DATE = "2026-11-10"

app = FastAPI(title="AI面试后端", version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

USERS_FILE = "users.json"
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        content = f.read().strip()
        if not content:
            return {}
        return json.loads(content)

def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

# ============================================================
# [新增] 密码存储：哈希，不存明文
# ============================================================
# 为什么不用 md5 / sha1 / 单次 sha256：
#   它们被设计成"快"，一块显卡每秒能试几十亿次，弱密码基本瞬间被撞出来。
#   PBKDF2 是刻意设计成慢的（这里 20 万轮），把单次尝试的成本抬高几个数量级。
# 为什么每个账号一个独立随机盐：
#   不加盐时相同密码得到相同哈希，攻击者用彩虹表可以批量还原；
#   加了盐，同一个密码在两个账号下的哈希也完全不同。
# 为什么用 hmac.compare_digest 而不是 ==：
#   普通 == 在第一个不同字节处就返回，响应时间的差异足以让攻击者逐字节试探哈希。
PBKDF2_ROUNDS = 200_000


def hash_password(password: str) -> dict:
    """把明文密码转成可存储的哈希记录（连算法与轮数一起存，便于日后升级）"""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return {
        "algo": "pbkdf2_sha256",
        "salt": salt.hex(),
        "hash": digest.hex(),
        "rounds": PBKDF2_ROUNDS,
    }


def verify_password(record: dict, password: str):
    """校验密码，返回 (是否通过, 是否需要把这条记录升级成哈希格式)

    兼容两种存储：
      · 新格式：{"algo", "salt", "hash", "rounds"}
      · 旧格式：{"password": "明文"} —— 历史遗留，登录成功后自动升级，用户无需重设密码
    """
    if "hash" in record and "salt" in record:
        rounds = int(record.get("rounds") or PBKDF2_ROUNDS)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(record["salt"]), rounds
        )
        return hmac.compare_digest(digest.hex(), record["hash"]), False

    if "password" in record:
        ok = hmac.compare_digest(str(record.get("password", "")), password)
        return ok, ok   # 旧格式且校验通过 → 需要迁移

    return False, False


# 用户注册
class RegisterReq(BaseModel):
    username: str
    password: str

# 用户登录
class LoginReq(BaseModel):
    username: str
    password: str

# 注册接口
@app.post("/api/auth/register")
def register(req: RegisterReq):
    username = (req.username or "").strip()
    if not username or not req.password:
        return {"error": "用户名和密码不能为空"}

    # [新增] 注册也要过密码策略。
    # 之前这里没校验 —— 上面那句「前端那份是体验、这份才是约束」当时是空话：
    # 绕过界面直接 POST 这个接口，能注册出任意弱密码。
    err = check_password_policy(req.password)
    if err:
        return {"error": err}

    users = load_users()
    if username in users:
        return {"error": "用户名已存在"}

    # [修改] 不再存明文
    record = hash_password(req.password)
    record["created_at"] = str(datetime.now())
    users[username] = record
    save_users(users)
    return {"message": "注册成功", "username": username}

# 登录接口
@app.post("/api/auth/login")
def login(req: LoginReq):
    username = (req.username or "").strip()
    users = load_users()
    if username not in users:
        return {"error": "用户不存在"}

    # [新增] 管理员在后台禁用过的账号直接挡住。
    # 不加这一段的话，「用户管理」里的禁用按钮就只是个装饰：
    # 用户换个页面重新登录照样进得来。
    if users[username].get("enabled") is False:
        logger.info(f"[Auth] 已禁用的账号尝试登录: {username!r}")
        return {"error": "该账号已被禁用，请联系管理员"}

    ok, need_upgrade = verify_password(users[username], req.password)
    if not ok:
        return {"error": "密码错误"}

    # [新增] 旧账号（明文存储）借这次登录自动升级成哈希，用户无感知
    if need_upgrade:
        upgraded = hash_password(req.password)
        upgraded["created_at"] = users[username].get("created_at", str(datetime.now()))
        users[username] = upgraded
        save_users(users)
        logger.info(f"[Auth] 已将 {username} 的密码从明文升级为 PBKDF2 哈希")

    # [修改] token 改用加密安全随机数。
    # 原来是对 username + 当前时间做 md5 —— 这是可预测的：
    # 知道用户名、再猜出大致登录时间，就能枚举出 token。
    token = secrets.token_urlsafe(32)
    return {"message": "登录成功", "token": token, "username": username}


# 聊天请求模型
class ChatRequest(BaseModel):
    message: str
    position: str = "Java后端"
    user_id: str = "local_user_001"
    user_name: str = "面试者"
    age: str = "25"
    degree: str = "本科"

# ============================================================
# [新增] 从 AI 回复文本中解析评分（满分 10 分）
# ============================================================
def extract_score(text: str):
    """从 AI 回复文本中提取评分分数，找不到返回 None"""
    if not text:
        return None
    # [新增] 按优先级匹配多种评分写法
    patterns = [
        r'评分\s*[：:]\s*(\d+(?:\.\d+)?)',   # 评分：8 或 评分: 8.5
        r'分数\s*[：:]\s*(\d+(?:\.\d+)?)',   # 分数：8
        r'得分\s*[：:]\s*(\d+(?:\.\d+)?)',   # 得分：8
        r'(\d+(?:\.\d+)?)\s*分',             # 8分
        r'(\d+(?:\.\d+)?)\s*/\s*10',         # 8/10
    ]
    for p in patterns:
        m = re.search(p, text)
        if m:
            score = float(m.group(1))
            if 0 <= score <= 10:
                return score
    return None

# ============================================================
# [新增] 根据评分返回所处档位（>7 / 5-7 / <5）
# ============================================================
def score_band(score):
    """返回评分档位字符串，score 为 None 时返回 None"""
    if score is None:
        return None
    if score > 7:
        return "高于7分"
    elif score >= 5:
        return "5-7分"
    else:
        return "5分以下"

# 封装调用Dify的函数
def call_dify_block(user_msg: str, position: str, user_id: str, user_name: str, age: str, degree: str):
    if not DIFY_API_URL or not DIFY_API_KEY:
        logger.error("DIFY_API_URL 或 DIFY_API_KEY 未配置，请检查 .env 文件")
        raise HTTPException(status_code=500, detail="Dify配置缺失，请联系管理员")

    headers = {
        "Authorization": f"Bearer {DIFY_API_KEY}",
        "Content-Type": "application/json"
    }
    # Dify标准请求体，inputs传递岗位给Prompt
    payload = {
        "inputs": {"position": position, "user_name": user_name, "Age": age, "degree": degree},
        "query": user_msg,
        "response_mode": "blocking",  # 阻塞：一次性返回全部文字
        "user": user_id
    }
    logger.info(f"[Dify] 请求 URL: {DIFY_API_URL}")
    logger.info(f"[Dify] 请求体: {json.dumps(payload, ensure_ascii=False)}")

    try:
        resp = requests.post(DIFY_API_URL, headers=headers, json=payload, timeout=60)
    except requests.exceptions.Timeout:
        logger.error("[Dify] 请求超时（60秒）")
        raise HTTPException(status_code=502, detail="Dify接口调用超时，请稍后重试")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"[Dify] 网络连接失败: {str(e)}")
        raise HTTPException(status_code=502, detail=f"Dify接口网络不通：{str(e)}")

    logger.info(f"[Dify] 响应状态码: {resp.status_code}")

    if not resp.ok:
        # 提取 Dify 返回的错误详情
        dify_err = f"HTTP {resp.status_code}"
        try:
            err_body = resp.json()
            logger.error(f"[Dify] 错误响应体: {json.dumps(err_body, ensure_ascii=False)}")
            dify_err = err_body.get("message") or err_body.get("error") or err_body.get("code") or json.dumps(err_body, ensure_ascii=False)
        except Exception:
            logger.error(f"[Dify] 错误响应文本: {resp.text}")
            dify_err = resp.text[:500]
        raise HTTPException(status_code=502, detail=f"Dify返回错误 [{resp.status_code}]：{dify_err}")

    res_data = resp.json()
    logger.info(f"[Dify] 响应体: {json.dumps(res_data, ensure_ascii=False)[:500]}...")
    return res_data.get("answer", "AI无返回内容")

# ============================================================
# [修改] 新增：SSE 流式调用 Dify，实现逐字输出（类似 ChatGPT）
# ============================================================
def call_dify_stream(user_msg: str, position: str, user_id: str, user_name: str, age: str, degree: str):
    """以 SSE（Server-Sent Events）流式方式调用 Dify，逐字返回 AI 回复"""
    if not DIFY_API_URL or not DIFY_API_KEY:
        logger.error("DIFY_API_URL 或 DIFY_API_KEY 未配置，请检查 .env 文件")
        raise HTTPException(status_code=500, detail="Dify配置缺失，请联系管理员")

    headers = {
        "Authorization": f"Bearer {DIFY_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "inputs": {"position": position, "user_name": user_name, "Age": age, "degree": degree},
        "query": user_msg,
        "response_mode": "streaming",  # [修改] 改为流式模式
        "user": user_id
    }
    logger.info(f"[Dify-Stream] 请求 URL: {DIFY_API_URL}")
    logger.info(f"[Dify-Stream] 请求体: {json.dumps(payload, ensure_ascii=False)}")

    try:
        # [修改] stream=True 以分块读取 Dify 的 SSE 响应
        resp = requests.post(
            DIFY_API_URL, headers=headers, json=payload,
            timeout=120, stream=True
        )
    except requests.exceptions.Timeout:
        logger.error("[Dify-Stream] 请求超时（120秒）")
        raise HTTPException(status_code=502, detail="Dify接口调用超时，请稍后重试")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"[Dify-Stream] 网络连接失败: {str(e)}")
        raise HTTPException(status_code=502, detail=f"Dify接口网络不通：{str(e)}")

    logger.info(f"[Dify-Stream] 响应状态码: {resp.status_code}")

    if not resp.ok:
        dify_err = f"HTTP {resp.status_code}"
        try:
            err_body = resp.json()
            logger.error(f"[Dify-Stream] 错误响应体: {json.dumps(err_body, ensure_ascii=False)}")
            dify_err = err_body.get("message") or err_body.get("error") or err_body.get("code") or json.dumps(err_body, ensure_ascii=False)
        except Exception:
            raw = resp.text[:500] if resp.text else "(空)"
            logger.error(f"[Dify-Stream] 错误响应文本: {raw}")
            dify_err = raw
        raise HTTPException(status_code=502, detail=f"Dify返回错误 [{resp.status_code}]：{dify_err}")

    # [修改] SSE 生成器：将 Dify 的原始 SSE 事件转换为前端可消费的格式
    def sse_generator():
        buffer = ""
        full_answer = ""  # [修改] 累计完整回复文本，仅用于最终评分解析
        failed_node = None  # [新增] 记录第一个失败的节点标题，用于报错定位
        try:
            # [修改] iter_content 逐块读取流式响应
            for chunk in resp.iter_content(chunk_size=None, decode_unicode=True):
                if not chunk:
                    continue
                buffer += chunk
                # [修改] Dify SSE 以 \n\n 分隔每条消息
                while "\n\n" in buffer:
                    raw_event, buffer = buffer.split("\n\n", 1)
                    for data_line in raw_event.split("\n"):
                        if not data_line.startswith("data: "):
                            continue
                        data_str = data_line[len("data: "):]
                        try:
                            event_data = json.loads(data_str)
                        except json.JSONDecodeError:
                            continue

                        event_type = event_data.get("event", "")

                        if event_type == "message":
                            # [修改] Dify 的 answer 是增量文本块，直接累加并转发，不做切片（切片会导致中文乱码）
                            answer = event_data.get("answer", "")
                            full_answer += answer
                            if answer:
                                yield f"data: {json.dumps({'type': 'text', 'content': answer}, ensure_ascii=False)}\n\n"

                        elif event_type == "message_end":
                            # [修改] 流结束信号，附带 conversation_id 供后续对话使用
                            # [修改] 用累计完整回复文本解析评分，附在 done 事件里
                            score = extract_score(full_answer)
                            done_payload = {
                                'type': 'done',
                                'conversation_id': event_data.get('conversation_id', ''),
                                'score': score,                # [修改] 评分分数（None 表示未解析到）
                                'score_band': score_band(score)  # [修改] 评分档位
                            }
                            yield f"data: {json.dumps(done_payload, ensure_ascii=False)}\n\n"

                        elif event_type == "node_finished":
                            # [新增] 记录失败的节点标题。
                            # Dify 的失败【不会】走 message 事件，只写在
                            # node_finished / workflow_finished 里；旧代码两者都不认，
                            # 于是整条流被静默丢弃 —— 前端只显示「面试官没有返回内容」，
                            # 真正的失败原因（例如模型余额不足）被吞掉了。
                            node_data = event_data.get("data") or {}
                            if node_data.get("status") == "failed" and failed_node is None:
                                failed_node = node_data.get("title") or "未命名节点"

                        elif event_type == "workflow_finished":
                            # [新增] 工作流结束：失败时把原因直接转给前端展示
                            wf_data = event_data.get("data") or {}
                            if wf_data.get("status") == "failed":
                                err_text = str(wf_data.get("error") or "未知错误")
                                where = f"（节点「{failed_node}」）" if failed_node else ""
                                logger.error(f"[Dify-Stream] 工作流失败{where}: {err_text[:300]}")
                                yield f"data: {json.dumps({'type': 'error', 'message': f'Dify 工作流执行失败{where}：{err_text[:300]}'}, ensure_ascii=False)}\n\n"

                        elif event_type == "error":
                            yield f"data: {json.dumps({'type': 'error', 'message': event_data.get('message', 'Dify内部错误')}, ensure_ascii=False)}\n\n"

        except Exception as e:
            logger.error(f"[Dify-Stream] SSE生成器异常: {str(e)}")
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)}, ensure_ascii=False)}\n\n"

    # [修改] 返回 StreamingResponse，media_type 必须为 text/event-stream
    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",      # 禁用 Nginx 缓冲
            "Connection": "keep-alive",
        }
    )

# 对外聊天接口 /api/chat（前端Vue调用这个接口）
@app.post("/api/chat")
def chat(req: ChatRequest):
    # 调用封装好的Dify函数
    ai_reply = call_dify_block(req.message, req.position, req.user_id, req.user_name, req.age, req.degree)
    # [修改] 从 AI 回复文本中解析评分
    score = extract_score(ai_reply)
    # [修改] 返回给前端时附带评分分数与档位
    return {
        "reply": ai_reply,
        "position": req.position,
        "score": score,                # [修改] 评分分数（None 表示未解析到）
        "score_band": score_band(score)  # [修改] 评分档位：高于7分 / 5-7分 / 5分以下
    }

# ============================================================
# [修改] 新增：SSE 流式聊天接口（前端用 EventSource 消费）
# ============================================================
@app.post("/api/chat/stream")
def chat_stream(req: ChatRequest):
    """流式聊天端点，返回 SSE 事件流，实现 AI 回复逐字显示"""
    # [修改] 调用流式版本的 Dify 函数，返回 StreamingResponse
    return call_dify_stream(req.message, req.position, req.user_id, req.user_name, req.age, req.degree)


# ============================================================
# [新增] 评分报告请求模型（依据《api接口.docx》文档）
# items 结构示例：
#   [{ "题目": "xxx", "参考答案": "xxx", "用户回答": "xxx" }, ...]
# 前端根据每次面试的真实对话数据组装十道题后传入
# ============================================================
class ReportRequest(BaseModel):
    items: list = []


# ============================================================
# [新增] 评分报告生成接口 —— 代理转发到 ECharts 报告服务
# 文档接口：POST https://2f4ad4c6.r7.cpolar.cn/api/report/html
# 作用：把 items（题目/参考答案/用户回答）转发给报告服务，
#       返回 { code: 0, msg: "ok", html: "<!DOCTYPE html>..." }
# 前端拿到 html 后通过 iframe srcdoc 直接渲染可视化报告。
# 说明：这里做成后端代理，是为了把会变动的 cpolar 公网域名
#       收敛到后端 .env 一处配置，避免前端每次改地址。
# ============================================================
@app.post("/api/report/html")
def report_html(req: ReportRequest):
    if not REPORT_API_URL:
        # [新增] 未配置报告服务地址时，直接返回明确错误
        raise HTTPException(status_code=500, detail="报告服务地址未配置，请检查 .env 的 REPORT_API_URL")

    # [新增] 记录请求体，便于排查（items 可能较长，仅打印条数）
    logger.info(f"[Report] 收到报告请求，items 数量: {len(req.items)}")

    try:
        # [新增] 转发请求给 ECharts 报告服务，超时给足（报告渲染可能较慢）
        resp = requests.post(REPORT_API_URL, json={"items": req.items}, timeout=120)
    except requests.exceptions.Timeout:
        logger.error("[Report] 报告服务调用超时（120秒）")
        raise HTTPException(status_code=502, detail="报告服务调用超时，请稍后重试")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"[Report] 报告服务网络连接失败: {str(e)}")
        raise HTTPException(status_code=502, detail=f"报告服务网络不通：{str(e)}")

    logger.info(f"[Report] 报告服务响应状态码: {resp.status_code}")

    if not resp.ok:
        # [新增] 报告服务返回错误时，提取错误信息透传给前端
        err_detail = f"HTTP {resp.status_code}"
        try:
            err_body = resp.json()
            logger.error(f"[Report] 报告服务错误响应体: {json.dumps(err_body, ensure_ascii=False)}")
            err_detail = err_body.get("msg") or err_body.get("message") or json.dumps(err_body, ensure_ascii=False)
        except Exception:
            logger.error(f"[Report] 报告服务错误响应文本: {resp.text[:500]}")
            err_detail = resp.text[:500]
        raise HTTPException(status_code=502, detail=f"报告服务返回错误 [{resp.status_code}]：{err_detail}")

    # [新增] 成功时原样返回报告服务的 JSON 结果
    # 结构：{ "code": 0, "msg": "ok", "html": "<!DOCTYPE html>..." }
    return resp.json()


# ============================================================
# [新增] Dify 打分工作流接口（打分模型 + 生成评价）
# 文档接口：POST https://7ec07dea.r7.cpolar.cn/v1/workflows/run
# 入参变量名：duihua（json 类型，含 items 数组）
# 返回：输出字段 text，里面是 json 字符串报告数据
# 说明：此接口与上面的报告接口二选一，报告接口内部已调用打分，
#       这里额外暴露打分接口，便于单独获取评分/评价文本。
# ============================================================
@app.post("/api/score/evaluate")
def score_evaluate(req: ReportRequest):
    if not DIFY_WORKFLOW_URL or not DIFY_WORKFLOW_KEY:
        # [新增] 未配置打分工作流时，直接返回明确错误
        raise HTTPException(status_code=500, detail="打分工作流未配置，请检查 .env 的 DIFY_WORKFLOW_URL / DIFY_WORKFLOW_KEY")

    # [新增] 依据文档拼装 Dify 工作流请求体
    # 文档要求：inputs.duihua 为 json 类型，包含 items 数组
    payload = {
        "inputs": {"duihua": {"items": req.items}},
        "response_mode": "blocking",   # 阻塞模式：一次性返回全部结果
        "user": "client01"              # 文档说明用户名可随便设
    }
    headers = {
        "Authorization": f"Bearer {DIFY_WORKFLOW_KEY}",
        "Content-Type": "application/json"
    }

    logger.info(f"[Score] 打分工作流请求，items 数量: {len(req.items)}")

    try:
        # [新增] 调用 Dify 工作流，超时 120 秒
        resp = requests.post(DIFY_WORKFLOW_URL, headers=headers, json=payload, timeout=120)
    except requests.exceptions.Timeout:
        logger.error("[Score] 打分工作流调用超时（120秒）")
        raise HTTPException(status_code=502, detail="打分工作流调用超时，请稍后重试")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"[Score] 打分工作流网络连接失败: {str(e)}")
        raise HTTPException(status_code=502, detail=f"打分工作流网络不通：{str(e)}")

    logger.info(f"[Score] 打分工作流响应状态码: {resp.status_code}")

    if not resp.ok:
        # [新增] 打分工作流返回错误时，提取错误信息透传
        err_detail = f"HTTP {resp.status_code}"
        try:
            err_body = resp.json()
            logger.error(f"[Score] 打分工作流错误响应体: {json.dumps(err_body, ensure_ascii=False)}")
            err_detail = err_body.get("message") or err_body.get("error") or json.dumps(err_body, ensure_ascii=False)
        except Exception:
            logger.error(f"[Score] 打分工作流错误响应文本: {resp.text[:500]}")
            err_detail = resp.text[:500]
        raise HTTPException(status_code=502, detail=f"打分工作流返回错误 [{resp.status_code}]：{err_detail}")

    # [新增] 解析 Dify 工作流返回结果，输出字段为 data.outputs.text（json 字符串）
    res_data = resp.json()
    logger.info(f"[Score] 打分工作流响应体: {json.dumps(res_data, ensure_ascii=False)[:500]}...")

    # [新增] 尝试从 data.outputs.text 中提取评分报告文本
    outputs = res_data.get("data", {}).get("outputs", {})
    text_report = outputs.get("text", "")

    return {
        "code": 0,
        "msg": "ok",
        # [新增] 文档说明输出字段是 text，里面是 json 字符串报告数据
        "report": text_report,
        "raw": res_data   # [新增] 附上原始响应，便于前端按需解析
    }


# ============================================================
# [替换] 文本转语音（TTS）—— 阿里云百炼 Qwen-Audio-TTS 代理
# ============================================================
# 为什么必须在后端做代理：前端代码里不存在"隐藏的密钥"。任何写进 AI_Vue/src
# 的 key 都会被 Vite 内联进 dist/assets/*.js，浏览器 DevTools 直接可读。
# 所以 key 只留在 .env，前端只调本站的 /api/tts。
#
# 接口依据官方文档 https://help.aliyun.com/en/model-studio/cosyvoice-tts-http-api
# 与上一版 MiniMax 实现有两个关键差异：
#   1. 非流式模式下 output.audio.data 是【空的】，音频只给一个 OSS URL，
#      所以这里必须再取一次字节才能回给前端。
#   2. 音色【不能跨模型混用】—— 填了当前模型不支持的 voice 会返回
#      InvalidParameter。因此维护一份白名单并在入口就挡住，
#      而不是让请求跑到阿里云才报一个前端看不懂的错。
# 域名：官方说明旧域名 dashscope.aliyuncs.com 仍完全可用，且不需要 Workspace ID
#      （新域名形如 {WorkspaceId}.cn-beijing.maas.aliyuncs.com）。
# ============================================================
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY")
TTS_URL = os.getenv(
    "TTS_URL",
    "https://dashscope.aliyuncs.com/api/v1/services/audio/tts/SpeechSynthesizer",
)
TTS_MODEL = os.getenv("TTS_MODEL", "qwen-audio-3.0-tts-flash")
TTS_VOICE = os.getenv("TTS_VOICE", "longanfengyue")
TTS_MAX_CHARS = 2000        # 单次合成的字数上限：既防超限，也防一次烧掉太多额度

# 音色白名单：取自官方「Qwen-Audio-TTS 音色列表」中 qwen-audio-3.0-tts-flash
# 对应那一组（12 个系统音色）。两个模型各自另有 500 余个「基础音色」，
# ID 形如 qwen-audio-3.0-tts-flash-xxx，需要时追加到这里即可。
TTS_VOICES = [
    {"id": "longanfengyue", "name": "龙安风悦", "note": "自然亲切音 · 30岁女"},
    {"id": "longanxiaoxin", "name": "龙安小昕", "note": "亲切活泼音 · 22岁女"},
    {"id": "longanlingxi", "name": "龙安灵希", "note": "可爱甜美音 · 25岁女"},
    {"id": "longanyuanfei", "name": "龙安元妃", "note": "高傲妃子音 · 30岁女"},
    {"id": "longanhuan_v3.6", "name": "龙安欢", "note": "25岁女"},
    {"id": "longchuanshu_v3.6", "name": "龙川叔", "note": "川普大叔音 · 40岁男"},
    {"id": "longjielidou_v3.6", "name": "龙杰力豆", "note": "天真男童 · 5岁"},
    {"id": "longhuohuo_v3.6", "name": "龙火火", "note": "顽皮少年音 · 8岁"},
    {"id": "longpaopao_v3.6", "name": "龙泡泡", "note": "软糯可爱音 · 5岁女"},
    {"id": "loongjohn", "name": "loongJohn", "note": "沉稳亲切美音 · 28岁男（英文）"},
    {"id": "loongmary", "name": "loongmary", "note": "温暖英音 · 20岁女（英文）"},
    {"id": "loongeva_v3.6", "name": "loongeva", "note": "高智美音 · 28岁女（英文）"},
]
TTS_VOICE_IDS = {v["id"] for v in TTS_VOICES}


class TTSRequest(BaseModel):
    text: str
    voice: str = ""


@app.get("/api/tts/voices")
def tts_voices():
    """把可用音色列表交给前端，避免前端再抄一份 —— 抄一份就会与后端脱节"""
    return {"model": TTS_MODEL, "default": TTS_VOICE, "voices": TTS_VOICES}


@app.post("/api/tts")
def tts(req: TTSRequest):
    """把一段文本合成为 mp3，直接以音频字节返回（前端用 Blob URL 播放）"""
    if not DASHSCOPE_API_KEY:
        raise HTTPException(status_code=500, detail="TTS 未配置，请检查 .env 的 DASHSCOPE_API_KEY")

    text = (req.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="待合成的文本为空")

    if len(text) > TTS_MAX_CHARS:
        logger.warning(f"[TTS] 文本过长（{len(text)} 字），截断到 {TTS_MAX_CHARS}")
        text = text[:TTS_MAX_CHARS]

    # 音色：没传就用默认值；传了但不在白名单里就直接拒绝并给出可选值
    voice = (req.voice or "").strip() or TTS_VOICE
    if voice not in TTS_VOICE_IDS:
        raise HTTPException(
            status_code=400,
            detail=f"音色 {voice} 不在 {TTS_MODEL} 的支持列表内。可选：{', '.join(sorted(TTS_VOICE_IDS))}",
        )

    payload = {
        "model": TTS_MODEL,
        "input": {
            "text": text,
            "voice": voice,
            "format": "mp3",
            "sample_rate": 24000,
            "language_hints": ["zh"],   # 面试场景以中文为主
        },
    }
    headers = {
        "Authorization": f"Bearer {DASHSCOPE_API_KEY}",
        "Content-Type": "application/json",
    }

    logger.info(f"[TTS] 合成请求：{len(text)} 字，model={TTS_MODEL}，voice={voice}")

    try:
        resp = requests.post(TTS_URL, headers=headers, json=payload, timeout=60)
    except requests.exceptions.Timeout:
        logger.error("[TTS] 请求超时（60秒）")
        raise HTTPException(status_code=502, detail="TTS 调用超时，请稍后重试")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"[TTS] 连接失败: {str(e)}")
        raise HTTPException(status_code=502, detail=f"TTS 域名连不上：{str(e)}")

    logger.info(f"[TTS] 响应状态码: {resp.status_code}")

    try:
        data = resp.json()
    except ValueError:
        logger.error(f"[TTS] 响应非 JSON: {resp.text[:300]}")
        raise HTTPException(status_code=502, detail=f"TTS 返回了非 JSON 内容 [{resp.status_code}]")

    if not resp.ok:
        logger.error(f"[TTS] HTTP 错误: {resp.text[:400]}")
        raise HTTPException(
            status_code=502,
            detail=f"TTS 返回错误 [{resp.status_code}]：{data.get('message') or resp.text[:200]}",
        )
    # 百炼的错误挂在顶层的 code / message 上
    if data.get("code"):
        logger.error(f"[TTS] 业务失败 [{data.get('code')}] {data.get('message')}")
        raise HTTPException(
            status_code=502, detail=f"TTS 失败 [{data.get('code')}]：{data.get('message')}"
        )

    # [关键] 非流式模式下音频不在 data 字段里，只返回 URL
    audio_url = ((data.get("output") or {}).get("audio") or {}).get("url")
    if not audio_url:
        logger.error(f"[TTS] 响应中没有音频地址: {json.dumps(data, ensure_ascii=False)[:400]}")
        raise HTTPException(status_code=502, detail="TTS 未返回音频地址")

    # 二次请求把字节取回来：前端只需调我们一次，也不必接触阿里云的 OSS 地址
    try:
        audio = requests.get(audio_url, timeout=60)
    except requests.exceptions.RequestException as e:
        logger.error(f"[TTS] 音频下载失败: {str(e)}")
        raise HTTPException(status_code=502, detail=f"TTS 音频下载失败：{str(e)}")

    if not audio.ok:
        logger.error(f"[TTS] 音频下载 HTTP {audio.status_code}")
        raise HTTPException(status_code=502, detail=f"TTS 音频下载失败 [HTTP {audio.status_code}]")

    audio_bytes = audio.content
    chars = (data.get("usage") or {}).get("characters")
    logger.info(f"[TTS] 合成成功：{len(audio_bytes)} 字节，计费 {chars} 字")

    return Response(
        content=audio_bytes,
        media_type="audio/mpeg",
        headers={"Cache-Control": "no-store"},
    )
@app.get("/")
def hello():
    return {"message": "Hello World! 面试系统启动成功"}

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "A05面试系统"}

@app.get("/api/echo")
def echo(message: str = Query()):
    return {"reply": f"你说的是：{message}。AI面试官已上线！"}


# ============================================================
# [新增] 实时语音识别（ASR）—— 浏览器 ⇄ 本后端 ⇄ 阿里云百炼
# ============================================================
# 为什么必须要有这一层代理，而不是让浏览器直连阿里云：
#   1. API Key 不能下发到浏览器；
#   2. 浏览器的 WebSocket 构造函数【不支持自定义请求头】，
#      而百炼的鉴权 Authorization 恰恰只能放在握手请求头里；
#   3. 上下文增强 / 即时热词要按「目标岗位」这一业务信息动态拼装，
#      放服务端才不用前端再抄一份词表（抄一份必然与后端脱节）。
#
# 接口依据官方文档：
#   客户端事件 https://help.aliyun.com/zh/model-studio/fun-asr-client-events
#   服务端事件 https://help.aliyun.com/zh/model-studio/fun-asr-server-events
#   连接与请求头 https://help.aliyun.com/zh/model-studio/fun-asr-realtime-websocket-api
#
# 三个最容易踩的坑，都在下面处理掉了：
#   1. 音频必须是【单声道 PCM】。官方明确 opus 必须 Ogg 封装、wav 必须 PCM 编码、
#      amr 只收 AMR-NB —— 所以浏览器 MediaRecorder 默认吐出来的 webm/opus
#      是【不能】直接用的，前端只能用 AudioWorklet 取原始 PCM。
#   2. input.context 与 parameters.vocabulary 只有 qwen-audio-3.0-asr-flash-streaming
#      （以及 fun-asr-realtime 系列）支持，换模型带上会被拒。
#   3. 必须等 task-started 之后才能推音频，早推会被直接丢掉。
# ============================================================
ASR_WS_URL = os.getenv("ASR_WS_URL", "wss://dashscope.aliyuncs.com/api-ws/v1/inference")
ASR_MODEL = os.getenv("ASR_MODEL", "qwen-audio-3.0-asr-flash-streaming")
ASR_SAMPLE_RATE = int(os.getenv("ASR_SAMPLE_RATE", "16000"))
ASR_LANGUAGE_HINTS = [s.strip() for s in os.getenv("ASR_LANGUAGE_HINTS", "zh,en").split(",") if s.strip()]

# 单次录音时长上限：连接一直挂着会持续计费，所以服务端也要有一道闸，不能只靠前端自觉
ASR_MAX_SECONDS = int(os.getenv("ASR_MAX_SECONDS", "180"))
ASR_MAX_AUDIO_BYTES = ASR_SAMPLE_RATE * 2 * ASR_MAX_SECONDS   # 16bit 单声道 → 每秒 32000 字节

# 官方对上下文的两条硬约束（超了会被静默截断，所以在这里先截好）
ASR_CTX_MAX_TURNS = 5        # input_text / text 各最多 5 条
ASR_CTX_MAX_CHARS = 400      # 每轮上下文文本总长度不超过 400 字符

# 只有这些模型支持 context / vocabulary，其余模型带上去会被拒
ASR_MODELS_WITH_CONTEXT = {
    "qwen-audio-3.0-asr-flash-streaming",
    "fun-asr-realtime",
    "fun-asr-realtime-2025-11-07",
}
ASR_MODELS_WITH_VOCABULARY = {"qwen-audio-3.0-asr-flash-streaming"}

# 即时热词基础表。权重取值只能是 [1,5] 或 50（50 = 超级热词，召回率大幅提升，
# 官方上限 50 个）。这里 5 表示「很想要」，3 表示「顺带提一下」。
#
# 选词思路：面试场景真正会被识别错的，一是这些高频题型词，
# 二是英文技术名词（ASR 对中英夹杂的技术词错得最多），所以两部分都要放。
ASR_HOTWORDS_BASE = {
    "自我介绍": 5, "项目经历": 5, "职业规划": 5, "实习经历": 5, "校园经历": 5,
    "薪资期望": 5, "到岗时间": 5, "离职原因": 5, "核心竞争力": 5, "团队协作": 5,
    "抗压能力": 5, "学习能力": 5, "业务理解": 5, "岗位匹配": 5, "优缺点": 5,
    "复盘": 3, "面经": 3, "笔试题": 3, "群面": 3, "终面": 3,
    # 数据方向
    "数据分析": 5, "数据仓库": 5, "数据建模": 5, "指标体系": 5, "实时数仓": 5,
    "离线数仓": 5, "维度建模": 5, "数据治理": 5, "数据质量": 5, "任务调度": 5,
    "数据集市": 5, "埋点": 5, "宽表": 5, "血缘": 3,
    # 后端 / 通用工程
    "消息队列": 5, "分布式": 5, "微服务": 5, "高并发": 5, "高可用": 5,
    "性能优化": 5, "索引优化": 5, "慢查询": 5, "事务隔离": 5, "读写分离": 5,
    "分库分表": 5, "缓存穿透": 5, "缓存雪崩": 5, "熔断降级": 5, "限流": 5,
    "容器化": 5, "持续集成": 5, "负载均衡": 5, "幂等": 5, "压测": 5,
    # 算法 / 基础
    "算法": 3, "数据结构": 3, "时间复杂度": 3, "空间复杂度": 3, "动态规划": 3,
    # 英文技术名词：中英夹杂时最容易识别错的一类
    "Kubernetes": 5, "Docker": 5, "Flink": 5, "Spark": 5, "Hive": 5, "Hadoop": 5,
    "Kafka": 5, "Redis": 5, "MySQL": 5, "ClickHouse": 5, "Doris": 5, "HBase": 5,
    "Elasticsearch": 5, "ZooKeeper": 5, "Python": 5, "Java": 5, "SQL": 5,
    "ETL": 5, "OLAP": 5, "OLTP": 5, "Linux": 5, "Git": 5, "API": 5, "Bug": 5,
}


def _asr_supports(model: str, allowed: set) -> bool:
    return (model or "").strip() in allowed


def build_asr_context(history):
    """把前几轮面试问答拼成官方要求的 input.context。

    两条硬约束先在这里截断：input_text / text 各最多 5 条、总长不超过 400 字符。
    顺序也有要求 —— 每轮 user 必须排在对应的 assistant 之前。
    取值策略是【从最近的一轮往前取】：越近的对话对本次识别越有帮助。
    """
    if not history:
        return []

    picks = []
    budget = ASR_CTX_MAX_CHARS
    used_user = 0
    used_assistant = 0

    for item in reversed(history):
        role = (item or {}).get("role")
        text = ((item or {}).get("text") or "").strip()
        if not text:
            continue
        if role == "user":
            if used_user >= ASR_CTX_MAX_TURNS:
                continue
            ctype = "input_text"
        elif role == "assistant":
            if used_assistant >= ASR_CTX_MAX_TURNS:
                continue
            ctype = "text"
        else:
            continue

        text = text[:budget]
        if not text:
            break
        budget -= len(text)
        picks.append({"role": role, "content": [{"type": ctype, "text": text}]})
        if role == "user":
            used_user += 1
        else:
            used_assistant += 1
        if budget <= 0:
            break

    picks.reverse()
    # 预算被截到从 assistant 开头会让上下文「没头没尾」，直接把开头的 assistant 丢掉
    while picks and picks[0]["role"] == "assistant":
        picks.pop(0)
    return picks


def build_asr_vocabulary(position: str):
    """即时热词 = 基础面试词表 + 目标岗位名。

    岗位名是整段对话里最该识别准、又最容易被识别错的词，所以单独给 50 权重
    提成超级热词 —— 比如「数据开发工程师」被听成「数据开发城市」，
    后面意图判断就全歪了。
    """
    vocab = dict(ASR_HOTWORDS_BASE)
    pos = (position or "").strip()
    if pos:
        vocab[pos] = 50
        for seg in re.split(r"[、,，/|｜\s]+", pos):
            seg = seg.strip()
            if len(seg) >= 2:
                vocab[seg] = 50

    # [新增] 管理后台题库里维护的术语。
    # 用 setdefault 而不是直接赋值：基础词表是精心挑过的，权重更高，
    # 题库里的同名词不应该把它覆盖掉。
    for term, weight in build_question_vocabulary().items():
        vocab.setdefault(term, weight)

    return vocab


def _asr_run_task(task_id: str, context: list, vocabulary: dict) -> dict:
    """拼 run-task 指令。字段名与层级严格照官方文档，不要自行发挥。"""
    parameters = {
        "format": "pcm",
        "sample_rate": ASR_SAMPLE_RATE,
    }
    if ASR_LANGUAGE_HINTS:
        parameters["language_hints"] = ASR_LANGUAGE_HINTS

    if vocabulary and _asr_supports(ASR_MODEL, ASR_MODELS_WITH_VOCABULARY):
        parameters["vocabulary"] = vocabulary
    elif vocabulary:
        logger.warning(f"[ASR] 模型 {ASR_MODEL} 不支持即时热词，已跳过 {len(vocabulary)} 个热词")

    payload = {
        "header": {"action": "run-task", "task_id": task_id, "streaming": "duplex"},
        "payload": {
            "task_group": "audio",
            "task": "asr",
            "function": "recognition",
            "model": ASR_MODEL,
            "parameters": parameters,
            # 不携带上下文时必须传 {}，不能把 input 整个省掉
            "input": {},
        },
    }

    if context:
        if _asr_supports(ASR_MODEL, ASR_MODELS_WITH_CONTEXT):
            payload["payload"]["input"] = {"context": context}
        else:
            logger.warning(f"[ASR] 模型 {ASR_MODEL} 不支持上下文增强，已跳过 {len(context)} 条上下文")
    return payload


def _asr_finish_task(task_id: str) -> dict:
    return {
        "header": {"action": "finish-task", "task_id": task_id, "streaming": "duplex"},
        "payload": {"input": {}},
    }


async def _asr_send(ws: WebSocket, obj: dict):
    """前端可能已经关掉页面了，发送失败不该把整个协程掀翻。"""
    try:
        await ws.send_json(obj)
    except Exception:
        pass


@app.websocket("/api/asr")
async def asr_proxy(ws: WebSocket):
    """浏览器 ⇄ 本接口 ⇄ 百炼实时 ASR 的双向代理。

    自定义的前后端协议（前端发来的 JSON 文本帧 + 二进制 PCM 帧）：
      前端 → 后端：{"type":"start","position":"...","history":[{"role":"user","text":"..."}]}
                   <二进制帧，16kHz / 16bit / 单声道 PCM>
                   {"type":"stop"}
      后端 → 前端：{"type":"ready"}                              可以开始推音频了
                   {"type":"partial","text":"...","sentenceId":n}  中间结果（会不断被改写）
                   {"type":"sentence","text":"...","sentenceId":n} 一句的最终结果
                   {"type":"done","text":"整段完整文本"}            收尾
                   {"type":"error","message":"..."}
    """
    await ws.accept()

    if not DASHSCOPE_API_KEY:
        await _asr_send(ws, {"type": "error", "message": "ASR 未配置，请检查 .env 的 DASHSCOPE_API_KEY"})
        await ws.close()
        return

    # ---------- 1. 等前端的 start 指令 ----------
    try:
        raw = await ws.receive()
        if raw.get("type") == "websocket.disconnect":
            return
        cfg = json.loads(raw.get("text") or "{}")
    except Exception as e:
        logger.warning(f"[ASR] 启动指令解析失败: {e}")
        await _asr_send(ws, {"type": "error", "message": "启动指令不是合法 JSON"})
        await ws.close()
        return

    if cfg.get("type") != "start":
        await _asr_send(ws, {"type": "error", "message": "第一条消息必须是 {\"type\":\"start\"}"})
        await ws.close()
        return

    task_id = str(uuid.uuid4())
    position = cfg.get("position") or ""
    context = build_asr_context(cfg.get("history") or [])
    vocabulary = build_asr_vocabulary(position)
    run_task = _asr_run_task(task_id, context, vocabulary)

    state = {
        "finals": {},          # sentence_id → 最终文本，收尾时按 id 排序拼回整段
        "audio_bytes": 0,
        "stop_sent": False,    # finish-task 是否已发，避免重复发
        "failed": False,
        "client_gone": False,
    }

    logger.info(
        f"[ASR] 开始识别 task={task_id} 模型={ASR_MODEL} "
        f"上下文={len(context)}条 热词={len(vocabulary)}个 岗位={position or '未指定'}"
    )

    # ---------- 2. 两个方向的泵 ----------
    async def pump_client_to_upstream(up):
        """把前端推来的 PCM 转给上游；收到 stop 就发 finish-task 收尾。"""
        while True:
            try:
                msg = await ws.receive()
            except Exception:
                state["client_gone"] = True
                return

            if msg.get("type") == "websocket.disconnect":
                state["client_gone"] = True
                logger.info(f"[ASR] 前端断开 task={task_id}")
                return

            data = msg.get("bytes")
            if data:
                if state["stop_sent"]:
                    continue
                state["audio_bytes"] += len(data)
                if state["audio_bytes"] > ASR_MAX_AUDIO_BYTES:
                    state["stop_sent"] = True
                    await _asr_send(ws, {
                        "type": "error",
                        "message": f"单次录音超过 {ASR_MAX_SECONDS} 秒上限，已自动结束识别",
                    })
                    await up.send(json.dumps(_asr_finish_task(task_id)))
                    return
                try:
                    await up.send(data)
                except Exception as e:
                    logger.warning(f"[ASR] 音频转发失败: {e}")
                    return
                continue

            text = msg.get("text")
            if not text:
                continue
            try:
                ctl = json.loads(text)
            except ValueError:
                continue
            if ctl.get("type") == "stop" and not state["stop_sent"]:
                state["stop_sent"] = True
                logger.info(f"[ASR] 收到 stop，音频共 {state['audio_bytes']} 字节，等待收尾识别")
                try:
                    await up.send(json.dumps(_asr_finish_task(task_id)))
                except Exception as e:
                    logger.warning(f"[ASR] finish-task 发送失败: {e}")
                return

    async def pump_upstream_to_client(up):
        """把上游事件翻译成前端看得懂的消息。"""
        while True:
            try:
                raw = await up.recv()
            except websockets.exceptions.ConnectionClosed as e:
                logger.info(f"[ASR] 上游连接关闭: code={e.code} reason={e.reason}")
                return

            if isinstance(raw, (bytes, bytearray)):
                continue   # ASR 不会回二进制，真收到了也没有意义

            try:
                msg = json.loads(raw)
            except ValueError:
                continue

            header = msg.get("header") or {}
            event = header.get("event")

            if event == "result-generated":
                sentence = (((msg.get("payload") or {}).get("output") or {}).get("sentence") or {})
                if sentence.get("heartbeat"):
                    continue          # 心跳包，sentence_id 固定为 0，跳过
                text = (sentence.get("text") or "").strip()
                if not text:
                    continue          # sentence_begin 那条的 text 是空的
                sid = sentence.get("sentence_id")
                if sentence.get("sentence_end"):
                    state["finals"][sid] = text
                    await _asr_send(ws, {"type": "sentence", "text": text, "sentenceId": sid})
                else:
                    await _asr_send(ws, {"type": "partial", "text": text, "sentenceId": sid})
                continue

            if event == "task-failed":
                state["failed"] = True
                logger.error(
                    f"[ASR] 识别失败 task={task_id} "
                    f"[{header.get('error_code')}] {header.get('error_message')}"
                )
                await _asr_send(ws, {
                    "type": "error",
                    "message": f"识别失败 [{header.get('error_code')}]：{header.get('error_message')}",
                })
                return

            if event == "task-finished":
                return

            # task-started 已经在握手阶段消费掉了，这里不用再管

    # ---------- 3. 连上游、跑会话 ----------
    upstream = None
    try:
        upstream = await websockets.connect(
            ASR_WS_URL,
            additional_headers={
                "Authorization": f"Bearer {DASHSCOPE_API_KEY}",
                "user-agent": "a05-interview-backend/1.0",
            },
            max_size=None,
            open_timeout=15,
            ping_interval=20,
            ping_timeout=20,
        )

        await upstream.send(json.dumps(run_task, ensure_ascii=False))

        # 官方时序：必须等到 task-started 才能推音频
        started = False
        while True:
            greeting = json.loads(await asyncio.wait_for(upstream.recv(), timeout=15))
            g_header = greeting.get("header") or {}
            g_event = g_header.get("event")
            if g_event == "task-started":
                started = True
                break
            if g_event == "task-failed":
                raise RuntimeError(
                    f"[{g_header.get('error_code')}] {g_header.get('error_message')}"
                )
        if not started:
            raise RuntimeError("上游没有返回 task-started")

        await _asr_send(ws, {"type": "ready", "taskId": task_id, "model": ASR_MODEL})
        logger.info(f"[ASR] task-started，已通知前端开始推流 task={task_id}")

        sender = asyncio.create_task(pump_client_to_upstream(upstream))
        try:
            await pump_upstream_to_client(upstream)
        finally:
            sender.cancel()
            try:
                # 取消的那一刻 ws.receive() 会抛 CancelledError，这里只是等它真正落地；
                # 不 await 的话会留下 "Task was destroyed but it is pending" 告警
                await sender
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.warning(f"[ASR] 上行泵退出异常: {e}")

    except asyncio.TimeoutError:
        state["failed"] = True
        logger.error(f"[ASR] 等待 task-started 超时 task={task_id}")
        await _asr_send(ws, {"type": "error", "message": "连接语音服务超时，请重试"})
    except websockets.exceptions.InvalidStatus as e:
        # 握手就被拒：几乎都是 Key 无效、或没开通这个模型
        state["failed"] = True
        status = getattr(e, "response", None)
        code = getattr(status, "status_code", "?")
        logger.error(f"[ASR] 上游握手失败 HTTP {code}")
        await _asr_send(ws, {
            "type": "error",
            "message": f"语音服务鉴权失败（HTTP {code}），请检查 DASHSCOPE_API_KEY 与模型 {ASR_MODEL} 是否已开通",
        })
    except Exception as e:
        state["failed"] = True
        logger.error(f"[ASR] 会话异常 task={task_id}: {type(e).__name__}: {e}")
        await _asr_send(ws, {"type": "error", "message": f"语音识别异常：{e}"})
    finally:
        if upstream is not None:
            try:
                await upstream.close()
            except Exception:
                pass

        # ---------- 4. 收尾：把各句最终结果按 sentence_id 拼回整段 ----------
        if not state["failed"]:
            full_text = "".join(state["finals"][k] for k in sorted(state["finals"]))
            await _asr_send(ws, {
                "type": "done",
                "text": full_text,
                "audioBytes": state["audio_bytes"],
                "sentences": len(state["finals"]),
            })
            logger.info(
                f"[ASR] 识别结束 task={task_id} 得到 {len(state['finals'])} 句 / "
                f"{len(full_text)} 字，音频 {state['audio_bytes']} 字节"
            )

        try:
            await ws.close()
        except Exception:
            pass


# ============================================================
# [新增] 管理后台 —— 数据层
# ============================================================
# 这个后台要管四样东西：账号、岗位、题库、面试记录。
# 其中「岗位」和「题库」原来根本不存在于服务端：
#   · 岗位是硬编码在前端 PositionPicker.vue 里的 4 项；
#   · 题目由 Dify 实时生成，本地没有任何题目数据。
# 所以这里先把它们变成真实存储，否则管理界面就只是个改不动的空列表。
POSITIONS_FILE = "positions.json"
QUESTIONS_FILE = "questions.json"
RECORDS_FILE = "interview_records.json"
ANNOUNCEMENTS_FILE = "announcements.json"

# 后台跑马灯的初始文案。同样只在文件不存在时用。
DEFAULT_ANNOUNCEMENTS = [
    "欢迎使用节点 NODE 管理后台 —— 左侧栏可拖动加宽，也可收起为图标条。",
    "公告内容点右侧的编辑按钮即可修改，保存后立即生效。",
]

# 岗位的初始值 = 前端原来硬编码的那 4 项。
# 只用于「文件不存在时」的播种，之后一切以文件为准。
DEFAULT_POSITIONS = [
    {
        "value": "数据开发工程师",
        "icon": "▦",
        "label": "数据开发工程师",
        "desc": "ETL、调度、数仓建模与性能调优",
    },
    {
        "value": "Linux服务器工程师",
        "icon": "⌘",
        "label": "Linux 服务器工程师",
        "desc": "系统运维、排查排障与自动化脚本",
    },
    {
        "value": "前端工程师",
        "icon": "◫",
        "label": "前端工程师",
        "desc": "组件设计、渲染性能与工程化",
    },
    {
        "value": "算法工程师",
        "icon": "◍",
        "label": "算法工程师",
        "desc": "模型选型、特征工程与效果评估",
    },
]


def load_json_file(path, default):
    """读一个 JSON 数据文件；不存在或内容损坏时返回默认值。

    为什么不像 load_users 那样直接 json.loads：
    管理后台的数据文件是【可写】的，一旦某次写坏，直接抛异常会让整个
    服务起不来（模块级调用）。这里降级成默认值，至少服务还能起、还能修。
    """
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
        return json.loads(content) if content else default
    except (OSError, ValueError) as e:
        logger.error(f"[Data] 读取 {path} 失败，回退到默认值: {e}")
        return default


def save_json_file(path, data):
    """写 JSON 数据文件，先写临时文件再原子替换。

    直接 open(path, "w") 会在「已经截断、还没写完」的瞬间留下半个文件 ——
    这时候进程被 kill（改动 main.py 后要手动重启后端，很容易撞上），
    数据就永久损坏了。os.replace 在 Windows 上同样是原子的。
    """
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ============================================================
# [新增] 管理员账号与登录
# ============================================================
# 凭据【只】存在于 .env（已 gitignore）与 users.json 的哈希里。
# 前端一行账号密码都没有 —— 三击手势只是「入口藏起来」，不是权限控制：
# 任何人都能按 F12 看请求，所以真正的闸门必须是服务端的密码校验 + 角色判定。
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

# 管理令牌：内存存储，12 小时过期。
# 用内存而不是签名令牌，是为了不引入新配置项（签名得有个稳定的 secret）。
# 代价是后端重启后管理员需要重新登录 —— 本地开发可以接受。
ADMIN_TOKENS = {}
ADMIN_TOKEN_TTL = int(os.getenv("ADMIN_TOKEN_TTL", str(12 * 3600)))


def bootstrap_admin_account():
    """首次启动时按 .env 创建管理员账号。

    只在账号【不存在】时创建 —— 否则管理端改了密码，下次重启就被覆盖回去了。
    密码在这里就经 hash_password() 转成 PBKDF2 哈希，users.json 里不出现明文。
    """
    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        logger.warning(
            "[Admin] .env 未配置 ADMIN_USERNAME / ADMIN_PASSWORD，"
            "已跳过管理员账号引导（管理后台将无法登录）"
        )
        return

    users = load_users()
    existing = users.get(ADMIN_USERNAME)
    if existing is not None:
        if existing.get("role") != "admin":
            logger.warning(
                f"[Admin] {ADMIN_USERNAME} 已存在但不是管理员角色（role={existing.get('role')}），"
                "为避免覆盖你的账号，启动流程未做改动"
            )
        return

    record = hash_password(ADMIN_PASSWORD)
    record["created_at"] = str(datetime.now())
    record["role"] = "admin"
    record["enabled"] = True
    users[ADMIN_USERNAME] = record
    save_users(users)
    logger.info(f"[Admin] 已按 .env 创建管理员账号 {ADMIN_USERNAME}（密码以 PBKDF2 哈希存储）")


def issue_admin_token(username: str) -> str:
    """发一个管理令牌，顺手清掉过期的。"""
    now = time.time()
    for k in [k for k, v in ADMIN_TOKENS.items() if v["expires_at"] < now]:
        ADMIN_TOKENS.pop(k, None)
    token = secrets.token_urlsafe(32)
    ADMIN_TOKENS[token] = {"username": username, "expires_at": now + ADMIN_TOKEN_TTL}
    return token


def require_admin(x_admin_token: str = Header(default="", alias="X-Admin-Token")):
    """所有 /api/admin/* 接口的统一闸门。

    没有它的话，任何人直接 GET /api/admin/users 就能拿到全部账号列表，
    再 POST 一个重置密码请求就把别人的密码改了 —— 前端藏入口挡不住这个。
    """
    token = (x_admin_token or "").strip()
    record = ADMIN_TOKENS.get(token)
    if not record:
        raise HTTPException(status_code=401, detail="管理员未登录")
    if record["expires_at"] < time.time():
        ADMIN_TOKENS.pop(token, None)
        raise HTTPException(status_code=401, detail="管理员登录已过期，请重新登录")
    return record["username"]


class AdminLoginReq(BaseModel):
    username: str
    password: str


@app.post("/api/auth/admin-login")
def admin_login(req: AdminLoginReq):
    """管理员登录：独立于普通登录，额外校验 role。

    失败原因（账号不存在 / 不是管理员 / 密码错）对外一律回同一句话 ——
    否则「该账号不是管理员」这条错误本身就成了「哪些账号是管理员」的情报。
    真正的原因只写进服务端日志。
    """
    username = (req.username or "").strip()
    users = load_users()
    record = users.get(username)

    if not record or record.get("role") != "admin":
        logger.warning(f"[Admin] 登录失败（账号不存在或非管理员）: {username!r}")
        return {"error": "账号或密码错误"}

    if record.get("enabled") is False:
        logger.warning(f"[Admin] 登录失败（账号已被禁用）: {username!r}")
        return {"error": "该账号已被禁用，请联系系统维护人员"}

    ok, need_upgrade = verify_password(record, req.password)
    if not ok:
        logger.warning(f"[Admin] 登录失败（密码错误）: {username!r}")
        return {"error": "账号或密码错误"}

    if need_upgrade:
        upgraded = hash_password(req.password)
        upgraded["created_at"] = record.get("created_at", str(datetime.now()))
        upgraded["role"] = "admin"
        upgraded["enabled"] = record.get("enabled", True)
        users[username] = upgraded
        save_users(users)

    token = issue_admin_token(username)
    logger.info(f"[Admin] 管理员 {username} 登录成功")
    return {
        "message": "管理员登录成功",
        "token": token,
        "username": username,
        "role": "admin",
        "expires_in": ADMIN_TOKEN_TTL,
    }


@app.post("/api/auth/admin-logout")
def admin_logout(x_admin_token: str = Header(default="", alias="X-Admin-Token")):
    """退出管理后台：把令牌从内存里摘掉，不等它自然过期。"""
    ADMIN_TOKENS.pop((x_admin_token or "").strip(), None)
    return {"message": "已退出管理后台"}


# ============================================================
# [新增] 管理后台 —— 用户管理
# ============================================================
def public_user_view(username, record):
    """对外暴露的用户视图，【绝不】包含 salt / hash。

    单独抽成一个函数，是为了让「脱敏」只有这一处实现 ——
    只要有一处图省事写成 return users，密码哈希就跟着发出去了。
    """
    return {
        "username": username,
        "role": record.get("role", "user"),
        "enabled": record.get("enabled", True),
        "created_at": record.get("created_at", ""),
        "hashed": "hash" in record,
    }


@app.get("/api/admin/users")
def admin_list_users(_admin: str = Depends(require_admin)):
    users = load_users()
    items = [public_user_view(u, r) for u, r in users.items()]
    # 新的在前；管理员再置顶一层（Python 的排序是稳定的，两次 sort 不会互相打乱）
    items.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    items.sort(key=lambda x: 0 if x["role"] == "admin" else 1)
    return {
        "users": items,
        "total": len(items),
        "admins": sum(1 for i in items if i["role"] == "admin"),
        "disabled": sum(1 for i in items if not i["enabled"]),
    }


class ToggleEnabledReq(BaseModel):
    enabled: bool


@app.post("/api/admin/users/{username}/enabled")
def admin_toggle_user(username: str, req: ToggleEnabledReq, admin: str = Depends(require_admin)):
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail=f"账号 {username} 不存在")
    if username == admin:
        raise HTTPException(status_code=400, detail="不能禁用自己的账号")
    if users[username].get("role") == "admin" and not req.enabled:
        # 别把最后一个能用的管理员关掉 —— 关完之后谁也进不来后台，只能去改 .env 重启
        remaining = [
            u
            for u, r in users.items()
            if r.get("role") == "admin" and r.get("enabled", True) and u != username
        ]
        if not remaining:
            raise HTTPException(status_code=400, detail="这是最后一个可用的管理员账号，禁用后将无法登录后台")
    users[username]["enabled"] = bool(req.enabled)
    save_users(users)
    logger.info(f"[Admin] {admin} 将 {username} 设为 {'启用' if req.enabled else '禁用'}")
    return {"message": f"已{'启用' if req.enabled else '禁用'}账号 {username}", "enabled": bool(req.enabled)}


def check_password_policy(password: str) -> str:
    """返回错误说明；通过则返回空串。

    策略与前端表单一致：≥8 位、只能由英文字母和数字组成、且两类都要有。
    前端那份是体验，这份才是约束 —— 绕过界面直接打接口同样会被挡住。
    """
    if len(password or "") < 8:
        return "密码长度不能少于 8 位"
    if not re.fullmatch(r"[A-Za-z0-9]+", password or ""):
        return "密码只能由英文字母和数字组成，不能包含其他字符"
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "密码必须同时包含字母和数字"
    return ""


class ResetPasswordReq(BaseModel):
    password: str


@app.post("/api/admin/users/{username}/password")
def admin_reset_password(username: str, req: ResetPasswordReq, admin: str = Depends(require_admin)):
    err = check_password_policy(req.password)
    if err:
        raise HTTPException(status_code=400, detail=err)

    users = load_users()
    record = users.get(username)
    if record is None:
        raise HTTPException(status_code=404, detail=f"账号 {username} 不存在")

    # 重新生成盐与哈希；旧记录上的 role / enabled / created_at 必须原样带过来，
    # 否则重置密码会顺手把管理员降级成普通用户。
    fresh = hash_password(req.password)
    fresh["created_at"] = record.get("created_at", str(datetime.now()))
    fresh["role"] = record.get("role", "user")
    fresh["enabled"] = record.get("enabled", True)
    users[username] = fresh
    save_users(users)
    logger.info(f"[Admin] {admin} 重置了 {username} 的密码")
    return {"message": f"已重置 {username} 的密码"}


@app.delete("/api/admin/users/{username}")
def admin_delete_user(username: str, admin: str = Depends(require_admin)):
    if username == admin:
        raise HTTPException(status_code=400, detail="不能删除自己的账号")
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail=f"账号 {username} 不存在")
    if users[username].get("role") == "admin":
        if not [u for u, r in users.items() if r.get("role") == "admin" and u != username]:
            raise HTTPException(status_code=400, detail="这是最后一个管理员账号，删除后将无法登录后台")
    users.pop(username)
    save_users(users)
    logger.info(f"[Admin] {admin} 删除了账号 {username}")
    return {"message": f"已删除账号 {username}"}


# ============================================================
# [新增] 管理后台 —— 岗位管理
# ============================================================
@app.get("/api/version")
def get_version():
    """对外暴露版本号 —— 管理后台「系统状态」页和排查问题都用它。"""
    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "build": BUILD_DATE,
        "api": "v1",
    }


@app.get("/api/positions")
def list_positions():
    """公开接口，给前端 PositionPicker 读。

    这四个岗位原来是硬编码在 PositionPicker.vue 里的 ——
    不改成读接口的话，管理端改了岗位前端纹丝不动，「岗位管理」就是个假功能。
    """
    return {"positions": load_json_file(POSITIONS_FILE, DEFAULT_POSITIONS)}


class PositionReq(BaseModel):
    value: str
    label: str = ""
    desc: str = ""
    icon: str = ""


def _clean_position(req: PositionReq, fallback_icon: str = "◆"):
    value = (req.value or "").strip()
    return {
        "value": value,
        "label": (req.label or value).strip(),
        "desc": (req.desc or "").strip(),
        "icon": (req.icon or "").strip() or fallback_icon,
    }


@app.post("/api/admin/positions")
def admin_create_position(req: PositionReq, _admin: str = Depends(require_admin)):
    item = _clean_position(req)
    if not item["value"]:
        raise HTTPException(status_code=400, detail="岗位名称不能为空")
    items = load_json_file(POSITIONS_FILE, DEFAULT_POSITIONS)
    if any(i.get("value") == item["value"] for i in items):
        raise HTTPException(status_code=400, detail=f"岗位「{item['value']}」已存在")
    items.append(item)
    save_json_file(POSITIONS_FILE, items)
    logger.info(f"[Admin] 新增岗位「{item['value']}」")
    return {"message": f"已新增岗位「{item['value']}」", "position": item, "total": len(items)}


@app.put("/api/admin/positions/{original}")
def admin_update_position(original: str, req: PositionReq, _admin: str = Depends(require_admin)):
    items = load_json_file(POSITIONS_FILE, DEFAULT_POSITIONS)
    index = next((i for i, x in enumerate(items) if x.get("value") == original), -1)
    if index < 0:
        raise HTTPException(status_code=404, detail=f"岗位「{original}」不存在")
    updated = _clean_position(req, items[index].get("icon", "◆"))
    if not updated["value"]:
        raise HTTPException(status_code=400, detail="岗位名称不能为空")
    if updated["value"] != original and any(i.get("value") == updated["value"] for i in items):
        raise HTTPException(status_code=400, detail=f"岗位「{updated['value']}」已存在")
    items[index] = updated
    save_json_file(POSITIONS_FILE, items)
    logger.info(f"[Admin] 岗位「{original}」改为「{updated['value']}」")
    return {"message": f"已更新岗位「{updated['value']}」", "position": updated}


@app.delete("/api/admin/positions/{value}")
def admin_delete_position(value: str, _admin: str = Depends(require_admin)):
    items = load_json_file(POSITIONS_FILE, DEFAULT_POSITIONS)
    left = [i for i in items if i.get("value") != value]
    if len(left) == len(items):
        raise HTTPException(status_code=404, detail=f"岗位「{value}」不存在")
    if not left:
        # 全删光的话前端就没有岗位可选，面试根本开不起来
        raise HTTPException(status_code=400, detail="至少要保留一个岗位，否则无法开始面试")
    save_json_file(POSITIONS_FILE, left)
    logger.info(f"[Admin] 删除岗位「{value}」")
    return {"message": f"已删除岗位「{value}」", "total": len(left)}


# ============================================================
# [新增] 简历存储 —— 用户端「简历管理」
# ============================================================
# 为什么放到服务端：简历原本只存在浏览器 localStorage（键名被 userStorage.js
# 前缀成 `<用户名>_saved_resumes`），换个浏览器、清一次缓存就全没了。
#
# 归属怎么定：按【用户名】分组，用户名由前端从 localStorage.username 带上来。
# 必须写清这里的信任边界 —— 这个 username 是【客户端自述】的，没有任何 token
# 校验，所以知道别人的用户名就能读别人的简历。当前定位是「跨设备同步自己的数据」，
# 不是「防越权」。将来要收紧，得先把 /api/auth/login 发的 token 变成后端真正校验的凭据。
#
# 原子性：save_json_file 已是「写临时文件 + os.replace」，不会写坏。
# 对照：users.json 用的 save_users() 至今不是原子的 —— 那是另一个待办。
RESUMES_FILE = "resumes.json"

# 白名单。为什么不直接把整个对象存下来：前端会把整个简历对象 PUT 上来，
# 若原样落盘，将来前端给对象挂任何临时字段（如 isExpanded）都会被写进文件，
# 数据文件会慢慢被前端内部状态污染。
RESUME_FIELDS = (
    "id", "title", "name", "gender", "age", "phone", "photo", "school",
    "resume", "schoolExperience", "workExperience", "projectExperience",
    "skillProficiency", "jobIntention", "customModules", "savedAt",
    "aiAnalyzed", "aiResultText", "aiSectionsData", "aiScoresData",
)


class ResumePayload(BaseModel):
    """简历本体。字段与前端 ResumeView 的 form 一一对应。"""

    id: str = ""
    title: str = ""
    name: str = ""
    gender: str = ""
    age: str = ""
    phone: str = ""
    photo: str = ""
    school: str = ""
    resume: str = ""
    schoolExperience: str = ""
    workExperience: str = ""
    projectExperience: str = ""
    skillProficiency: str = ""
    jobIntention: str = ""
    customModules: list = []
    # 前端存的是 Date.now() 的毫秒时间戳（数字），旧本地数据也是数字，
    # 所以这里必须收数字 —— Pydantic v2 不会把 int 转成 str，写成 str 会直接校验失败。
    # 带上 str 是为了兼容历史上可能已经写成字符串的记录。
    savedAt: float | str = 0
    aiAnalyzed: bool = False
    aiResultText: str = ""
    aiSectionsData: list = []
    aiScoresData: dict | None = None


class ResumeSaveReq(BaseModel):
    username: str
    resume: ResumePayload


class ResumeBulkReq(BaseModel):
    username: str
    resumes: list[ResumePayload] = []


def _resume_clean(raw: dict) -> dict:
    item = {}
    for k in RESUME_FIELDS:
        v = raw.get(k)
        if isinstance(v, str):
            v = v.strip()
        item[k] = v
    item["customModules"] = item.get("customModules") or []
    item["aiSectionsData"] = item.get("aiSectionsData") or []
    return item


def _load_resumes() -> dict:
    """读全量。文件不存在或格式坏了都退回 {}，不让一个坏文件把接口打成 500。"""
    data = load_json_file(RESUMES_FILE, {})
    return data if isinstance(data, dict) else {}


@app.get("/api/resumes")
def list_resumes(username: str = ""):
    who = (username or "").strip()
    if not who:
        return {"resumes": [], "total": 0}
    items = _load_resumes().get(who, [])
    return {"resumes": items, "total": len(items)}


@app.post("/api/resumes")
def upsert_resume(req: ResumeSaveReq):
    """新建与修改共用。按 id 判断：带上的 id 已存在就原地替换，否则插到最前。

    为什么不做成 POST 新建 + PUT 修改两套：前端「修改简历」弹窗提交时对象是完整的，
    分两个接口只会让「id 到底存不存在」这个判断在多处重复一遍。
    """
    who = (req.username or "").strip()
    if not who:
        raise HTTPException(status_code=400, detail="缺少用户名")
    item = _resume_clean(req.resume.model_dump())
    if not item["id"]:
        item["id"] = f"res-{secrets.token_hex(8)}"
    data = _load_resumes()
    items = data.get(who, [])
    idx = next((i for i, x in enumerate(items) if x.get("id") == item["id"]), -1)
    if idx >= 0:
        items[idx] = item
        action = "更新"
    else:
        items.insert(0, item)
        action = "新增"
    data[who] = items
    save_json_file(RESUMES_FILE, data)
    logger.info(
        f"[Resume] {who} {action}简历「{item.get('title') or item.get('name') or item['id']}」"
    )
    return {"message": f"简历已{action}", "resume": item, "total": len(items)}


@app.post("/api/resumes/bulk")
def bulk_import_resumes(req: ResumeBulkReq):
    """首次加载时把浏览器里的存量简历一次性搬上来。

    语义是【按 id 去重后追加】而不是覆盖：已有的不动。
    这样重复调用是安全的（页面每次加载都会调一次），
    也不会把已经在服务端改过的内容冲回旧版本。
    """
    who = (req.username or "").strip()
    if not who:
        raise HTTPException(status_code=400, detail="缺少用户名")
    data = _load_resumes()
    items = data.get(who, [])
    if not req.resumes:
        return {"message": "没有需要导入的简历", "imported": 0, "total": len(items)}
    have = {i.get("id") for i in items}
    added = 0
    for r in req.resumes:
        item = _resume_clean(r.model_dump())
        if not item["id"]:
            item["id"] = f"res-{secrets.token_hex(8)}"
        if item["id"] in have:
            continue
        items.append(item)
        have.add(item["id"])
        added += 1
    data[who] = items
    save_json_file(RESUMES_FILE, data)
    logger.info(f"[Resume] 已为 {who} 从本地迁移 {added} 份简历")
    return {"message": f"已导入 {added} 份简历", "imported": added, "total": len(items)}


@app.delete("/api/resumes/{resume_id}")
def delete_resume(resume_id: str, username: str = ""):
    who = (username or "").strip()
    if not who:
        raise HTTPException(status_code=400, detail="缺少用户名")
    data = _load_resumes()
    items = data.get(who, [])
    left = [i for i in items if i.get("id") != resume_id]
    if len(left) == len(items):
        raise HTTPException(status_code=404, detail="简历不存在")
    data[who] = left
    save_json_file(RESUMES_FILE, data)
    logger.info(f"[Resume] {who} 删除简历 {resume_id}")
    return {"message": "已删除", "total": len(left)}


# ============================================================
# [新增] 界面配色 —— 令牌级颜色控制
# ============================================================
# 存哪：ui_theme.json。键是界面名（interview / data / me / admin），
# 值是 { "light": {"accent","hover","highlight"}, "dark": {...} }。
#
# 为什么只存【覆盖】而不是全量下发：前端 uiTheme.js 自带默认色板，
# 文件里没出现的界面就继续用 base.css 的硬编码值。这一点很关键 ——
# 从 6 个输入色推导出的 18 个令牌里，有 8 个与原手调值存在偏差
# （--accent-soft 最大差 49/255，原值是手挑的、色相都不同，无法由主色推出）。
# 若默认就全量下发，那些没人动过配色的工作台外观也会跟着变。
#
# 读接口是公开的：未登录的首页也要拿到配置才能上色。
# 写接口必须带 X-Admin-Token。
UI_THEME_FILE = "ui_theme.json"


class UiThemeReq(BaseModel):
    theme: dict


@app.get("/api/ui-theme")
def get_ui_theme():
    data = load_json_file(UI_THEME_FILE, None)
    return {"theme": data if isinstance(data, dict) else None}


@app.put("/api/admin/ui-theme")
def set_ui_theme(req: UiThemeReq, _admin: str = Depends(require_admin)):
    """整份覆盖。

    只做结构校验，色值合法性交给前端的 isHex —— 后端不认识具体色名，
    在这儿硬校验每种取值反而会在将来加字段时挡路。
    """
    if not isinstance(req.theme, dict):
        raise HTTPException(status_code=400, detail="theme 必须是对象")
    if not req.theme:
        raise HTTPException(status_code=400, detail="至少要配置一个界面")
    save_json_file(UI_THEME_FILE, req.theme)
    logger.info(f"[UITheme] 管理员更新了界面配色：{', '.join(req.theme.keys())}")
    return {"message": "配色已保存", "theme": req.theme}


@app.delete("/api/admin/ui-theme")
def reset_ui_theme(_admin: str = Depends(require_admin)):
    """恢复默认：直接删文件。文件不存在 → 读接口返回 None → 前端回落默认色板。"""
    if os.path.exists(UI_THEME_FILE):
        os.remove(UI_THEME_FILE)
    logger.info("[UITheme] 已恢复默认配色")
    return {"message": "已恢复默认配色"}


# ============================================================
# [新增] 管理后台 —— 题库管理
# ============================================================
# 先说清一件容易误解的事：题库【不会】改变 AI 面试官问什么。
# 题目仍由 Dify 实时生成，而那个应用的输入变量是固定的 6 个
# （position / user_name / Age / degree / jianli / work__exeperience），
# 没有给题目留位置。
# 题库目前唯一真实生效的地方是【ASR 即时热词】：把题目里的专业术语
# 拿去提升语音识别准确率（见下面的 build_question_vocabulary）。
# 不做这一步的话，这个模块就只是个能增删改查的空列表。
BANKS_FILE = "question_banks.json"


def load_banks():
    data = load_json_file(BANKS_FILE, [])
    return data if isinstance(data, list) else []


def save_banks(banks):
    # 原子写。题库是用户上传的原始资料，写坏了没法恢复（Excel 还在手机里但人会跑）
    save_json_file(BANKS_FILE, banks)


def load_questions():
    """把所有题库里的题目摊平。

    保留这个函数是因为 ASR 热词（build_question_vocabulary）还在用它 ——
    换成多题库之后，那个函数不该关心题目属于哪个库。
    """
    out = []
    for b in load_banks():
        out.extend(b.get("questions") or [])
    return out


# ---------- 极简 xlsx 读取（零依赖）----------
# 为什么不用 openpyxl / pandas：后端虚拟环境里没有它们，装包要联网、要改环境。
# xlsx 本质是一个 zip 包，里面 sharedStrings.xml（共享字符串）+ sheetN.xml（单元格），
# 用标准库的 zipfile + ElementTree 就够读「一个表头 + 若干行文本」这种简单表格。
# 已知限制：只取第一个工作表；不处理合并单元格、公式、样式 —— 本项目的题库都用不到。
XLSX_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def _col_index(letters: str) -> int:
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch.upper()) - 64)
    return n - 1


def _xlsx_parse_sheet(z, shared, sheet_path):
    """解析单个工作表，返回 [[字符串, ...], ...]。"""
    from xml.etree import ElementTree as ET

    root = ET.fromstring(z.read(sheet_path))
    rows = []
    for row in root.iter(f"{XLSX_NS}row"):
        cells = {}
        for c in row.findall(f"{XLSX_NS}c"):
            ref = c.get("r") or ""
            letters = "".join(ch for ch in ref if ch.isalpha())
            if not letters:
                continue
            idx = _col_index(letters)
            t = c.get("t")
            v = c.find(f"{XLSX_NS}v")
            if t == "s" and v is not None and v.text is not None:
                i = int(v.text)
                val = shared[i] if 0 <= i < len(shared) else ""
            elif t == "inlineStr":
                node = c.find(f"{XLSX_NS}is")
                val = "".join(x.text or "" for x in node.iter(f"{XLSX_NS}t")) if node is not None else ""
            else:
                val = v.text if v is not None and v.text is not None else ""
            cells[idx] = str(val).strip()
        if not cells:
            continue
        width = max(cells) + 1
        rows.append([cells.get(i, "") for i in range(width)])
    return rows


def read_xlsx_sheets(raw: bytes):
    """返回 [(工作表名, 行列表), ...]，按工作表顺序排列。

    客观题的 Excel 通常把「单选题 / 多选题 / 判断题」分成不同工作表存放，
    只读第一个工作表会把后两种题型整段丢掉 —— 这正是「上传后看不到选项」的原因。
    """
    import io as _io
    import zipfile
    from xml.etree import ElementTree as ET

    with zipfile.ZipFile(_io.BytesIO(raw)) as z:
        names = z.namelist()
        shared = []
        if "xl/sharedStrings.xml" in names:
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall(f"{XLSX_NS}si"):
                shared.append("".join(t.text or "" for t in si.iter(f"{XLSX_NS}t")))

        # 工作表显示名（用于前缀「多选题」之类的判断）
        title_by_index = {}
        try:
            wb = ET.fromstring(z.read("xl/workbook.xml"))
            for i, sh in enumerate(wb.iter(f"{XLSX_NS}sheet"), start=1):
                title_by_index[i] = sh.get("name") or f"Sheet{i}"
        except Exception:
            pass

        found = []
        for n in names:
            if not (n.startswith("xl/worksheets/sheet") and n.endswith(".xml")):
                continue
            m = re.search(r"sheet(\d+)\.xml$", n)
            order = int(m.group(1)) if m else 9999
            try:
                rows = _xlsx_parse_sheet(z, shared, n)
            except Exception:
                continue
            if rows:
                found.append((order, title_by_index.get(order, f"Sheet{order}"), rows))

        found.sort(key=lambda x: x[0])
        return [(name, rows) for _, name, rows in found]


def read_xlsx_rows(raw: bytes):
    """返回第一个工作表的行（保留旧调用方）。"""
    sheets = read_xlsx_sheets(raw)
    return sheets[0][1] if sheets else []


# 表头识别：按中文列名找下标，找不到就退回固定顺序（Excel 缺表头时也能导）
COLUMN_ALIASES = {
    "no": ["题号", "序号", "编号", "no", "id"],
    "type": ["题型", "题目类型", "类型", "type"],
    "title": ["题目", "题干", "问题", "question", "title"],
    "optA": ["选项a", "选项1", "a"],
    "optB": ["选项b", "选项2", "b"],
    "optC": ["选项c", "选项3", "c"],
    "optD": ["选项d", "选项4", "d"],
    "correct": ["正确答案", "正确选项", "correct"],
    "explain": ["解析", "答案解析", "解释", "explain"],
    "answer": ["参考答案", "答案", "answer"],
    "difficulty": ["难度", "difficulty", "level"],
    "category": ["知识点分类", "知识点", "分类", "category", "knowledge"],
    "position": ["岗位", "适用岗位", "position", "job"],
}


def _normalize_correct(qtype, correct, options):
    """把「正确答案」统一成选项字母（多选题按字母升序拼接）。

    判断题的答案列常写成「正确 / 错误」，要按选项文本反查成 A / B，
    否则前端拿正确答案和用户选择没法直接比对。
    """
    c = (correct or "").strip()
    if not options:
        return c

    if "判断" in (qtype or ""):
        for o in options:
            text = (o.get("text") or "").strip()
            if c and (c == text or c in text or text in c):
                return o["key"]

    letters = re.findall(r"[A-Za-z]", c.upper())
    if letters:
        return "".join(sorted(set(letters)))

    # 答案写成选项原文时反查
    for o in options:
        if c and c == (o.get("text") or "").strip():
            return o["key"]
    return c


def _guess_type(raw_type, options, correct):
    """用户没填「题型」时按内容推断，避免所有题都被当成问答题。"""
    t = (raw_type or "").strip()
    if t:
        return t
    if options:
        letters = re.findall(r"[A-Za-z]", (correct or "").upper())
        return "多选题" if len(set(letters)) > 1 else "单选题"
    return "问答题"


def _map_columns(header):
    lower = [str(h or "").strip().lower() for h in header]
    idx = {}
    for key, aliases in COLUMN_ALIASES.items():
        for a in aliases:
            if a.lower() in lower:
                idx[key] = lower.index(a.lower())
                break
    return idx


class BankUploadReq(BaseModel):
    name: str = ""
    filename: str = ""
    data_base64: str


@app.post("/api/admin/banks/upload")
def admin_upload_bank(req: BankUploadReq, _admin: str = Depends(require_admin)):
    """上传 Excel 建立新题库。前端把文件读成 base64 发过来 ——
    这样后端不需要 python-multipart（虚拟环境里没装）。"""
    import base64

    try:
        raw = base64.b64decode(req.data_base64 or "", validate=False)
    except Exception:
        raise HTTPException(status_code=400, detail="文件内容解析失败")
    if not raw:
        raise HTTPException(status_code=400, detail="文件是空的")

    try:
        sheets = read_xlsx_sheets(raw)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"不是有效的 Excel 文件：{e}")
    if not sheets:
        raise HTTPException(status_code=400, detail="表格里没有可解析的工作表")

    def cell(row, idx, key, default=""):
        i = idx.get(key)
        if i is None or i >= len(row):
            return default
        return (row[i] or "").strip()

    questions = []
    used_sheets = []
    skipped_sheets = []
    # 逐个工作表解析：单选 / 多选 / 判断 常被分在不同表里，只读第一张会丢题型
    for sheet_name, rows in sheets:
        if len(rows) < 2:
            skipped_sheets.append(sheet_name)
            continue
        header, body = rows[0], rows[1:]
        idx = _map_columns(header)
        if "title" not in idx:
            skipped_sheets.append(sheet_name)
            continue
        used_sheets.append(sheet_name)

        for n, row in enumerate(body, start=1):
            title = cell(row, idx, "title")
            if not title:
                continue

            options = []
            for key, label in (("optA", "A"), ("optB", "B"), ("optC", "C"), ("optD", "D")):
                text = cell(row, idx, key)
                if text:
                    options.append({"key": label, "text": text})

            raw_type = cell(row, idx, "type")
            correct = cell(row, idx, "correct")
            explain = cell(row, idx, "explain")
            qtype = _guess_type(raw_type, options, correct)

            questions.append(
                {
                    "id": uuid.uuid4().hex[:12],
                    "no": cell(row, idx, "no") or str(n),
                    "type": qtype,
                    "title": title,
                    "options": options,
                    "correct": _normalize_correct(qtype, correct, options),
                    "explain": explain,
                    "answer": cell(row, idx, "answer"),
                    "difficulty": cell(row, idx, "difficulty") or "基础",
                    "category": cell(row, idx, "category"),
                    "position": cell(row, idx, "position"),
                }
            )

    if not questions:
        raise HTTPException(
            status_code=400,
            detail=f"没有解析出任何题目。检查过的表：{'、'.join(used_sheets + skipped_sheets) or '空'}",
        )

    name = (req.name or "").strip() or (req.filename or "未命名题库").rsplit(".", 1)[0]
    banks = load_banks()
    bank = {
        "id": f"bank-{uuid.uuid4().hex[:10]}",
        "name": name,
        "source": (req.filename or "").strip(),
        "created_at": str(datetime.now()),
        "questions": questions,
    }
    banks.insert(0, bank)
    save_banks(banks)
    logger.info(f"[Bank] 上传题库「{name}」：{len(questions)} 道题")
    return {"message": f"已导入 {len(questions)} 道题", "bank": {**bank, "questions": []}, "total": len(questions)}


@app.get("/api/admin/banks")
def admin_list_banks(_admin: str = Depends(require_admin)):
    banks = load_banks()
    return {
        "banks": [
            {
                "id": b.get("id"),
                "name": b.get("name"),
                "source": b.get("source"),
                "created_at": b.get("created_at"),
                "count": len(b.get("questions") or []),
            }
            for b in banks
        ]
    }


@app.post("/api/admin/banks")
def admin_create_bank(req: dict, _admin: str = Depends(require_admin)):
    name = str(req.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="题库名称不能为空")
    banks = load_banks()
    bank = {
        "id": f"bank-{uuid.uuid4().hex[:10]}",
        "name": name,
        "source": "",
        "created_at": str(datetime.now()),
        "questions": [],
    }
    banks.insert(0, bank)
    save_banks(banks)
    return {"message": "已新建题库", "bank": bank}


class BankRenameReq(BaseModel):
    name: str


@app.put("/api/admin/banks/{bank_id}")
def admin_rename_bank(bank_id: str, req: BankRenameReq, _admin: str = Depends(require_admin)):
    """重命名题库。

    题库名现在会直接显示给用户端当「岗位」分类，所以名称是用户可见的文案，
    不是内部标识 —— 改名不影响题目和 id，只换 label。
    """
    name = (req.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="题库名称不能为空")
    banks = load_banks()
    bank = _find_bank(banks, bank_id)
    if not bank:
        raise HTTPException(status_code=404, detail="题库不存在")
    if any(b.get("id") != bank_id and (b.get("name") or "") == name for b in banks):
        raise HTTPException(status_code=400, detail=f"已存在同名题库「{name}」")
    old = bank.get("name")
    bank["name"] = name
    save_banks(banks)
    logger.info(f"[Bank] 题库《{old}》改名为《{name}》")
    return {"message": f"已重命名为「{name}」", "bank": {**bank, "questions": []}}


@app.delete("/api/admin/banks/{bank_id}")
def admin_delete_bank(bank_id: str, _admin: str = Depends(require_admin)):
    banks = load_banks()
    left = [b for b in banks if b.get("id") != bank_id]
    if len(left) == len(banks):
        raise HTTPException(status_code=404, detail="题库不存在")
    save_banks(left)
    return {"message": "已删除题库", "total": len(left)}


@app.get("/api/banks")
def list_banks_public():
    """用户端用：只给题库名和题目数，不暴露答案。"""
    return {
        "banks": [
            {"id": b.get("id"), "name": b.get("name"), "count": len(b.get("questions") or [])}
            for b in load_banks()
        ]
    }


@app.get("/api/banks/{bank_id}")
def get_bank_public(bank_id: str):
    bank = next((b for b in load_banks() if b.get("id") == bank_id), None)
    if not bank:
        raise HTTPException(status_code=404, detail="题库不存在")
    return {"id": bank.get("id"), "name": bank.get("name"), "questions": bank.get("questions") or []}


@app.get("/api/admin/banks/{bank_id}/questions")
def list_bank_questions(bank_id: str, _admin: str = Depends(require_admin)):
    """管理端读某个题库的全部题目。

    路径必须带 /admin 前缀 —— 之前写成 /api/banks/{id}/questions，
    和前端请求的 /api/admin/banks/{id}/questions 对不上，
    表现就是「题目列表打不开、标题显示共 0 题」。
    """
    bank = next((b for b in load_banks() if b.get("id") == bank_id), None)
    if not bank:
        raise HTTPException(status_code=404, detail="题库不存在")
    return {"questions": bank.get("questions") or []}




# ============================================================
# [新增] 上传两步走：先解析出预览，人工确认后再入库
# ============================================================
class BankParseReq(BaseModel):
    filename: str = ""
    data_base64: str


class BankCommitReq(BaseModel):
    name: str = ""
    source: str = ""
    questions: list


def _questions_from_sheets(raw):
    """把 Excel 的所有工作表解析成题目列表（不落库）。

    列名靠 COLUMN_ALIASES 自适应识别，不依赖固定顺序；
    识别不到的字段留空，由 _question_missing() 标出「待补充」。
    """
    sheets = read_xlsx_sheets(raw)
    questions = []
    used, skipped = [], []

    for sheet_name, rows in sheets:
        if len(rows) < 2:
            skipped.append(sheet_name)
            continue
        header, body = rows[0], rows[1:]
        idx = _map_columns(header)
        if "title" not in idx:
            skipped.append(sheet_name)
            continue
        used.append(sheet_name)

        def cell(row, key, default=""):
            i = idx.get(key)
            if i is None or i >= len(row):
                return default
            return (row[i] or "").strip()

        for n, row in enumerate(body, start=1):
            title = cell(row, "title")
            if not title:
                continue
            options = []
            for key, label in (("optA", "A"), ("optB", "B"), ("optC", "C"), ("optD", "D")):
                text = cell(row, key)
                if text:
                    options.append({"key": label, "text": text})
            questions.append(
                _make_question(
                    {
                        "no": cell(row, "no") or str(n),
                        "type": cell(row, "type"),
                        "title": title,
                        "options": options,
                        "correct": cell(row, "correct"),
                        "explain": cell(row, "explain"),
                        "answer": cell(row, "answer"),
                        "difficulty": cell(row, "difficulty"),
                        "category": cell(row, "category"),
                        "position": cell(row, "position"),
                    },
                    fallback_no=str(n),
                )
            )

    return questions, used, skipped


@app.post("/api/admin/banks/parse")
def admin_parse_bank(req: BankParseReq, _admin: str = Depends(require_admin)):
    """只解析、不入库 —— 前端拿结果做可编辑预览，人工确认后再调 commit。"""
    import base64

    try:
        raw = base64.b64decode(req.data_base64 or "", validate=False)
    except Exception:
        raise HTTPException(status_code=400, detail="文件内容解析失败")
    if not raw:
        raise HTTPException(status_code=400, detail="文件是空的")
    try:
        questions, used, skipped = _questions_from_sheets(raw)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"不是有效的 Excel 文件：{e}")
    if not questions:
        raise HTTPException(
            status_code=400,
            detail="没有解析出任何题目。请确认表里有一列叫「题目」（或「题干 / 问题」）",
        )

    lacking = sum(1 for q in questions if q.get("missing"))
    return {
        "questions": questions,
        "sheets": used,
        "skipped": skipped,
        "total": len(questions),
        "lacking": lacking,
        "suggestName": (req.filename or "").rsplit(".", 1)[0] or "未命名题库",
    }


@app.post("/api/admin/banks/commit")
def admin_commit_bank(req: BankCommitReq, _admin: str = Depends(require_admin)):
    """把预览里（可能已手工修正过）的题目正式入库。"""
    clean = []
    for i, q in enumerate(req.questions or [], start=1):
        if not isinstance(q, dict):
            continue
        if not str(q.get("title") or "").strip():
            continue
        clean.append(_make_question(q, fallback_no=str(i)))
    if not clean:
        raise HTTPException(status_code=400, detail="没有可导入的题目")

    name = (req.name or "").strip() or "未命名题库"
    banks = load_banks()
    bank = {
        "id": f"bank-{uuid.uuid4().hex[:10]}",
        "name": name,
        "source": (req.source or "").strip(),
        "created_at": str(datetime.now()),
        "questions": clean,
    }
    banks.insert(0, bank)
    save_banks(banks)

    lacking = sum(1 for q in clean if q.get("missing"))
    logger.info(f"[Bank] 确认导入「{name}」：{len(clean)} 道题，待补充 {lacking} 道")
    return {
        "message": f"已导入 {len(clean)} 道题" + (f"，其中 {lacking} 道待补充" if lacking else ""),
        "bank": {**bank, "questions": []},
        "total": len(clean),
        "lacking": lacking,
    }


@app.get("/api/admin/questions")
def admin_all_questions(_admin: str = Depends(require_admin)):
    """跨题库的题目总表 —— 管理页用「岗位 + 知识点 + 难度 + 题型 + 关键词」定位。"""
    out = []
    for b in load_banks():
        for q in b.get("questions") or []:
            item = dict(q)
            item["bankId"] = b.get("id")
            item["bank"] = b.get("name")
            item["missing"] = _question_missing(item)
            out.append(item)
    return {"questions": out, "total": len(out)}


def build_question_vocabulary():
    """把题库里的术语汇成 ASR 热词。

    取舍：权重固定 5（「很想要」档），不取 50（超级热词）——
    超级热词官方上限 50 个，是留给「岗位名」这类一错就全盘皆输的词，
    题库术语数量不可控，抢了配额反而会挤掉更关键的词。
    """
    vocab = {}
    for q in load_questions():
        if not isinstance(q, dict):
            continue
        for term in (q.get("terms") or []):
            term = str(term).strip()
            if len(term) >= 2 and term not in vocab:
                vocab[term] = 5
    return vocab


@app.get("/api/admin/questions")
def admin_list_questions(_admin: str = Depends(require_admin)):
    items = load_questions()
    return {"questions": items, "total": len(items)}


class QuestionReq(BaseModel):
    no: str = ""
    title: str
    type: str = "问答题"
    options: list = []
    correct: str = ""
    explain: str = ""
    answer: str = ""
    difficulty: str = "基础"
    category: str = ""
    position: str = ""


def _norm_options(raw):
    """选项归一化：只保留 {key, text} 且都有值的项，按字母排序。"""
    out = []
    for o in raw or []:
        if not isinstance(o, dict):
            continue
        k = str(o.get("key") or "").strip().upper()[:1]
        t = str(o.get("text") or "").strip()
        if k and t:
            out.append({"key": k, "text": t})
    out.sort(key=lambda x: x["key"])
    return out


def _question_missing(q):
    """返回缺失项列表，空列表表示信息完整。

    客观题（单选/多选/判断）必须有选项和正确答案；主观题必须有参考答案。
    这就是「系统读不到答案或选项时提示管理者补充」的判据。
    """
    missing = []
    qtype = q.get("type") or "问答题"
    options = q.get("options") or []
    correct = (q.get("correct") or "").strip().upper()

    if qtype in ("单选题", "多选题", "判断题"):
        if len(options) < 2:
            missing.append("选项")
        if not correct:
            missing.append("正确答案")
        else:
            keys = {o["key"] for o in options}
            if not set(re.findall(r"[A-Z]", correct)).issubset(keys):
                missing.append("正确答案")
    else:
        if not (q.get("answer") or "").strip():
            missing.append("参考答案")
    return missing


def _make_question(src, fallback_no="1"):
    """把任意来源（Excel 行 / 前端提交 / 旧数据）整理成统一题目结构。"""
    d = src if isinstance(src, dict) else {}
    title = str(d.get("title") or "").strip()
    options = _norm_options(d.get("options"))
    qtype = _guess_type(d.get("type"), options, d.get("correct"))
    item = {
        "id": str(d.get("id") or uuid.uuid4().hex[:12]),
        "no": str(d.get("no") or fallback_no).strip(),
        "type": qtype,
        "title": title,
        "options": options,
        "correct": _normalize_correct(qtype, d.get("correct"), options),
        "explain": str(d.get("explain") or "").strip(),
        "answer": str(d.get("answer") or "").strip(),
        "difficulty": str(d.get("difficulty") or "基础").strip() or "基础",
        "category": str(d.get("category") or "").strip(),
        "position": str(d.get("position") or "").strip(),
    }
    item["missing"] = _question_missing(item)
    return item


def _find_bank(banks, bank_id):
    for b in banks:
        if b.get("id") == bank_id:
            return b
    return None


@app.post("/api/admin/banks/{bank_id}/questions")
def admin_add_question(bank_id: str, req: QuestionReq, _admin: str = Depends(require_admin)):
    banks = load_banks()
    bank = _find_bank(banks, bank_id)
    if not bank:
        raise HTTPException(status_code=404, detail="题库不存在")
    title = (req.title or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="题干不能为空")
    item = _make_question(
        req.model_dump(), fallback_no=str(len(bank.get("questions") or []) + 1)
    )
    bank.setdefault("questions", []).insert(0, item)
    save_banks(banks)
    logger.info(f"[Bank] 「{bank.get('name')}」新增题目：{title[:24]}")
    return {"message": "已新增题目", "question": item, "total": len(bank["questions"])}


@app.put("/api/admin/banks/{bank_id}/questions/{qid}")
def admin_update_question(bank_id: str, qid: str, req: QuestionReq, _admin: str = Depends(require_admin)):
    banks = load_banks()
    bank = _find_bank(banks, bank_id)
    if not bank:
        raise HTTPException(status_code=404, detail="题库不存在")
    items = bank.get("questions") or []
    index = next((i for i, x in enumerate(items) if str(x.get("id")) == qid), -1)
    if index < 0:
        raise HTTPException(status_code=404, detail="题目不存在")
    title = (req.title or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="题干不能为空")
    merged = {**items[index], **req.model_dump(), "id": items[index].get("id")}
    items[index] = _make_question(merged, fallback_no=items[index].get("no") or "1")
    save_banks(banks)
    return {"message": "已更新题目", "question": items[index]}


@app.delete("/api/admin/banks/{bank_id}/questions/{qid}")
def admin_delete_question(bank_id: str, qid: str, _admin: str = Depends(require_admin)):
    banks = load_banks()
    bank = _find_bank(banks, bank_id)
    if not bank:
        raise HTTPException(status_code=404, detail="题库不存在")
    items = bank.get("questions") or []
    left = [x for x in items if str(x.get("id")) != qid]
    if len(left) == len(items):
        raise HTTPException(status_code=404, detail="题目不存在")
    bank["questions"] = left
    save_banks(banks)
    return {"message": "已删除题目", "total": len(left)}


# ---------- AI 评分：拿参考答案对比，让模型逐题打分 ----------
class PracticeScoreReq(BaseModel):
    items: list          # [{question, reference, answer}]


SCORE_PROMPT = """你是严格但公正的技术面试官。下面是一批「题目 / 参考答案 / 候选人回答」，请逐条评分。

评分标准（满分 10 分）：
- 9-10：要点基本齐全，表述准确
- 6-8：抓到主要要点，遗漏了个别关键点
- 3-5：只说对了一部分，或方向对但深度不足
- 0-2：答错、答非所问，或基本没答

只输出 JSON，不要任何解释、不要代码块围栏。格式：
{"items":[{"id":0,"score":8,"comment":"一句话点评"}]}
id 与输入的方括号序号一致。"""


@app.post("/api/practice/score")
def practice_score(req: PracticeScoreReq):
    """按参考答案给开放题打分。

    为什么放后端：模型密钥在服务端，前端拿不到 —— 也就不存在把 Key 塞进浏览器的风险。
    """
    items = req.items or []
    if not items:
        raise HTTPException(status_code=400, detail="没有需要评分的作答")

    key = os.getenv("DASHSCOPE_API_KEY")
    if not key:
        raise HTTPException(status_code=500, detail="服务端未配置评分模型密钥")

    blocks = []
    for i, it in enumerate(items):
        blocks.append(
            f"【{i}】\n题目：{it.get('question', '')}\n参考答案：{it.get('reference', '')}\n"
            f"候选人回答：{it.get('answer', '') or '（未作答）'}"
        )
    payload = {
        "model": "qwen-plus",
        "messages": [
            {"role": "system", "content": SCORE_PROMPT},
            {"role": "user", "content": "\n\n".join(blocks)},
        ],
        "temperature": 0.2,
    }
    try:
        resp = requests.post(
            "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json=payload,
            timeout=180,
        )
        if resp.status_code != 200:
            logger.warning(f"[Score] 模型返回 {resp.status_code}: {resp.text[:300]}")
            raise HTTPException(status_code=502, detail=f"评分模型调用失败（HTTP {resp.status_code}）")
        content = resp.json()["choices"][0]["message"]["content"]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"评分模型调用异常：{e}")

    # 模型偶尔会带 ```json 围栏或多说几句，宽容地抠出第一段 JSON
    text = (content or "").strip()
    if "```" in text:
        text = re.sub(r"```[a-zA-Z]*", "", text).strip()
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        raise HTTPException(status_code=502, detail="评分结果格式无法解析")
    try:
        parsed = json.loads(m.group(0))
    except Exception:
        raise HTTPException(status_code=502, detail="评分结果不是合法 JSON")

    got = {}
    for x in parsed.get("items") or []:
        try:
            got[int(x.get("id"))] = x
        except Exception:
            continue

    results = []
    for i in range(len(items)):
        x = got.get(i) or {}
        try:
            score = max(0.0, min(10.0, float(x.get("score"))))
        except Exception:
            score = 0.0
        results.append({"id": i, "score": score, "comment": str(x.get("comment") or "").strip()})
    total = sum(r["score"] for r in results)
    return {"results": results, "total": total, "max": len(results) * 10}


# ============================================================
# [新增] 练习 / 考试记录（按账号）
# ============================================================
# 为什么放服务端：数据工作台要用这些记录画进度、次数和趋势图。
# 记录只存本机的话，换个浏览器就全空了，看板会变成一片零。
# 归属同样是【前端自述的用户名】（和简历一致）—— 定位是跨设备同步，不是防越权。
PRACTICE_FILE = "practice_records.json"


def load_practice_records():
    data = load_json_file(PRACTICE_FILE, {})
    return data if isinstance(data, dict) else {}


class PracticeRecordReq(BaseModel):
    username: str
    records: list


class ExamRecordReq(BaseModel):
    username: str
    bank: str = ""
    card: str = ""
    total: float = 0
    max: float = 0
    count: int = 0
    answered: int = 0
    items: list = []


@app.get("/api/practice/records")
def get_practice_records(username: str = ""):
    who = (username or "").strip()
    if not who:
        return {"practice": [], "exam": [], "summaries": []}
    d = load_practice_records().get(who) or {}
    return {
        "practice": d.get("practice") or [],
        "exam": d.get("exam") or [],
        # 练习结束时的 AI 点评（按提交时间戳关联）
        "summaries": d.get("summaries") or [],
    }


@app.post("/api/practice/records")
def add_practice_records(req: PracticeRecordReq):
    """追加练习记录。一条 = 一道题的一次作答，粒度细到题，
    这样卡片进度、按时间分组、知识点占比都能从同一份数据算出来。"""
    who = (req.username or "").strip()
    if not who:
        raise HTTPException(status_code=400, detail="缺少用户名")
    if not req.records:
        return {"message": "没有需要保存的记录", "added": 0}

    data = load_practice_records()
    bucket = data.setdefault(who, {})
    bucket.setdefault("practice", [])
    bucket.setdefault("exam", [])
    now = str(datetime.now())
    added = 0
    for r in req.records:
        bucket["practice"].append(
            {
                "id": uuid.uuid4().hex[:12],
                "bank": str(r.get("bank") or "").strip(),
                "category": str(r.get("category") or "").strip(),
                "qid": str(r.get("qid") or "").strip(),
                "score": float(r.get("score") or 0),
                # 保存用户当时的作答，练习记录的详情里要能「我的回答 / 参考答案」对照着看
                "answer": str(r.get("answer") or ""),
                "at": now,
            }
        )
        added += 1
    data[who] = bucket
    save_json_file(PRACTICE_FILE, data)
    logger.info(f"[Practice] {who} 记下 {added} 道题的作答")
    return {"message": f"已保存 {added} 条记录", "added": added, "at": now}


@app.post("/api/practice/exams")
def add_exam_record(req: ExamRecordReq):
    who = (req.username or "").strip()
    if not who:
        raise HTTPException(status_code=400, detail="缺少用户名")
    data = load_practice_records()
    bucket = data.setdefault(who, {})
    bucket.setdefault("practice", [])
    bucket.setdefault("exam", [])
    item = {
        "id": uuid.uuid4().hex[:12],
        "bank": (req.bank or "").strip(),
        "card": (req.card or "").strip(),
        "total": float(req.total or 0),
        "max": float(req.max or 0),
        "count": int(req.count or 0),
        "answered": int(req.answered or 0),
        "items": [
            {
                "qid": str(x.get("qid") or ""),
                "score": float(x.get("score") or 0),
                "answer": str(x.get("answer") or ""),
            }
            for x in (req.items or [])
        ],
        "at": str(datetime.now()),
    }
    bucket["exam"].insert(0, item)
    data[who] = bucket
    save_json_file(PRACTICE_FILE, data)
    logger.info(f"[Practice] {who} 完成一次模拟考试：{item['total']}/{item['max']}")
    return {"message": "已保存考试记录", "exam": {**item, "items": []}}


# ============================================================
# [新增] 交卷后的 AI 点评（30-50 字，一句优点 + 一句不足）
# ============================================================
class SummarizeReq(BaseModel):
    items: list = []
    total: float = 0
    max: float = 0
    mode: str = "practice"


SUMMARY_PROMPT = """你是技术面试教练。根据这组练习/考试结果，写一段中文点评。

要求：
- 全文 30-50 个字，绝不能超过 50 字
- 一句话说优点，一句话说不足，中间用「；」连接
- 不要小标题、不要「优点：」「缺点：」字样、不要换行、不要表情符号
- 语气客观具体，指出方向即可

只输出点评本身，不要任何解释。"""


def _fallback_summary(total, maxi, weak_types):
    """模型不可用时的兜底点评，保证这个功能不会因为没网就整块空掉。"""
    rate = (total / maxi * 100) if maxi else 0
    if rate >= 80:
        head = "整体掌握扎实，答题思路清晰"
    elif rate >= 60:
        head = "基础尚可，关键细节还需巩固"
    else:
        head = "基础还不够牢，建议回看知识点"
    if weak_types:
        tail = f"；{weak_types[0]}失分较多，建议重点复习"
    else:
        tail = "；继续保持这个节奏就好"
    return head + tail


@app.post("/api/practice/summarize")
def practice_summarize(req: SummarizeReq):
    """根据本次得分生成一段点评。模型调不通时退回规则生成，不让流程卡住。"""
    items = req.items or []
    count = len(items)
    try:
        total = float(req.total or 0)
        maxi = float(req.max or 0)
    except Exception:
        total, maxi = 0.0, 0.0
    maxi = maxi or (count * 10)

    by_type = {}
    for it in items:
        t = str(it.get("type") or "问答题")
        s = float(it.get("score") or 0)
        g = by_type.setdefault(t, {"n": 0, "sum": 0.0})
        g["n"] += 1
        g["sum"] += s
    weak = [
        t
        for t, g in sorted(by_type.items(), key=lambda kv: (kv[1]["sum"] / max(1, kv[1]["n"])))
        if g["sum"] / max(1, g["n"]) < 6
    ]

    key = os.getenv("DASHSCOPE_API_KEY")
    if key and count:
        rate = round(total / maxi * 100) if maxi else 0
        detail = "、".join(f"{t}{g['sum'] / max(1, g['n']):.1f}分" for t, g in by_type.items())
        payload = {
            "model": "qwen-plus",
            "messages": [
                {"role": "system", "content": SUMMARY_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"本次{'模拟考试' if req.mode == 'exam' else '练习'}：共 {count} 题，"
                        f"总分 {total:g}/{maxi:g}，得分率 {rate}%。各题型平均分：{detail}。"
                    ),
                },
            ],
            "temperature": 0.4,
        }
        try:
            resp = requests.post(
                "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json=payload,
                timeout=60,
            )
            if resp.status_code == 200:
                text = (resp.json()["choices"][0]["message"]["content"] or "").strip()
                text = re.sub(r"[\r\n]+", " ", text).strip()
                text = re.sub(r"^(优点[:：]|缺点[:：])", "", text).strip()
                if text:
                    return {"summary": text[:80], "source": "ai"}
            else:
                logger.warning(f"[Summary] 模型返回 {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            logger.warning(f"[Summary] 模型调用异常：{e}")

    return {"summary": _fallback_summary(total, maxi, weak), "source": "rule"}


class SummarySaveReq(BaseModel):
    username: str
    mode: str = "practice"
    ref: str = ""
    bank: str = ""
    card: str = ""
    total: float = 0
    max: float = 0
    count: int = 0
    summary: str = ""


@app.post("/api/practice/summary")
def save_practice_summary(req: SummarySaveReq):
    """用户彻底退出答题后，把点评落到记录里。"""
    who = (req.username or "").strip()
    if not who:
        raise HTTPException(status_code=400, detail="缺少用户名")
    text = (req.summary or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="点评内容为空")

    data = load_practice_records()
    bucket = data.setdefault(who, {})
    bucket.setdefault("practice", [])
    bucket.setdefault("exam", [])

    if req.mode == "exam" and req.ref:
        target = next((e for e in bucket["exam"] if e.get("id") == req.ref), None)
        if not target:
            raise HTTPException(status_code=404, detail="考试记录不存在")
        target["summary"] = text
    else:
        bucket.setdefault("summaries", []).append(
            {
                "id": uuid.uuid4().hex[:12],
                "ref": (req.ref or "").strip(),
                "bank": (req.bank or "").strip(),
                "card": (req.card or "").strip(),
                "total": float(req.total or 0),
                "max": float(req.max or 0),
                "count": int(req.count or 0),
                "summary": text,
                "at": str(datetime.now()),
            }
        )

    data[who] = bucket
    save_json_file(PRACTICE_FILE, data)
    logger.info(f"[Practice] {who} 保存了点评（{req.mode}）")
    return {"message": "已保存点评"}

@app.delete("/api/practice/exams/{exam_id}")
def delete_exam_record(exam_id: str, username: str = ""):
    who = (username or "").strip()
    if not who:
        raise HTTPException(status_code=400, detail="缺少用户名")
    data = load_practice_records()
    bucket = data.get(who) or {}
    exams = bucket.get("exam") or []
    left = [x for x in exams if x.get("id") != exam_id]
    if len(left) == len(exams):
        raise HTTPException(status_code=404, detail="记录不存在")
    bucket["exam"] = left
    data[who] = bucket
    save_json_file(PRACTICE_FILE, data)
    return {"message": "已删除", "total": len(left)}


@app.delete("/api/practice/records")
def clear_practice_records(username: str = "", bank: str = "", category: str = ""):
    """清空某个卡片的练习记录（bank + category 定位一张卡）；都不传则清空全部。"""
    who = (username or "").strip()
    if not who:
        raise HTTPException(status_code=400, detail="缺少用户名")
    data = load_practice_records()
    bucket = data.get(who) or {}
    items = bucket.get("practice") or []
    left = [
        x
        for x in items
        if not (
            (not bank or (x.get("bank") or "") == bank)
            and (not category or (x.get("category") or "") == category)
        )
    ]
    removed = len(items) - len(left)
    bucket["practice"] = left
    data[who] = bucket
    save_json_file(PRACTICE_FILE, data)
    return {"message": f"已清空 {removed} 条记录", "removed": removed}


@app.get("/api/practice/stats")
def practice_stats(username: str = ""):
    """数据工作台用的汇总：按知识点算进度，加上考试次数和趋势。

    进度口径（已确认）：答对 = 单题得分 >= 6；同一道题做多次只算一次、
    取历史最好成绩 —— 否则反复刷同一题就能把进度灌满。
    """
    from collections import defaultdict

    who = (username or "").strip()
    d = (load_practice_records().get(who) or {}) if who else {}
    practice = d.get("practice") or []
    exams = d.get("exam") or []

    best = {}
    for r in practice:
        k = ((r.get("bank") or ""), (r.get("category") or ""), (r.get("qid") or ""))
        s = float(r.get("score") or 0)
        if k not in best or s > best[k]:
            best[k] = s

    totals = {}
    for b in load_banks():
        bank_name = b.get("name") or ""
        for q in b.get("questions") or []:
            cat = q.get("category") or "未分类"
            totals[(bank_name, cat)] = totals.get((bank_name, cat), 0) + 1

    agg = {}
    for (bank, cat, qid), s in best.items():
        g = agg.setdefault((bank, cat), {"answered": 0, "correct": 0})
        g["answered"] += 1
        if s >= 6:
            g["correct"] += 1

    progress = []
    for (bank, cat), total in totals.items():
        g = agg.get((bank, cat), {"answered": 0, "correct": 0})
        progress.append(
            {
                "bank": bank,
                "category": cat,
                "total": total,
                "answered": g["answered"],
                "correct": g["correct"],
                "percent": round(g["correct"] * 100.0 / total, 1) if total else 0.0,
            }
        )
    progress.sort(key=lambda x: (x["bank"], x["category"]))

    by_day = defaultdict(lambda: {"count": 0, "total": 0.0})
    for e in exams:
        day = str(e.get("at") or "")[:10]
        if not day:
            continue
        by_day[day]["count"] += 1
        by_day[day]["total"] += float(e.get("total") or 0)

    # 考试明细里只存了 qid，要按知识点算通过率就得先映射回题目所属知识点
    qid_cat = {}
    for b in load_banks():
        bn = b.get("name") or ""
        for q in b.get("questions") or []:
            qid_cat[str(q.get("id"))] = (bn, q.get("category") or "未分类")

    exam_pass = {}
    for e in exams:
        for it in e.get("items") or []:
            hit = qid_cat.get(str(it.get("qid") or ""))
            if not hit:
                continue
            bank, cat = hit
            g = exam_pass.setdefault((bank, cat), {"total": 0, "passed": 0})
            g["total"] += 1
            if float(it.get("score") or 0) >= 6:
                g["passed"] += 1

    exam_pass_list = [
        {
            "bank": bank,
            "category": cat,
            "total": v["total"],
            "passed": v["passed"],
            "percent": round(v["passed"] * 100.0 / v["total"], 1) if v["total"] else 0.0,
        }
        for (bank, cat), v in exam_pass.items()
    ]
    exam_pass_list.sort(key=lambda x: (x["bank"], x["category"]))
    trend = [
        {
            "date": day,
            "count": v["count"],
            "score": round(v["total"] / v["count"], 1) if v["count"] else 0,
        }
        for day, v in sorted(by_day.items())[-14:]
    ]

    total_questions = sum(totals.values())
    correct_all = sum(v["correct"] for v in agg.values())
    return {
        "progress": progress,
        "exam": {
            "count": len(exams),
            "avgScore": round(sum(float(e.get("total") or 0) for e in exams) / len(exams), 1)
            if exams
            else 0,
            "trend": trend,
        },
        # 考试按知识点的通过率（用于「通过率最高 / 最低」展示）
        "examPass": exam_pass_list,
        "overall": {
            "questions": total_questions,
            "correct": correct_all,
            "percent": round(correct_all * 100.0 / total_questions, 1) if total_questions else 0.0,
        },
    }


# ============================================================
# [新增] 面试记录上报
# ============================================================
class RecordReportReq(BaseModel):
    username: str
    record: dict


@app.post("/api/interview/records")
def report_interview_record(req: RecordReportReq):
    """前端提交面试时同步一份到服务端。

    为什么非要新增这个接口：面试记录原来【只】存在各自浏览器的 localStorage 里
    （按 `用户名_键名` 隔离），服务端一条都没有 ——
    管理后台的「数据总览」因此完全没有数据源，只能显示注册人数。
    """
    username = (req.username or "").strip()
    record = req.record or {}
    if not username or not isinstance(record, dict) or not record:
        raise HTTPException(status_code=400, detail="username 与 record 不能为空")

    items = load_json_file(RECORDS_FILE, [])
    rid = str(record.get("id") or uuid.uuid4().hex[:12])
    # 同一个 id 重复上报时先删旧的再插新的 —— 否则用户反复点「提交」会让数据翻倍
    items = [
        x
        for x in items
        if not (x.get("username") == username and str((x.get("record") or {}).get("id")) == rid)
    ]
    items.insert(0, {"username": username, "received_at": str(datetime.now()), "record": record})
    # 只保留最近 2000 条：这是个 JSON 文件，无限增长迟早会把整个文件读进内存
    items = items[:2000]
    save_json_file(RECORDS_FILE, items)
    return {"message": "已记录", "id": rid, "total": len(items)}


# ============================================================
# [新增] 管理后台 —— 数据总览 / 系统状态
# ============================================================
def _record_rounds_and_scores(record):
    """从一条面试记录里取「轮数」与「所有已评分轮次的分数」。

    轮数的口径和前端 rounds 计算保持一致：面试官有正文的回复才算一轮。
    """
    rounds, scores = 0, []
    for m in (record or {}).get("messages") or []:
        if not isinstance(m, dict):
            continue
        if m.get("role") == "ai" and m.get("content"):
            rounds += 1
        s = m.get("score")
        if s is not None:
            try:
                scores.append(float(s))
            except (TypeError, ValueError):
                pass
    return rounds, scores


@app.get("/api/admin/overview")
def admin_overview(_admin: str = Depends(require_admin)):
    users = load_users()
    records = load_json_file(RECORDS_FILE, [])
    questions = load_questions()
    positions = load_json_file(POSITIONS_FILE, DEFAULT_POSITIONS)

    today = datetime.now().date()
    days = [(today - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]

    # ---- 账号 ----
    seven_days_ago = (today - timedelta(days=6)).isoformat()
    user_stats = {
        "total": len(users),
        "admins": sum(1 for r in users.values() if r.get("role") == "admin"),
        "disabled": sum(1 for r in users.values() if r.get("enabled") is False),
        "new_7d": sum(1 for r in users.values() if str(r.get("created_at", ""))[:10] >= seven_days_ago),
    }
    register_trend = {
        d: sum(1 for r in users.values() if str(r.get("created_at", ""))[:10] == d) for d in days
    }

    # ---- 面试 ----
    all_scores = []
    rounds_total = 0
    position_count = {}
    score_by_day = {d: [] for d in days}
    for entry in records:
        rec = entry.get("record") or {}
        rounds, scores = _record_rounds_and_scores(rec)
        rounds_total += rounds
        all_scores.extend(scores)
        pos = str(rec.get("position") or "未标注")
        position_count[pos] = position_count.get(pos, 0) + 1
        day = str(rec.get("date") or entry.get("received_at") or "")[:10]
        if day in score_by_day and scores:
            score_by_day[day].extend(scores)

    record_stats = {
        "total": len(records),
        "users": len({e.get("username") for e in records if e.get("username")}),
        "rounds": rounds_total,
        "avg_rounds": round(rounds_total / len(records), 1) if records else 0,
        "avg_score": round(sum(all_scores) / len(all_scores), 1) if all_scores else 0,
        "scored_rounds": len(all_scores),
    }

    return {
        "users": user_stats,
        "records": record_stats,
        "positions": {
            "configured": len(positions),
            "used": [
                {"position": p, "count": c}
                for p, c in sorted(position_count.items(), key=lambda kv: -kv[1])
            ],
        },
        "questions": {
            "total": len(questions),
            "with_terms": sum(1 for q in questions if q.get("terms")),
            "terms": len(build_question_vocabulary()),
        },
        "register_trend": [{"date": d, "count": register_trend[d]} for d in days],
        "score_trend": [
            {
                "date": d,
                "avg": round(sum(score_by_day[d]) / len(score_by_day[d]), 1) if score_by_day[d] else 0,
                "count": len(score_by_day[d]),
            }
            for d in days
        ],
    }


@app.get("/api/admin/system-status")
def admin_system_status(probe: int = 0, _admin: str = Depends(require_admin)):
    """把调 bug 时手敲的那几个探针做成面板。

    probe=0 只回配置（毫秒级，纯读内存）；probe=1 才真的发一次网络请求。
    分开是因为探针会消耗额度与时间，不该每次打开面板都跑一遍 ——
    由界面上的「重新检测」按钮显式触发。
    """

    def mask(value):
        """只露头尾几位，够管理员「认出是哪一把钥匙」即可。

        不能直接回显：面板虽然要登录，但密钥一旦出现在响应体里，
        就会顺着浏览器控制台、截图、日志到处流。留 6+4 位足以区分轮换前后的两把钥匙。
        """
        if not value:
            return ""
        return f"{value[:6]}…{value[-4:]}" if len(value) > 16 else "已配置"

    status = {
        "probed": bool(probe),
        "dify": {
            "configured": bool(DIFY_API_URL and DIFY_API_KEY),
            "url": DIFY_API_URL or "",
            "key": mask(DIFY_API_KEY),
            "workflow_configured": bool(DIFY_WORKFLOW_URL and DIFY_WORKFLOW_KEY),
            "workflow_url": DIFY_WORKFLOW_URL or "",
        },
        "tts": {
            "configured": bool(DASHSCOPE_API_KEY),
            "key": mask(DASHSCOPE_API_KEY),
            "model": TTS_MODEL,
            "default_voice": TTS_VOICE,
            "voices": len(TTS_VOICES),
            "max_chars": TTS_MAX_CHARS,
        },
        "asr": {
            "configured": bool(DASHSCOPE_API_KEY),
            "model": ASR_MODEL,
            "sample_rate": ASR_SAMPLE_RATE,
            "max_seconds": ASR_MAX_SECONDS,
            "hotwords_base": len(ASR_HOTWORDS_BASE),
            "hotwords_from_bank": len(build_question_vocabulary()),
        },
        "storage": {
            "users": len(load_users()),
            "positions": len(load_json_file(POSITIONS_FILE, DEFAULT_POSITIONS)),
            "questions": len(load_questions()),
            "records": len(load_json_file(RECORDS_FILE, [])),
        },
    }

    if not probe:
        return status

    # ---- Dify 探针：打 /parameters 而不是 /chat-messages ----
    # /parameters 只读应用配置，不触发模型推理，所以【不花钱】；
    # 而它同样要过 API Key 鉴权，所以完全够用来判断「Key 是否有效、应用是否在」。
    if status["dify"]["configured"]:
        param_url = re.sub(r"/chat-messages/?$", "/parameters", DIFY_API_URL)
        try:
            r = requests.get(param_url, headers={"Authorization": f"Bearer {DIFY_API_KEY}"}, timeout=15)
            body = r.json() if r.headers.get("Content-Type", "").startswith("application/json") else {}
            status["dify"]["probe"] = {
                "ok": r.ok,
                "http": r.status_code,
                "opening_statement": (body.get("opening_statement") or "")[:80],
                "inputs": len(body.get("user_input_form") or []),
                "detail": "" if r.ok else (body.get("message") or r.text[:120]),
            }
        except requests.exceptions.RequestException as e:
            status["dify"]["probe"] = {"ok": False, "http": 0, "detail": f"连不上：{e}"}
    else:
        status["dify"]["probe"] = {"ok": False, "http": 0, "detail": "未配置 DIFY_API_URL / DIFY_API_KEY"}

    # ---- TTS 探针：音色列表接口是纯读本地常量的，不花钱 ----
    status["tts"]["probe"] = {
        "ok": bool(TTS_VOICES),
        "voices": len(TTS_VOICES),
        "detail": "" if TTS_VOICES else "音色白名单为空",
    }

    return status


# ============================================================
# [新增] 管理后台 —— 公告跑马灯
# ============================================================
@app.get("/api/admin/announcements")
def admin_get_announcements(_admin: str = Depends(require_admin)):
    return {"announcements": load_json_file(ANNOUNCEMENTS_FILE, DEFAULT_ANNOUNCEMENTS)}


class AnnouncementsReq(BaseModel):
    announcements: list = []


@app.post("/api/admin/announcements")
def admin_set_announcements(req: AnnouncementsReq, admin: str = Depends(require_admin)):
    """整表覆盖。

    公告就是几行短文本，没必要拆成增 / 删 / 改三个接口 ——
    那种设计还得给每条配一个 id，前端要多维护一套映射，
    而整表覆盖只需要一个 textarea、一次请求。
    """
    items = [str(a).strip() for a in (req.announcements or []) if str(a).strip()]
    save_json_file(ANNOUNCEMENTS_FILE, items)
    logger.info(f"[Admin] {admin} 更新了公告，共 {len(items)} 条")
    return {
        "message": f"已保存 {len(items)} 条公告",
        "count": len(items),
        "announcements": items,
    }


# 启动时按 .env 引导管理员账号（幂等，已存在则不动）
bootstrap_admin_account()


# 启动服务入口
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", reload=True, host="0.0.0.0", port=8000)