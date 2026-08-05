import hashlib
import json
import logging
import os
from datetime import datetime

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()
DIFY_API_URL = os.getenv("DIFY_API_URL")
DIFY_API_KEY = os.getenv("DIFY_API_KEY")


app = FastAPI(title="AI面试后端")
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
    users = load_users()
    if req.username in users:
        return {"error": "用户名已存在"}
    users[req.username] = {"password": req.password, "created_at": str(datetime.now())}
    save_users(users)
    return {"message": "注册成功", "username": req.username}

# 登录接口
@app.post("/api/auth/login")
def login(req: LoginReq):
    users = load_users()
    if req.username not in users:
        return {"error": "用户不存在"}
    if users[req.username]["password"] != req.password:
        return {"error": "密码错误"}
    token = hashlib.md5(f"{req.username}{datetime.now()}".encode()).hexdigest()
    return {"message": "登录成功", "token": token, "username": req.username}


# 聊天请求模型
class ChatRequest(BaseModel):
    message: str
    position: str
    user_id: str
    user_name: str
    age: str
    degree: str

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

# 对外聊天接口 /api/chat（前端Vue调用这个接口）
@app.post("/api/chat")
def chat(req: ChatRequest):
    # 调用封装好的Dify函数
    ai_reply = call_dify_block(req.message, req.position, req.user_id, req.user_name, req.age, req.degree)
    # 返回给前端的固定格式
    return {
        "reply": ai_reply,
        "position": req.position
    }

@app.get("/")
def hello():
    return {"message": "Hello World! 面试系统启动成功"}

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "A05面试系统"}

@app.get("/api/echo")
def echo(message: str = Query()):
    return {"reply": f"你说的是：{message}。AI面试官已上线！"}

# 启动服务入口
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", reload=True, host="0.0.0.0", port=8000)