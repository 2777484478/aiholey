"""示例：故意包含多处安全漏洞的 Python 服务，用于演示 Aiholey 扫描能力。"""
import os
import pickle
import sqlite3
import hashlib
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)

# 漏洞1：硬编码密钥
SECRET_KEY = "sk-live-9f3a2b7c8d1e4f5a6b7c8d9e0f1a2b3c"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# 漏洞2：调试模式
app.config["DEBUG"] = True


@app.route("/user")
def get_user():
    """漏洞3：SQL 注入"""
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return {"rows": cur.fetchall()}


@app.route("/run")
def run_cmd():
    """漏洞4：命令注入"""
    cmd = request.args.get("cmd", "id")
    return os.popen(cmd).read()


@app.route("/load")
def load_obj():
    """漏洞5：pickle 反序列化"""
    payload = bytes.fromhex(request.args.get("data", ""))
    return str(pickle.loads(payload))


@app.route("/fetch")
def fetch_url():
    """漏洞6：SSRF"""
    target = request.args.get("url")
    resp = requests.get(target, timeout=5)
    return resp.text


@app.route("/file")
def read_file():
    """漏洞7：路径穿越"""
    path = request.args.get("path")
    with open(path, "rb") as f:
        return f.read()


@app.route("/sign")
def sign():
    """漏洞8：弱哈希"""
    data = request.args.get("data", "")
    return hashlib.md5(data.encode()).hexdigest()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
