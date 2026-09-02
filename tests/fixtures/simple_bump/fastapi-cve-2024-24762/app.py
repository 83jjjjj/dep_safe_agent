from fastapi import FastAPI, Form

app = FastAPI()


@app.get("/")
def root():
    return {"ok": True}


@app.post("/submit")
def submit(name: str = Form(...)):
    # CVE-2024-24762 触发点：multipart 表单解析（大量 part 触发 ReDoS 的正则路径）
    return {"name": name}
