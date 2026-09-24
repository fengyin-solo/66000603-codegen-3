from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from typing import List, Optional
import json
import re
import uuid
import random
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = FastAPI(title="Smart Contract Security Auditor")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Vulnerability patterns —— 全系统唯一一份模式定义，
# 模式库页面（GET /api/patterns）与合约审计（POST /api/audit）共用，
# 列表顺序即页面展示顺序，导入合并时同名规则原位更新、新规则追加到末尾。
VULNERABILITY_PATTERNS = [
    {
        "name": "重入攻击 (Reentrancy)",
        "severity": "critical",
        "pattern": r"\.call\{[^}]*value:\s*[^}]*\}\([^)]*\)",
        "description": "使用低级call()或send()转移ETH存在重入攻击风险。攻击者可部署恶意合约在fallback中反复调用提款。",
        "suggestion": "使用Checks-Effects-Interactions模式，或引入ReentrancyGuard。推荐使用transfer()或call()并限制Gas。"
    },
    {
        "name": "整数溢出 (Integer Overflow/Underflow)",
        "severity": "high",
        "pattern": r"[+\-*/]\s*=|(&&|\|\|)\s*\w+\s*[<>=]",
        "description": "Solidity 0.7及以下版本，未使用SafeMath时可能发生整数溢出。",
        "suggestion": "使用SafeMath库或升级到Solidity 0.8+（内置溢出检查）。"
    },
    {
        "name": "未授权访问控制",
        "severity": "high",
        "pattern": r"function\s+\w+\s*\([^)]*\)\s*public\s*(payable)?\s*\{[^}]*(?:require|if)\s*\(",
        "description": "关键函数缺少访问控制检查，任何人都可以调用。",
        "suggestion": "添加onlyOwner或自定义访问控制修饰符。"
    },
    {
        "name": "selfdestruct使用",
        "severity": "medium",
        "pattern": r"selfdestruct|suicide",
        "description": "selfdestruct可强制将合约所有ETH发送到任意地址，可能被滥用。",
        "suggestion": "谨慎使用selfdestruct，确保有正当的业务需求。"
    },
    {
        "name": "tx.origin钓鱼",
        "severity": "high",
        "pattern": r"tx\.origin",
        "description": "使用tx.origin进行身份验证可能被钓鱼攻击，攻击者诱导用户触发交易。",
        "suggestion": "使用msg.sender代替tx.origin进行身份验证。"
    },
    {
        "name": "精确度损失",
        "severity": "medium",
        "pattern": r"/\s*\d+",
        "description": "除法运算可能导致精度损失，特别是在代币金额计算中。",
        "suggestion": "先乘后除，使用高精度计算或使用Babylonian方法。"
    },
]

GAS_PATTERNS = [
    {"function": "storage_read", "issue": "循环中读取storage变量", "saving": 0.3},
    {"function": "redundant_sstore", "issue": "不必要的storage写入", "saving": 0.25},
    {"function": "short_circuit", "issue": "逻辑运算可短路优化", "saving": 0.15},
]

SEVERITY_LEVELS = ["critical", "high", "medium", "low"]

class AuditRequest(BaseModel):
    code: str
    filename: str

def detect_vulnerabilities(code: str) -> List[dict]:
    """Scan code for vulnerability patterns"""
    lines = code.split("\n")
    vulnerabilities = []

    for vp in VULNERABILITY_PATTERNS:
        matches = re.finditer(vp["pattern"], code, re.MULTILINE)
        for m in matches:
            line_num = code[:m.start()].count("\n") + 1
            # Find context
            context_start = max(0, line_num - 2)
            context_end = min(len(lines), line_num + 2)
            context = "\n".join(lines[context_start:context_end])

            vulnerabilities.append({
                "type": vp["name"],
                "severity": vp["severity"],
                "line": line_num,
                "description": vp["description"],
                "suggestion": vp["suggestion"],
                "code": context.strip()
            })

    return vulnerabilities

def compute_gas_issues(code: str) -> List[dict]:
    """Analyze gas consumption issues"""
    issues = []
    functions = re.findall(r"function\s+(\w+)\s*\(", code)
    for fn in functions:
        base_gas = random.randint(20000, 60000)
        issues.append({
            "functionName": f"{fn}()",
            "currentGas": base_gas,
            "optimizedGas": int(base_gas * (0.7 + random.random() * 0.2)),
            "suggestion": random.choice(["移除不必要的storage写入", "缓存storage变量到memory", "使用短路逻辑", "合并多个事件为一个"])
        })
    return issues

def compute_security_score(vulnerabilities: List[dict]) -> int:
    """Compute overall security score"""
    if not vulnerabilities:
        return 100
    severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    deduction = sum(severity_weights.get(v["severity"], 5) for v in vulnerabilities)
    return max(0, 100 - deduction)

def validate_pattern(item) -> (dict, Optional[str]):
    """Validate a single imported pattern entry.

    Returns (normalized_pattern, None) on success, or (None, reason) on failure.
    """
    if not isinstance(item, dict):
        return None, "条目必须是 JSON 对象"

    name = item.get("name")
    if not isinstance(name, str) or not name.strip():
        return None, "缺少必填字段 name（非空字符串）"

    severity = item.get("severity")
    if severity not in SEVERITY_LEVELS:
        return None, f"severity 必须是 {'/'.join(SEVERITY_LEVELS)} 之一，当前为: {severity!r}"

    pattern = item.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        return None, "缺少必填字段 pattern（正则表达式）"
    try:
        re.compile(pattern)
    except re.error as e:
        return None, f"pattern 不是合法的正则表达式: {e}"

    description = item.get("description")
    if not isinstance(description, str) or not description.strip():
        return None, "缺少必填字段 description（非空字符串）"

    suggestion = item.get("suggestion", "")
    if not isinstance(suggestion, str):
        return None, "suggestion 必须是字符串"

    return {
        "name": name.strip(),
        "severity": severity,
        "pattern": pattern,
        "description": description.strip(),
        "suggestion": suggestion.strip()
    }, None

def merge_patterns(items: List) -> dict:
    """Validate entries one by one and merge valid ones into VULNERABILITY_PATTERNS.

    同名规则以导入内容为准，但保留库中原有的严重程度，且位置不变；
    新规则追加到列表末尾，保证原有展示顺序不变。
    """
    results = []
    imported = 0

    for index, item in enumerate(items):
        name = item.get("name") if isinstance(item, dict) else None
        pattern, error = validate_pattern(item)
        if error:
            results.append({
                "index": index,
                "name": name,
                "status": "failed",
                "reason": error
            })
            continue

        existing = next((p for p in VULNERABILITY_PATTERNS if p["name"] == pattern["name"]), None)
        if existing is not None:
            # 同名：导入内容覆盖，但保留原有严重程度，位置不变
            original_severity = existing["severity"]
            existing.update(pattern)
            existing["severity"] = original_severity
            results.append({
                "index": index,
                "name": pattern["name"],
                "status": "success",
                "action": "updated",
                "message": f"已更新同名规则，严重程度保留为 {original_severity}"
            })
        else:
            VULNERABILITY_PATTERNS.append(pattern)
            results.append({
                "index": index,
                "name": pattern["name"],
                "status": "success",
                "action": "added",
                "message": "已新增规则"
            })
        imported += 1

    return {
        "total": len(items),
        "imported": imported,
        "failed": len(items) - imported,
        "results": results
    }

@app.get("/")
async def root():
    return {"message": "Smart Contract Security Auditor", "version": "1.0.0"}

@app.get("/api/patterns")
async def list_patterns():
    return {"code": 0, "message": "success", "data": VULNERABILITY_PATTERNS}

@app.get("/api/patterns/export")
async def export_patterns():
    """Export the current pattern library as a JSON file.

    导出内容与库中当前规则完全对应（含导入合并后的结果）。
    """
    content = json.dumps(VULNERABILITY_PATTERNS, ensure_ascii=False, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=patterns.json"}
    )

@app.post("/api/patterns/import")
async def import_patterns(request: Request):
    """Import a batch of patterns and merge them into the library.

    支持两种请求方式：
    - JSON body：规则数组，或 {"patterns": [...]}
    - multipart/form-data：file 字段上传 JSON 文件

    逐条校验，格式不对的条目在 results 中单独列出并说明原因；
    同名规则以导入内容为准，但保留原有严重程度。
    """
    content_type = request.headers.get("content-type", "")
    try:
        if "multipart/form-data" in content_type:
            form = await request.form()
            upload = form.get("file")
            if upload is None:
                raise HTTPException(status_code=400, detail="缺少上传文件字段 file")
            raw = await upload.read()
            payload = json.loads(raw.decode("utf-8"))
        else:
            payload = await request.json()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="文件内容不是合法的 JSON")

    if isinstance(payload, dict):
        items = payload.get("patterns")
    else:
        items = payload

    if not isinstance(items, list):
        raise HTTPException(status_code=400, detail="请求体必须是规则数组，或包含 patterns 数组字段的对象")

    result = merge_patterns(items)
    return {"code": 0, "message": "success", "data": result}

@app.post("/api/audit")
async def audit_contract(request: AuditRequest):
    vulnerabilities = detect_vulnerabilities(request.code)
    gas_issues = compute_gas_issues(request.code)
    score = compute_security_score(vulnerabilities)

    result = {
        "id": str(uuid.uuid4()),
        "filename": request.filename,
        "score": score,
        "vulnerabilities": vulnerabilities,
        "gasIssues": gas_issues,
        "timestamp": datetime.now().isoformat()
    }

    return {"code": 0, "message": "success", "data": result}

@app.get("/api/history")
async def get_history():
    return {"code": 0, "message": "success", "data": []}

@app.post("/api/report/{audit_id}")
async def generate_report(audit_id: str):
    """Generate PDF report"""
    # Simplified report generation
    return {"code": 0, "message": "success", "data": {"url": f"/api/reports/{audit_id}.pdf"}}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
