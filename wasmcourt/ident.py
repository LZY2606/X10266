"""稳定身份（stable identity）。

所有派生对象使用内容寻址 CID：sha256(canonical_json(payload))。
CID 只取决于内容，因此导出 -> 删除本地数据库 -> 再导入后身份保持不变；
时间相关字段（ts/seq）不进入对象 payload，只属于事件信封。
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

CID_PREFIX = "bafy"  # 与 multibase base32 风格区分开的本地内容寻址前缀


def canonical_json(obj: Any) -> str:
    """确定性 JSON 序列化：键排序、无空白、保证 UTF-8 可复现。"""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def cid(payload: Any) -> str:
    """从任意可 JSON 化的内容计算稳定身份。"""
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"{CID_PREFIX}{digest[:52]}"


def hash_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
