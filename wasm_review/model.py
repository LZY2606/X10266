"""领域模型与常量。

所有跨层传递的结果使用普通 dict（便于 JSON 序列化与事件回放），
字段含义固定，任何派生值都带 provenance（算法版本 / 参数指纹 / 直接来源 / span）。
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

ALGO_VERSION = "wasm-boundary-court-1.0.0"

# 一等状态：候选 / 拒绝 / 误差或未知 / 采纳
STATUSES = ("candidate", "rejected", "unknown", "accepted")
STATUS_CANDIDATE = "candidate"
STATUS_REJECTED = "rejected"
STATUS_UNKNOWN = "unknown"
STATUS_ACCEPTED = "accepted"

FINDING_LEVELS = ("error", "warning", "candidate", "note")

# 提案目录：key -> (展示名, 描述)。proposal 关闭时，对应 opcode 报 capability_missing 而非 unknown_byte。
PROPOSAL_CATALOG = {
    "mvp": ("MVP", "WebAssembly 1.0 MVP（始终启用）"),
    "multi_value": ("Multi-value", "块/函数多值返回与多值块类型"),
    "sign_extension": ("Sign-extension", "0xFC 前缀整数符号扩展算子"),
    "reference_types": ("Reference-types", "ref.null/ref.func/ref.is_null/externref 表/funcref"),
    "bulk_memory": ("Bulk-memory", "memory.init/copy/fill/table.init 等 0xFC 算子"),
    "saturating_float_to_int": ("Non-trap float-to-int", "0xFC 截断取整算子"),
    "simd": ("SIMD", "0xFD 向量指令"),
    "threads": ("Threads", "0xFE 原子指令"),
}

DEFAULT_PROPOSALS = {
    "mvp": True,
    "multi_value": False,
    "sign_extension": False,
    "reference_types": False,
    "bulk_memory": False,
    "saturating_float_to_int": False,
    "simd": False,
    "threads": False,
}

# Wasm 数值类型
VALTYPE_I32 = 0x7F
VALTYPE_I64 = 0x7E
VALTYPE_F32 = 0x7D
VALTYPE_F64 = 0x7C
VALTYPE_V128 = 0x7B
VALTYPE_FUNCREF = 0x70
VALTYPE_EXTERNREF = 0x6F

NUMERIC_VALTYPES = {
    VALTYPE_I32: "i32",
    VALTYPE_I64: "i64",
    VALTYPE_F32: "f32",
    VALTYPE_F64: "f64",
    VALTYPE_V128: "v128",
}
REF_VALTYPES = {VALTYPE_FUNCREF: "funcref", VALTYPE_EXTERNREF: "externref"}
ALL_VALTYPES = {**NUMERIC_VALTYPES, **REF_VALTYPES}


@dataclass(frozen=True)
class Span:
    """原字节中的半开区间 [start, end)，坐标基准为“模块相对字节偏移”。"""

    start: int
    end: int

    def as_dict(self) -> dict:
        return {"start": self.start, "end": self.end, "unit": "byte-offset", "basis": "module-relative"}


def span_dict(start: int, end: int) -> dict:
    return Span(start, end).as_dict()


def stable_id(kind: str, *parts: object) -> str:
    """生成跨数据库、跨导入导出稳定的内容身份（不依赖自增主键）。"""
    material = kind + "|" + "|".join(str(p) for p in parts)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"{kind}_{digest}"


def fingerprint(obj: object) -> str:
    """参数指纹：对规范化 JSON 取 SHA256。"""
    import json

    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_provenance(
    direct_sources: list[dict],
    params: dict | None,
    parents: list[str] | None = None,
) -> dict:
    """所有派生值统一携带的溯源结构。"""
    return {
        "algo_version": ALGO_VERSION,
        "parameter_fingerprint": fingerprint(params or {}),
        "parameter_ref": stable_id("params", fingerprint(params or {})),
        "direct_sources": direct_sources,
        "parent_result_ids": list(parents or []),
    }


def make_finding(
    code: str,
    message: str,
    span: dict,
    *,
    level: str = "error",
    status: str = STATUS_CANDIDATE,
    subject: str | None = None,
    evidence: dict | None = None,
    source_ref: str | None = None,
) -> dict:
    """机器可读判定事件的最小单元：候选/拒绝/未知都作为一等数据。"""
    finding_id = stable_id(
        "finding",
        code,
        span["start"],
        span["end"],
        subject or "",
        evidence or {},
    )
    return {
        "id": finding_id,
        "code": code,
        "level": level,
        "status": status,
        "message": message,
        "subject_id": subject,
        "span": span,
        "evidence": evidence or {},
        "source_ref": source_ref,
    }
