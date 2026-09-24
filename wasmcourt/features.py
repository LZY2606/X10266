"""提案功能开关（capability set）。

能力键即提案名；opcode -> 所需能力的映射由 validate 使用。
未启用 proposal 的 opcode 必须报 capability_missing（而不是 unknown byte）。
"""
from __future__ import annotations

# 案例包涉及的提案；MVP 总是隐式启用。
PROPOSALS = ("multi_value", "reference_types", "tail_call", "simd")

DEFAULT_FEATURES: dict[str, bool] = {name: False for name in PROPOSALS}

# MVP 1.0 能力（永远存在），便于 UI 与事件统一展示。
MVP = "mvp_1_0"


def parse_features(raw: dict | None) -> dict[str, bool]:
    features = dict(DEFAULT_FEATURES)
    if raw:
        for name, on in raw.items():
            if name in features:
                features[name] = bool(on)
            # 未知提案名保留但忽略，导入层诊断里会记录
    return features


def feature_fingerprint(features: dict[str, bool]) -> str:
    """参数指纹：能力集合的确定性短摘要。"""
    on = sorted(k for k, v in features.items() if v)
    return "feat:" + ("+".join(on) if on else "mvp-only")


def describe(features: dict[str, bool]) -> str:
    return feature_fingerprint(features)
