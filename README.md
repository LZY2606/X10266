# 模块边界庭 · WebAssembly 段索引、类型栈与提案能力验证

面向运行时团队的长期可复查系统：导入 Wasm binary、启用的 proposal 集合与
host import 签名，审查段顺序、索引空间、函数类型栈与限制，并把每一次判定、
裁定与回溯都固化为带稳定身份的机器可读事件。

## 安装与演示

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q; .venv/bin/uvicorn app:app --host 127.0.0.1 --port 5368
```

然后打开 http://127.0.0.1:5368 ，点击「载入离线案例包」，即可走完
导入 → 产生候选 → 作出裁定 → 重开复核 → 导出再导入 的完整路径。

## 领域判定的一等区分

- **非规范 LEB128 vs 数值越界**：`noncanonical_leb128` 与 `value_out_of_range`
  是两个独立错误码，判断依据写入 `judgments`（`leb128_form_vs_range`）。
- **polymorphic stack 只在 unreachable 区域生效**：控制帧带 `unreachable` 标记，
  只有帧内不可达时才产生多态栈槽（`polymorphic_stack_scope`）。
- **能力缺失 vs 未知字节**：已注册但未启用 proposal 的 opcode 报
  `capability_missing`（附 proposal 名），完全未知的字节报 `unknown_opcode`
  （`capability_vs_unknown`）。

候选、拒绝原因、误差与未知状态都作为一等数据保存；每个错误都带最小失败
字节范围与索引来源（`origin`）。

## 版本与过期

- 原始输入一经提交不可覆盖；修订是带 `parent_id` 的新版本。
- 派生结果携带算法版本（`algo`）、参数指纹（`fingerprint`）与直接来源哈希。
- 局部输入变化只使依赖它的结果过期（按函数体粒度比对指纹）；过期结果仍可
  查看但标记 `stale`，不会冒充当前结果。
- 接受 / 否定 / 参数调整 / 撤销全部写入事件日志；互相冲突的人工裁定共存
  并标记冲突。
- 「回到任意旧事件」恢复当时的依赖版本与可见结论，历史不被最新计算覆盖。
- 导出 → 删除本地数据库 → 导入后，身份、顺序与来源关系保持不变。

## 离线案例包

`cases/boundary_court.json`（由 `casepack.py` 生成，测试保证可再生成）：
模块边界庭叙事 —— v1 基线导入（原字节范围、section id/size、LEB128 编码、
索引来源、功能开关、import 契约、自定义段均保留）→ v2 局部源数据改动 →
v3 参数修订（关闭 multi-value）→ 冲突裁定与撤销 → 七个边界场景分支
（section 重复与乱序、非规范 LEB128、unreachable 栈、多值返回、
proposal 关闭、import 不匹配、自定义段保真）。

## 结构

- `wasmcore.py` — Wasm 二进制解析与验证（段地图、LEB128、索引空间、控制栈、类型栈）
- `store.py` — SQLite 版本化存储（输入版本、派生结果、事件、裁定、档案导出/导入）
- `app.py` — FastAPI 接口（`create_app(db_path, clock)` 支持测试注入）
- `casepack.py` — 离线案例包构建与重放
- `web/static/index.html` — 复核界面（SVG 段地图、索引表、控制栈、类型转移、最小失败字节范围）
- `tests/test_acceptance.py` — 固定 seed、临时目录、虚拟时间的验收测试
