"""WebAssembly 模块验证 / 提案能力 / 版本可复查系统（模块边界庭）。

领域分层：
  ident      稳定身份（内容寻址 CID）
  units      领域量的单位 / 坐标基准
  leb128     非规范编码与数值越界严格分离的 LEB128 解码
  features   提案功能开关（能力集合）
  parser     字节级模块解析（段地图 / 索引空间 / 自定义段保真）
  validate   函数类型栈 / 控制栈 / 能力与 import 契约验证
  graph      依赖图与局部失效传播（NumPy）
  store      SQLite 事件存储（只追加事件日志 + 物化快照）
  engine     版本、候选/拒绝、裁定、时间旅行
  casepack   离线案例包（基线 + 参数修订 + 局部改动 + 冲突决定）
"""

ALGORITHM_VERSION = "wasmcourt-validator-1.0.0"
SCHEMA_VERSION = "case-export-1"
