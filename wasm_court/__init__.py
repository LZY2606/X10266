"""模块边界庭：WebAssembly 段索引、类型栈与提案能力验证。

领域子系统（不依赖持久化层）：
  leb       - LEB128 解码/编码（非规范编码与数值越界严格分离）
  parser    - 二进制/段地图/索引空间（原始字节范围全程保留）
  features  - proposal 能力集合与指纹
  host      - host import 签名契约
  validator - 函数类型栈/控制栈（polymorphic stack 仅限 unreachable 区域）
  analyze   - 汇总判定、候选与依赖来源图

应用层：
  storage   - SQLite 事件日志（追加、重放、导出/再导入）
  service   - 项目状态机（版本、父版本、局部过期、裁定）
  app       - FastAPI 复核界面（SVG 段地图等）
"""

ALGO_VERSION = "wasm-court-1.0.0"
