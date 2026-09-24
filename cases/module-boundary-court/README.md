# 模块边界庭离线案例

固定 seed 为 20260925，虚拟时间从 `2026-09-25T00:00:00Z` 开始。案例按父子修订重放 section 重复/乱序、非规范 LEB128、unreachable polymorphic stack、多值返回、提案关闭、host import 不匹配和自定义段保真。

`case.json` 是机器可读的重放档案；`*.wasm` 是可复制的小型原始样例。所有字节坐标均为从 0 开始、左闭右开。
