# 模块边界庭：WebAssembly 段索引、类型栈与提案能力验证

这是一个可离线复查的 WebAssembly 模块验证案例系统。运行时团队导入 Wasm binary、启用的 proposal 集合和 host import 签名后，系统保留原始字节和每一级来源，再生成 section 地图、索引空间、函数类型栈、能力判定、候选与拒绝原因。

## 安装与演示

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q
.venv/bin/uvicorn app:app --host 127.0.0.1 --port 5368
```

然后打开 `http://127.0.0.1:5368`。页面可完成：

1. 从仓库内离线案例包安装初始材料。
2. 查看原字节范围、section id/size、LEB128、索引来源、功能开关、import 契约和自定义段。
3. 产生参数修订、局部源数据修订和互相冲突的人工决定。
4. 在 section 地图、索引表、控制栈、类型转移、最小失败字节范围中追溯来源。
5. 导出项目，删除本地数据库，重新导入后核对稳定身份、顺序与来源关系。

## 核心边界

- 非规范 LEB128 是编码诊断；数值越界是独立的域越界诊断。
- polymorphic stack 只在 `unreachable` 之后到控制块结束前生效。
- 未启用 proposal 的已知 opcode 报 `capability_missing`，不报未知字节；未知字节才是 `unknown_byte`。
- 多值 block/function 返回由 `multi_value` proposal 控制。
- 原始输入不可覆盖；所有修订以父子版本关系表达。
- 派生值带算法版本、参数指纹和直接来源；局部源数据变化只令依赖结果过期，旧结果仍可查看。

## 离线案例包

`cases/module-boundary-court/` 是专门的领域案例，不是通用表格：

- `case.json`：初始 binary、proposal、host import、后续修订和脚本化复核动作。
- `README.md`：每一步覆盖的边界组合。
- `*.wasm`：由案例生成器固化的可复制小型样例。

数据库默认位于临时/当前工作目录下的 `data/module_court.sqlite3`。设置 `MODULE_COURT_DB` 可指定测试数据库路径。
