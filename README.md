# 乡镇政务协同服务

这是一个面向乡镇综合服务中心的模块化后端，集中管理居民档案、政务事务、信访流转、公告、部门、用户、角色、权限、会话、审计和可恢复后台任务。项目使用 FastAPI 与 SQLite，所有运行数据保存在单个本地数据库文件中，不依赖另行部署的数据库、缓存或消息队列。

## 主要模块

- 居民档案：登记、查询、更新和关联事务。
- 事务办理：受理、分派、退回、办结和部门责任查询。
- 信访流转：签收、分派、办理、审核、复查、催办和流转记录。
- 公告与部门：公告置顶、分类检索、部门信息及关联业务查看。
- 身份与权限：用户、角色、细粒度权限、会话令牌、账号停用和会话撤销。
- 审计记录：关键身份操作留痕，并对口令和令牌等敏感字段做过滤。
- 审计链完整性：每条审计事件绑定前一条摘要与自身规范化内容，按固定批次生成检查点，支持定位第一处断裂、缺号或重排的校验、历史存量锚定、可断点续跑的定期校验和只含摘要的验证材料导出。
- 后台任务：使用 SQLite 保存待执行任务，支持去重、租约、重试和完成回执。

## 运行环境

- Python 3.11
- SQLite 3，由 Python 标准库提供
- Linux、macOS 或 Windows

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

配置项均以 `TOWNSHIP_` 开头。可以复制 `.env.example` 后按需设置，默认数据库位于 `./data/township.db`。

## 初始化与检查

```bash
python -m app.cli init-db
python -m app.cli check-db
```

## 启动服务

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康检查：

```bash
curl -sS http://127.0.0.1:8432/api/system/health
```

首次部署可创建唯一的初始管理员：

```bash
curl -sS -X POST http://127.0.0.1:8432/api/auth/bootstrap   -H 'Content-Type: application/json'   -d '{"username":"admin","password":"Admin!23456","client_label":"initial-setup"}'
```

之后通过 `/api/auth/login` 获取会话令牌，并在管理接口请求头中使用 `Authorization: Bearer <token>`。

## 测试

```bash
python -m pytest
```

测试覆盖身份初始化、登录、用户与角色维护、权限计算、账号停用后的会话撤销、审计脱敏、居民事务、信访状态流转、公告排序、后台任务去重与领取，以及数据库时间格式。

## 编译检查

```bash
python -m compileall -q app tests
```

## API 冒烟

```bash
python -m app.cli smoke
```

该命令在进程内启动应用并检查服务根路径与健康接口，适合部署前快速确认路由和数据库初始化是否正常。

## 目录结构

```text
app/
  api/             用户、角色、审计、认证和系统接口
  core/            时钟、安全、异常和分页能力
  repositories/    SQLite 查询与持久化读取
  routers/         居民、事务、公告、部门和信访业务接口
  schemas/         管理接口输入模型
  services/        身份、审计和后台任务领域服务
  cli.py           初始化、检查和冒烟入口
  database.py      SQLite 连接、事务、表结构与基础权限
tests/             核心、管理接口和原有业务回归测试
tools/             本地维护脚本
```

## 数据一致性

SQLite 连接默认启用外键、WAL、busy timeout 与同步写入策略。需要跨多张表更新的管理操作在即时事务中执行，失败会整体回滚。会话令牌只保存摘要；用户停用会撤销仍有效的会话。审计事件保存操作者、动作、资源、结果和前后状态，但不会保存明文密码或令牌。

## 审计链与完整性校验

审计写入链路为每条事件分配唯一连续序号（`seq`），并计算绑定前一条摘要（`prev_digest`）与自身规范化内容的 SHA-256 摘要（`digest`）。规范化内容取事件全部链字段，按键名排序、固定分隔符序列化，摘要基于脱敏后的存储内容计算，敏感字段过滤规则不变。序号由单行链状态表在同一写事务内条件更新分配，并发业务写入在 SQLite 写锁下串行推进，序号不会重复或跳号；未处于事务中的调用会自动包裹 `BEGIN IMMEDIATE`。

每写满 `TOWNSHIP_AUDIT_CHECKPOINT_SIZE` 条事件（默认 100）就在同一事务内生成一个检查点：内容为批次内事件摘要的 Merkle 根，检查点之间同样以前一检查点摘要链接。检查点批次大小属于部署参数，变更后历史批次边界不会重算。

校验接口按序号顺序扫描，返回第一处问题的类型与位置，而不是只返回真假：

```bash
curl -sS http://127.0.0.1:8432/api/audit/integrity/verify -H "Authorization: Bearer <token>"
```

`first_failure.kind` 可能为 `sequence_gap`（缺号）、`sequence_reorder`（重排）、`chain_break`（前序摘要断裂）、`digest_mismatch`（内容被替换）、`head_mismatch`（链状态表被改写）、`unanchored_events`（存在未锚定记录）以及 `checkpoint_missing`、`checkpoint_digest_mismatch`、`checkpoint_root_mismatch`、`checkpoint_chain_break` 四类检查点问题。

历史存量事件在应用启动迁移时自动按 id 顺序锚定入链，从序号 1 的明确起点建立首个检查点；也可随时显式触发（幂等）：

```bash
curl -sS -X POST http://127.0.0.1:8432/api/audit/integrity/anchor -H "Authorization: Bearer <token>"
python -m app.cli audit-anchor
```

定期校验任务将进度持久化在 `audit_verification_runs` 中，按 `TOWNSHIP_AUDIT_VERIFY_CHUNK_SIZE`（默认 500）分块推进；进程重启或执行出错后可从断点继续，发现完整性问题的任务不会续跑，下一次会从起点重新校验并再次定位同一处。每次调用处理 `chunks` 个分块，适合交给定时器循环触发：

```bash
curl -sS -X POST "http://127.0.0.1:8432/api/audit/integrity/verification-runs?chunks=10" -H "Authorization: Bearer <token>"
curl -sS http://127.0.0.1:8432/api/audit/integrity/verification-runs/latest -H "Authorization: Bearer <token>"
```

导出的验证材料只含序号、摘要和检查点，不包含任何密钥、口令或业务明文（设计本身不使用密钥，任何一方都能独立重算），可交给纪检等外部方留存，用于事后比对链头与检查点：

```bash
curl -sS "http://127.0.0.1:8432/api/audit/integrity/export?include_events=true" -H "Authorization: Bearer <token>"
python -m app.cli audit-verify
```

已锚定的审计事件不再允许通过 `/api/maintenance/prune/audit` 删除，以免破坏可验证连续性；如需清理请先导出验证材料并归档。
