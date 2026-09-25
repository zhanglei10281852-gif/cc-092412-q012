# 乡镇政务协同服务

这是一个面向乡镇综合服务中心的模块化后端，集中管理居民档案、政务事务、信访流转、公告、部门、用户、角色、权限、会话、审计和可恢复后台任务。项目使用 FastAPI 与 SQLite，所有运行数据保存在单个本地数据库文件中，不依赖另行部署的数据库、缓存或消息队列。

## 主要模块

- 居民档案：登记、查询、更新和关联事务。
- 事务办理：受理、分派、退回、办结和部门责任查询。
- 信访流转：签收、分派、办理、审核、复查、催办和流转记录。
- 公告与部门：公告置顶、分类检索、部门信息及关联业务查看。
- 身份与权限：用户、角色、细粒度权限、会话令牌、账号停用和会话撤销。
- 审计记录：关键身份操作留痕，对敏感字段做过滤，并以哈希链和固定批次检查点保证连续性可验证。
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

测试覆盖身份初始化、登录、用户与角色维护、权限计算、账号停用后的会话撤销、审计脱敏、居民事务、信访状态流转、公告排序、后台任务去重与领取、数据库时间格式，以及审计链的序号唯一、并发写入、篡改/删除/重排定位、检查点、历史封存、增量校验续跑、导出材料重算和链感知的保留清理。

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

## 审计链与完整性校验

审计事件在写入时即被编入一条无密钥的 SHA-256 哈希链，即使数据库管理员直接改库，删除、替换或重排记录也会被校验定位。

- 写入链路：每条事件获得唯一递增序号 `seq`（由单行顺序器在写事务内分配，并发写入不会重号），并记录 `prev_digest`（前一条摘要）与 `digest`（自身规范化内容的摘要）。规范化内容只覆盖脱敏后的字段，口令、令牌等敏感键在入链前已被剔除。
- 检查点：每 `TOWNSHIP_AUDIT_CHECKPOINT_INTERVAL` 条事件（默认 100）生成一个检查点，检查点之间同样成链，作为防回卷的锚点。
- 历史存量：首次写入或执行 `python -m app.cli audit-chain-init` 时，存量记录按 id 顺序从创世摘要建立首个检查点，命令幂等可重复执行。
- 校验接口：`GET /api/audit/verify` 全量校验并定位第一处断裂（`chain_break`）、缺号（`missing`）、篡改（`digest_mismatch`）、重排或检查点异常，而不是只返回真假；`GET /api/audit/chain/status` 查看链与校验状态。
- 定期校验：`python -m app.cli audit-verify`（或 `POST /api/audit/verify/run`）按 `TOWNSHIP_AUDIT_VERIFY_CHUNK` 分块推进，每块进度落库，失败和重启后从上次位置继续；一轮走完后下一轮从锚点重新全量复核，历史区段的事后篡改也能被发现。CLI 在链断裂时以退出码 1 结束，适合接入计划任务告警。
- 导出材料：`GET /api/audit/chain/export` 导出事件摘要、规范化内容与检查点，可离线独立重算。链条不使用任何密钥，材料中也不含明文口令或令牌。
- 保留策略：`POST /api/maintenance/prune/audit` 只清理已被检查点覆盖的区段，并写入截断锚点，后续校验从锚点继续，正常清理不会被误判为断链。

## 数据一致性

SQLite 连接默认启用外键、WAL、busy timeout 与同步写入策略。需要跨多张表更新的管理操作在即时事务中执行，失败会整体回滚。会话令牌只保存摘要；用户停用会撤销仍有效的会话。审计事件保存操作者、动作、资源、结果和前后状态，但不会保存明文密码或令牌；审计链的序号分配、事件写入与检查点生成在同一事务内完成。
