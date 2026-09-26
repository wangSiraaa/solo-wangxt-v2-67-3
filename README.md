# protocompat — Protobuf 发布兼容性登记服务

纯后端的 Protobuf 注册与兼容性判定服务。新增字段不等于兼容：发布入口必须给出
**有依据** 的判断。判定基于 protocompile 产出的完整链接描述符闭包（不是源码正则），
同时检查二进制线路编码与 JSON 映射两个维度；**无法证明安全的部分一律标为
`NEEDS_REVIEW`，绝不笼统标成通过**。

## 架构

```
cmd/server        ConnectRPC 服务入口（纯后端，无管理页面）
cmd/compatcheck   命令行：回归用例运行器 + 两棵 proto 树的临时比对
internal/schema   protocompile 封装：编译 → 描述符集 → 内容哈希 → 重新加载
internal/compat   兼容性判定核心（字段号复用 / 保留删除 / 类型变化 / 枚举默认值 / 样例载荷）+ finding 指纹/行号
internal/registry ConnectRPC 处理器、Store 接口、PostgreSQL 实现、内存实现；豁免状态机、乐观并发与审计
internal/regress  文件型回归用例运行器（CLI 与 go test 共用）
testdata/cases    回归案例：嵌套导入、oneof 迁移、同名不同包……
api/registry/v1   服务契约（ConnectRPC，当前手写 handler + JSON codec，无需 codegen）
```

- **解析**：`github.com/bufbuild/protocompile`，嵌套导入、菱形导入、well-known
  types 均由编译器解析；判断在 `protoreflect` 描述符上进行。
- **传输**：ConnectRPC（connect 协议 + JSON codec）。除
  `RegisterVersion` / `CheckCompatibility` / `DeclareConsumer` / `ListVersions`
  外，还提供豁免生命周期的 7 个方法（申请/批准/拒绝/撤销/查询/列表/审计）。
- **存储**：PostgreSQL 存包、不可变版本（描述符集 + 内容哈希）、兼容性报告、
  使用方声明（consumer declarations）以及有时效的豁免与审计事件。
  `STORE=memory` 可本地冒烟（不持久化）。

## 判定模型

每条 finding 带 `severity`（FAIL/WARN/INFO）、`dimension`（WIRE/JSON/BOTH）、
`message`（全限定名）与 `path`（字段路径）。整体结论：

| verdict | 含义 |
|---|---|
| `COMPATIBLE` | 所有检查都有证据通过 |
| `NEEDS_REVIEW` | 没有证伪，但至少一项**无法证明**安全（如移入 oneof、取消保留号段） |
| `INCOMPATIBLE` | 至少一项被证明破坏（如字段号复用、JSON 表示变化） |

覆盖的检查（详见 `internal/compat`）：

- **字段号复用**：同号不同名且类型不同 → FAIL；同号不同名同类型 → 无法区分改名与
  换义，wire 维度 WARN、JSON 名变化 FAIL。
- **保留字段删除**：删字段且号+名都保留 → INFO；只保留号 → JSON 维度 WARN；
  什么都不保留 → WIRE 维度 FAIL。取消保留号段 / 复用保留号 → WARN。
- **类型变化**：按 wire 类型分类矩阵（varint/fixed32/fixed64/length-delimited）
  与 JSON 表示分类（number/quoted-number/bool/string/base64/enum-name/object）
  分别定级；packed repeated ↔ singular、map 键值类型、消息类型换绑等均覆盖。
- **枚举默认值**：零值（隐式默认值）改名/删除、proto2 封闭枚举新增值
  （老读者落入 unknown fields）、proto3 开放枚举新增值（INFO）。
- **oneof 迁移**：移入 → WARN（旧载荷可能同时设置互斥字段，JSON 双成员文档解析失败）；
  移出 → INFO；oneof 删除 → WARN。合成 oneof（proto3 optional）不计。
- **样例载荷**：提交者可附 `samples`（json 文本或 base64 wire），服务用新旧描述符
  分别解析并比对确定性 wire 字节与 protojson 输出，差异定位到
  `acme.Msg.lines[2].amount` 这样的字段路径；无法验证的样例记 WARN，不算通过。

## 使用方声明

消费方声明自己读取的消息/字段与编码（wire/json/both），`CheckCompatibility`
带上 `consumer` 后，报告会投影到该消费方的实际使用面：wire-only 消费者不受
纯 JSON 破坏影响，反之亦然。

## 有时效的豁免（time-bounded exemptions）

确定的 finding 可申请**有时效、按消费方作用域**的豁免。豁免**永不改写
历史报告**：报告与版本都是不可变的，豁免只在查询时派生“发布判定”。

- **指纹**：每条 finding 带 `fingerprint = sha256(package | code | message |
  path | dimension)`。它**不含行号、detail、严重级别**——所以新报告里声明
  挪动了行号，指纹不变、豁免延续；规则（code）或对象（message/path/
  dimension）变化会产生新指纹，必须重新申请。行号以 `annotated.findings[].
  line` 单独返回（来自 SourceCodeInfo，仅用于展示）。
- **生命周期**：`PENDING → APPROVED/REJECTED`，`APPROVED → REVOKED/EXPIRED`。
  申请需填写 `owner`、`reason`、`consumers`（必填，至少一个消费方，绝不全局
  生效）、`expires_at`（RFC3339，半开区间，到达边界即刻失效）。审批必须由
  **另一个身份**完成，申请人自批返回 `permission_denied` 且状态不变。
- **乐观并发**：每次迁移都要回带读到的 `version`；两个审批者基于同一旧版本
  并发操作时只有一个成功，落败方收到 `aborted`，重新读取后可再操作。
- **幂等**：同一申请人对同一 finding 的未决申请只保留一条（终态后可再次申请）；
  同一审批者重复审批已批准的豁免直接返回当前行，不产生第二条审计。
- **审计**：每次状态迁移与豁免行在同一事务写入 `exemption_audit_events`
  （`REQUESTED/APPROVED/REJECTED/REVOKED/EXPIRED`）。
- **双判定**：响应同时给出原始结论（`report.verdict` / `publish.raw_verdict`）
  与豁免后的发布判定（`publish.verdict` / `consumer_decision.verdict`，可为
  `EXEMPTED`）；过期、撤销或指纹变化都会让发布判定**立刻**恢复阻断。

ConnectRPC 方法：`RequestExemption` / `ApproveExemption` / `RejectExemption` /
`RevokeExemption` / `GetExemption` / `ListExemptions` / `ListAuditEvents`。
身份通过请求体字段或 `X-Actor` 头传递。

```bash
# 1) 注册 v1、v2（产生已存储报告），声明消费方
# 2) 从带注释的报告中取 finding 指纹
FP=$(curl -s localhost:8080/registry.v1.Registry/CheckCompatibility \
  -H 'Content-Type: application/json' \
  -d '{"package":"acme.pay","base_version":"v1","candidate_version":"v2","consumer":"ledger"}' \
  | jq -r '.annotated.findings[] | select(.severity=="FAIL") | .fingerprint')
# 3) alice 申请、bob 批准（不能自批）
go run ./cmd/compatcheck exemption request -pkg acme.pay -base v1 -head v2 \
  -fingerprint "$FP" -owner team-pay -reason "quiescence window" \
  -consumer ledger -expires 2026-10-01T00:00:00Z -by alice
go run ./cmd/compatcheck exemption approve -id 1 -expected-version 1 -by bob
# 4) 再查：raw_verdict=INCOMPATIBLE, verdict=EXEMPTED；审计轨迹
go run ./cmd/compatcheck exemption audit -pkg acme.pay
```

## 运行

```bash
docker compose up --build        # PostgreSQL + 服务（:8080）
# 或本地：
STORE=memory go run ./cmd/server # 冒烟用，不持久化
```

注册版本（发布入口，自动与上一版本比对）：

```bash
curl -s localhost:8080/registry.v1.Registry/RegisterVersion -H 'Content-Type: application/json' -d '{
  "package": "acme.pay",
  "version": "v2",
  "files": [{"path": "pay/invoice.proto", "content": "syntax = \"proto3\"; ..."}],
  "samples": [{"message": "acme.pay.Invoice", "encoding": "json", "data": "{\"id\":\"i-1\",\"total\":5}"}],
  "require_compatible": true
}'
```

- 同版本同内容 → 幂等成功（`already_existed: true`）。
- **同版本不同内容 → `already_exists` 错误，拒绝覆盖**。
- `require_compatible: true` 且结论为 `INCOMPATIBLE` → `failed_precondition`，
  版本不落库。

声明消费方并做投影检查：

```bash
curl -s localhost:8080/registry.v1.Registry/DeclareConsumer -H 'Content-Type: application/json' -d '{
  "package": "acme.pay", "consumer": "ledger", "encoding": "wire",
  "usages": [{"message": "acme.pay.Invoice", "fields": ["id"]}]
}'
curl -s localhost:8080/registry.v1.Registry/CheckCompatibility -H 'Content-Type: application/json' -d '{
  "package": "acme.pay", "base_version": "v1", "candidate_version": "v2", "consumer": "ledger"
}'
```

## 命令行回归

```bash
go run ./cmd/compatcheck run testdata/cases     # 全部回归案例
go run ./cmd/compatcheck check -old A -new B -format text   # 临时比对两棵 proto 树
go run ./cmd/compatcheck exemption request ...  # 申请 finding 豁免（见上节）
go test ./...                                    # 单元测试 + 同一套回归案例
```

`testdata/cases` 下每个案例是 `old/`、`new/` 两棵 proto 树加 `case.json` 期望，
覆盖嵌套导入（菱形依赖）、oneof 迁移、同名不同包、字段号复用、保留/未保留删除、
枚举默认值变化、类型变化矩阵与样例载荷。期望未列出的 WARN/FAIL 会使案例失败——
沉默不算通过。

## 测试

```bash
go test ./...                    # 全部（PostgreSQL 集成测试在无 DATABASE_URL 时跳过）
DATABASE_URL=postgres://... go test ./internal/registry/ -run TestPGStore
```
