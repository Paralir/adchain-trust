# AdChain Trust v2.0 · 基于联盟链的网文广告多方信任存证系统

> **一句话定位：这是一个「模拟存证链」的竞赛 Demo —— 用单文件 Python 在本地重现「多方共同记账 + 篡改可检出」的核心思想，不是生产级联盟链。**

AI 编程大赛参赛作品 **v2.0**｜区块链为主体，AI 为辅助风控组件
共 **18 个接口**：1-12 核心业务闭环（含 7′ 读者打赏），13-17 管理增强（员工授权 / 月度工作上缴 / 打赏月结 / 隐私隔离），18 审计

### ⚠️ 能力边界（请先读，避免误解）

| 项目 | 是否有 | 说明 |
|---|---|---|
| 哈希链式结构 / 只追加 / 篡改检出 | ✅ 有 | 这是本Demo 的核心，全部手写实现 |
| Ed25519 双签名协议 | ✅ 有 | 真实密码学验签，非模拟 |
| P2P 网络 / 节点发现（Gossip） | ❌ 无 | 单进程本地文件，不跨节点通信 |
| 共识算法（PoW / Raft / PBFT） | ❌ 无 | 区块由单进程串行追加，**不存在挖矿** |
| 智能合约（EVM / DSL） | ❌ 无 | 链上逻辑全部是 Python 代码 |
| 多节点容灾 / 最终性保证 | ❌ 无 | 单点实现 |
| 代币发行 / 挖矿激励 | ❌ 无 | 书币是平台内部记账凭证，不可流通、不可提现 |
| 客户端自定义计费条款 | ❌ 无 | **v2.0 起全部计费条款由服务端 `PLATFORM_RULES` 锁定**，广告商只能选择广告类型，不能自定价或自定分成 |
| 作家身份冒用 | ❌ 无 | **v2.0 起查记录（④）与注销（⑫）都必须出示本人 Ed25519 私钥**，伪造 ID 也无法操作他人账户 |
| 内部管理信息公开 | ❌ 无 | 月报（⑮）含员工姓名与案件量，v2.0 起需老板密钥；但审计校验（⑨⑩）仍公开——链的验证权必须公开 |
| 路径穿越写入 | ❌ 无 | 月报文件名由 `staff_id` 拼出，v2.0 起所有 ID 字段启用字符白名单 `ID_PATTERN`，落盘前再用 `realpath` 做二次校验 |
| 负数发放上链 | ❌ 无 | v2.0 起结算 `payout = max(raw, 0)`，差额转 `settle_debt` 结转下期，链上不存在负数发放区块 |
| 订单代签 | ❌ 无 | **v2.0 起接口 ③ 校验签名私钥推导的公钥是否等于订单归属广告商的登记公钥**，防止拿任意私钥替他人订单签署生效 |

**为什么这样做**：本次考察的是**业务建模与存证设计**（双签协议、滚动结算、防重复扣款、聚合哈希存证），
因此刻意保持「单文件、零重依赖、一条命令跑起来」，让评委能直接观察业务闭环本身。
生产化升级路径见`项目设计文档.md` 第九章「已知边界与未来工作」。

## 一、项目简介

网文平台的广告生态长期存在三方信任难题：

| 痛点 | 具体表现 | 本系统解法 |
|---|---|---|
| 广告商跑路拖欠 | 投完广告不结费用，作家白干活 | **先充值后投放**：书币余额锁定 + 协议双签名上链 |
| 平台单方面篡改规则 | 事后改 CPM 单价、改分成比例 | **计费条款哈希固化 + 双签约束**，改一条即验签失败 |
| 作家对账不透明 | 不知道广告带来多少收益、扣了多少 | **周结区块化留痕**，作家可自查全部链上记录 |

本系统主体是**联盟链（Permissioned Chain）**：链上只追加、不修改、可校验、可追溯。
AI 在其中**只承担一件事——广告素材一致性抽检**（感知哈希比对 + 违规关键词命中），
输出报告供审核部参考，**不自动处罚、不替代人工审核**。

### 书币（book_coin）

平台内部记账凭证，**不是虚拟货币，不可对外流通、不可提现**。
广告商充值人民币按 `1 元 = 10 书币` 兑换，先充值后投放，从机制上杜绝投放后拖欠。

## 二、核心亮点

1. **区块本地持久化**：新区块自动追加写入 `chain.json`，程序重启自动从文件加载整条链，数据不丢失。
   落盘采用「临时文件 → `fsync` 强制刷盘 → `os.replace` 原子替换 →失败回滚内存」四步，
   既不会出现半个损坏文件，也不会因断电丢块，更不会出现内存与磁盘不一致。
2. **链完整性校验（六维度）**：逐块校验 区块自身哈希 / 前哈希链接 / 双签名合法性 / 封块高度锁 / **区块高度连续性** / **出块时间单调性**；
   返回结构化结果（总块数、合法块数、错误块明细、失败维度列表）并给出**篡改定位**。
   后两个维度尤其关键：攻击者若改了高度或时间戳**并重算哈希**，前四项仍会通过，
   只有新增的连续性/单调性校验能将其检出。
3. **只追加不修改 + 业务幂等**：所有资产变更一律新增区块，代码层面不提供任何修改历史区块的接口。
   同时对退款等接口补充幂等校验——「只追加」不等于「可以无限追加」，重复退款会被拒绝。
4. **协议双签名**：广告订单协议由广告商与平台分别用 Ed25519 签名，两方签名全部校验通过才允许打包上链，缺任一方签名直接拒绝写入。
5. **聚合哈希存证**：曝光等大容量原始明细不上链，只上链批量明细的摘要哈希，原始明细本地留存，核验时重算比对——既防篡改又控制存储开销。
6. **角色权限分级 + 独立审计**：审计员为独立第三方，对全量链上记录**只读**，可随时校验整条链完整性。
7. **写接口角色鉴权**：所有写接口需在请求头携带 `X-API-Key`（按角色区分），密钥走环境变量，未配置时使用内置 Demo 密钥以保证开箱即用。
8. **计费条款服务端锁定（v2.0）**：分成比例、分成上限、打赏抽成、CPM 单价全部来自服务端 `PLATFORM_RULES`，接口层`extra="forbid"` 显式拒绝客户端提交这些字段——**先有可信条款，双签名才有意义**。
9. **作家侧密码学隔离（v2.0）**：作家查本人收益需出示 Ed25519 私钥做持有证明，与广告商隔离方案一致。
8. **密码学级隐私隔离**：广告商只能查看本人流水，且需提交 Ed25519 私钥做持有证明——
   比「只按 ID 过滤」强得多，因为 ID 可枚举而私钥无法伪造。

## 三、技术栈

- **存证链层**：自研哈希链式结构（区块哈希 + 链式前哈希 + 封块高度锁 + 高度连续性 + 时间单调性 + 逐块校验）
- **密码学**：Ed25519 数字签名（`cryptography`）、SHA-256、文本 SimHash 感知哈希
- **接口层**：FastAPI + Pydantic v2，自动生成 Swagger 文档
- **鉴权层**：请求头 `X-API-Key` 角色密钥（环境变量注入），`hmac.compare_digest` 恒定时间比较
- **可靠性**：`threading.RLock` 链级锁 + `fsync` 强制刷盘 + `os.replace` 原子替换 + 失败回滚
- **存储层**：JSON 文件持久化（`chain.json`）+ 本地明细目录（`raw_exposure/`）
- **语言**：Python 3.10+
- **依赖**：仅 4 个（fastapi / uvicorn / pydantic / cryptography），无数据库、无 filelock

## 四、本地运行（完整步骤）

### 第 0 步：确认 Python 版本

### 第 1 步：获取代码并进入目录

```bash
git clone <你的仓库地址>
cd adchain-trust
```

### 第 2 步：安装依赖

建议使用虚拟环境，避免污染系统 Python：

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 第 3 步：启动服务

```bash
python -m uvicorn main:app --reload
```

看到以下输出即启动成功：

```
[INFO] chain.json 不存在，初始化创世块（首次启动属正常情况）
[WARNING] 以下角色正在使用内置 Demo 密钥（未配置环境变量）：...
INFO:     Uvicorn running on http://127.0.0.1:8000
 基于联盟链的网文广告多方信任存证系统 (AdChain Trust v2.0) 已启动
 ⚠️ 本项目是本地模拟存证链 Demo：无 P2P / 共识算法 / 智能合约 / 挖矿，勿按生产链理解
 接口总数: 18 个
 业务参数（服务端锁定，客户端不可设定）:
          1 CNY = 10 book_coin | 作家分成40% | 单篇单日上限200书币
          合规弹窗CPM12 / 普通广告CPM8 | 打赏抽成30%(月结免手续费) | 周结手续费固定0.5书币
 预置作家查询私钥（演示用，接口 ④ 需出示）:
   - WRITER_001(作家·青云): a6fd1247feffbfcb6acdbee5296054c31a8da482d096994cb15eaa85b2196458
   - WRITER_002(作家·墨白): d526da6250742c0052b62a3ee879c373008db7de69dc5a0fb929b261ccf5f53e
```

> 预置作家钱包由固定种子派生（`demo_wallet()`），**重启后私钥不变**，
> 因此 README 与演示脚本可以直接写死私钥、现场反复演示都不会失效。
> 这是演示便利性取舍：生产环境私钥必须由作家自行生成并保管，服务端只登记公钥。

### 第 4 步：打开接口文档

浏览器访问 **http://127.0.0.1:8000/docs** —— Swagger UI 列出全部 18 个接口，
每个接口都带中文说明。**在 Swagger 里直接点 Try it out 即可完成演示**，
写操作需在请求头带上 `X-API-Key`（Swagger 会自动提供该输入框）。

### 第 5 步：（可选）配置正式密钥

不配置也能完整跑通所有演示（使用内置 Demo 密钥）。正式部署请覆盖：

```bash
# macOS / Linux
export ADCHAIN_KEY_BOSS="你的高强度随机串"
export ADCHAIN_KEY_REVIEWER="..."
# Windows PowerShell
$env:ADCHAIN_KEY_BOSS = "你的高强度随机串"
```

也可复制 `.env.example` 为 `.env` 作模板（该文件已被 `.gitignore` 排除）。
密钥优先级：环境变量 > `config.local.py` > 内置 Demo 默认值。

### 验证持久化

启动 → 调用若干接口产生区块 → 停止服务 → 再次启动 →
调用 `GET /api/auditor/all` 可看到此前区块全部恢复；
调用 `GET /api/auditor/verify-chain` 应显示全部区块合法。

### 常见问题

| 现象 | 原因与解决 |
|---|---|
| 写接口返回 403 | 缺少或错误的 `X-API-Key`，见下方接口表「所需密钥」列 |
| 出现 `chain.json.broken.*` 文件 | 上次运行异常中断导致文件损坏；程序已自动备份并重建创世块，旧数据可从备份文件人工恢复 |
| 端口被占用 | 换端口：`python -m uvicorn main:app --port 8080` |
| 想从头开始 | 删除 `chain.json` 与 `raw_exposure/`，重启即可重建 |

## 四之二、鉴权说明（Demo 密钥）

未配置环境变量时使用以下内置 Demo 密钥，**仅供本地演示，切勿用于任何真实部署**：

| 角色 | Demo 密钥 | 环境变量名 |
|---|---|---|
| 老板 | `demo-boss-key-2026` | `ADCHAIN_KEY_BOSS` |
| 审核部部长 | `demo-minister-key-2026` | `ADCHAIN_KEY_REVIEW_MINISTER` |
| 审核部员 | `demo-reviewer-key-2026` | `ADCHAIN_KEY_REVIEWER` |
| 广告商 | `demo-advertiser-key-2026` | `ADCHAIN_KEY_ADVERTISER` |
| 作家 | `demo-writer-key-2026` | `ADCHAIN_KEY_WRITER` |
| 审计员 | `demo-auditor-key-2026` | `ADCHAIN_KEY_AUDITOR` |

**设计取舍（答辩可能被追问）**：

为什么用「环境变量 + Demo兜底」而不是「必须提供 config.py」？
因为本项目要保证评委 `git clone` 后 `pip install` + `uvicorn` 一条命令就能跑起来——
若密钥文件是必需的，评委没有该文件会直接启动失败。现在的做法既保证开箱即用，
又让密钥**可被环境变量覆盖**（生产环境必须覆盖，启动时会有 WARNING 提醒）。

也请诚实说明：API Key 属于「角色声明 + 访问控制」层面的机制，
**不等同于真正的身份认证**。生产环境应替换为 JWT/OAuth2 + HSM 密钥管理；
本项目中强度更高的机制是接口 ⑰ 的 **Ed25519 私钥持有证明**（密码学级，无法伪造）。

## 五、接口一览（18 个）

> 编号沿用业务序号 1-17，其中「7′ 读者打赏」为独立接口，故实际路由共 **18 个**。

| # | 方法 | 路径 | 说明 | 所需角色 | 所需密钥（请求头 `X-API-Key`） |
|---|------|------|------|------|------|
| 1 | POST | `/api/advertiser/apply` | 广告商提交投放申请（校验余额、锁定书币、备案素材哈希上链；**计费条款服务端锁定**） | **广告商** | `X-API-Key: demo-advertiser-key-2026` |
| 2 | POST | `/api/advertiser/deposit` | 广告商充值书币（1 元 = 10 书币） | **广告商** | `X-API-Key: demo-advertiser-key-2026` |
| 3 | POST | `/api/order/sign-agreement/{order_id}` | 订单协议双签名上链（广告商 + 平台，缺一拒绝） | **广告商** | `X-API-Key: demo-advertiser-key-2026` |
| 4 | POST | `/api/writer/records` | 作家查询本人全部链上记录（**需出示 Ed25519 私钥做持有证明**） | 公开 + 私钥证明 | — |
| 5 | POST | `/api/review/penalty` | 审核部执行处罚扣款（仅新增区块） | **审核部** | `X-API-Key: demo-reviewer-key-2026`<br>或 `demo-minister-key-2026` |
| 6 | POST | `/api/review/penalty-refund` | 登记处罚撤销退款（滚入下期结算，不改历史） | **审核部** | `X-API-Key: demo-reviewer-key-2026`<br>或 `demo-minister-key-2026` |
| 7 | POST | `/api/reader/report` | 读者举报违规广告（证据哈希上链） | **公开（读者无账号体系）** | — |
| 7′ | POST | `/api/reader/tip` | 读者打赏（平台实时抽成 30%，作家所得累计待月结） | **公开（读者无账号体系）** | — |
| 8 | POST | `/api/ai/random-check` | AI 素材一致性抽检（辅助风控，不替代人工审核） | **审核部** | `X-API-Key: demo-reviewer-key-2026` |
| 9 | GET | `/api/auditor/all` | 审计员查询全量链上记录（只读） | **公开只读** | — |
| 10 | GET | `/api/auditor/verify-chain` | 校验链完整性（返回篡改定位） | **公开只读** | — |
| 11 | POST | `/api/settlement/weekly/{writer_id}` | 广告分成周结（滚动公式，扣固定 0.5 书币手续费） | **老板** | `X-API-Key: demo-boss-key-2026` |
| 12 | POST | `/api/settlement/cancel-account/{writer_id}` | 作家注销（**需出示本人私钥**），未到期收益划转平台 | **作家 + 私钥证明** | `X-API-Key: demo-writer-key-2026` |
| 13 | POST | `/api/boss/staff` | **老板授予/回收员工账号**（内部角色由老板授权） | **老板** | `X-API-Key: demo-boss-key-2026` |
| 14 | POST | `/api/staff/monthly-report` | **员工每月向老板上缴本月工作内容**（正文哈希上链） | **审核部** | `X-API-Key: demo-reviewer-key-2026`<br>或 `demo-minister-key-2026` |
| 15 | GET | `/api/boss/monthly-reports` | **老板查阅全部月度工作上缴记录**（含内部管理信息，v2.0 起需鉴权） | **老板** | `X-API-Key: demo-boss-key-2026` |
| 16 | POST | `/api/settlement/monthly/{writer_id}` | **读者打赏月结**（抽成 30%，不收手续费） | **老板** | `X-API-Key: demo-boss-key-2026` |
| 17 | POST | `/api/advertiser/records` | **广告商查自身流水**（Ed25519 私钥持有证明，密码学隐私隔离） | **公开 + 密码学证明** | —（用 Ed25519 私钥做持有证明，比 API Key 强度更高） |

> 接口 1-12 为核心业务闭环（含 7′ 读者打赏），接口 13-17 为管理增强功能（员工授权、月度工作上缴、打赏月结、隐私隔离），
> 接口 17 解决「联盟链不可篡改≠人人可见」的权限隔离问题。

### 5.1 隐私隔离（接口 17）为什么用密码学而非按 ID 过滤

联盟链的「不可篡改」不等于「人人可见」。若全量账目对广告商开放，同行投了什么、投了多少、
读者举报了什么都会泄露，权限隔离就不是加分项而是**落地前置条件**。

但很多同类Demo 只按 `advertiser_id` 过滤就算「权限隔离」—— 只要 ID 可枚举
（`ADV_001`、`ADV_002`……），任何人换个 ID 就能看别人的账，隔离形同虚设。

本接口要求提交广告商 **Ed25519 私钥**做持有证明：

1. 用私钥推导公钥；
2. 与链上双签区块中登记的该广告商公钥逐一比对；
3. 不匹配、或该广告商从未双签 -> `403` 拒绝。

因此伪造 `advertiser_id` 也拿不到别人的流水。实测：冒用他人 ID + 本人私钥 -> `403`；
乱填私钥 -> `403`；本人私钥 -> `200` 且记录区不含同行订单、读者举报证据、作家收益字段。

## 五之二、业务参数（平台既定规则）

| 项目 | 规则 |
|---|---|
| 书币兑换 | **1 元 = 10 书币**（内部记账凭证，不可流通提现） |
| CPM 定价 | **合规弹窗 12** 书币/千次曝光；**普通广告 8** 书币/千次曝光（按类型服务端定价，客户端不可自填） |
| 作家分成 | 广告分成 **40%**（服务端锁定，客户端不可改） |
| 单篇单日分成上限 | **200 书币**（防刷量） |
| 打赏抽成 | 平台抽 **30%**，打赏瞬间实时抽取 |
| 周结手续费 | **固定 0.5 书币**（定值，不随结算金额放大） |
| 打赏月结 | **不额外收手续费**，无单篇单日上限 |
| 跨周期滚动结算 | `本周分成 − 本期新处罚 + 历史滚动调整 − 历史欠款抵扣 − 手续费` |
| 欠款结转 | 扣罚超分成时**不产生负数发放**，差额转为 `settle_debt` 欠款，由后续结算期优先抵扣；注销时一次性清账 |
| 员工账号 | 内部角色**必须由老板授予**，老板可随时回收 |
| 月度工作 | 员工每月向老板上缴工作内容，正文哈希上链 |

### 快速演示顺序（可复制的 curl 脚本）

服务启动后，在另一个终端粘贴以下脚本即可跑通核心闭环。
脚本会自动从上一步响应中提取 `order_id` 与私钥，无需手工替换参数。
> 前置：删除旧的 `chain.json` 与 `raw_exposure/`，保证从创世块开始。

```bash
# ---------- 密钥变量（Demo 密钥；生产环境请用环境变量覆盖）----------
ADV_KEY="demo-advertiser-key-2026"
REVIEW_KEY="demo-reviewer-key-2026"
BOSS_KEY="demo-boss-key-2026"
WRITER_KEY="demo-writer-key-2026"
# v2.0 新增：接口 ④ 需作家出示 Ed25519 私钥做持有证明。
# 预置作家钱包由固定种子派生（demo_wallet()），重启后私钥不变，故此处可直接写死。
# 生产环境绝不可如此：私钥必须由作家自行生成并保管，服务端只登记公钥。
WRITER_PRIVATE_KEY="a6fd1247feffbfcb6acdbee5296054c31a8da482d096994cb15eaa85b2196458"

# ========== 阶段一：广告商充值 + 提交投放申请 ==========
# 充值书币（1 元 = 10 书币）。必须先充值，否则申请会被余额校验拦截。
curl -s -X POST http://localhost:8000/api/advertiser/deposit \
  -H "X-API-Key: $ADV_KEY" \
  -H "Content-Type: application/json" \
  -d '{"advertiser_id":"ADV_001","amount_coin":10000}'

# 提交投放申请：锁定书币 + 广告素材备案哈希上链
# 注意：这里只提交「投放意图」字段。CPM、作家分成、分成上限、打赏抽成
# 全部由服务端 PLATFORM_RULES 锁定，客户端无权设定（多传任一计费字段 -> 422）
APPLY=$(curl -s -X POST http://localhost:8000/api/advertiser/apply \
  -H "X-API-Key: $ADV_KEY" \
  -H "Content-Type: application/json" \
  -d '{"advertiser_id":"ADV_001","advertiser_name":"天行广告","writer_id":"WRITER_001",
       "book_title":"青云剑歌","lock_amount_coin":1000,"ad_type":"banner",
       "material_text":"休闲小说APP，下载即送万卷小说全集"}')
echo "$APPLY"

# 自动提取 order_id 与广告商私钥，供后续步骤使用
# （正则兼容 "key":"v" 与 "key": "v" 两种 JSON 格式）
ORDER_ID=$(echo "$APPLY" | grep -o '"order_id": *"[^"]*"' | cut -d'"' -f4)
PRIV_KEY=$(echo "$APPLY" | grep -o '"advertiser_private_key_hex": *"[^"]*"' | cut -d'"' -f4)
echo "order_id = $ORDER_ID"
echo "私钥长度 = ${#PRIV_KEY}（应为 64）"

# 反例：缺少请求头 -> 403
curl -s -o /dev/null -w "no api key -> HTTP=%{http_code}\n" \
  -X POST http://localhost:8000/api/advertiser/deposit \
  -H "Content-Type: application/json" \
  -d '{"advertiser_id":"ADV_001","amount_coin":10}'

# ========== 阶段二：协议双签名上链（防篡改核心）============
# 广告商 + 平台双签名，两方验签全部通过才允许上链
curl -s -X POST "http://localhost:8000/api/order/sign-agreement/$ORDER_ID" \
  -H "X-API-Key: $ADV_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"advertiser_private_key_hex\":\"$PRIV_KEY\"}"

# 反例：传入非法私钥会被拒绝（链上不产生任何新区块）
curl -s -X POST "http://localhost:8000/api/order/sign-agreement/$ORDER_ID" \
  -H "X-API-Key: $ADV_KEY" \
  -H "Content-Type: application/json" \
  -d '{"advertiser_private_key_hex":"0000000000000000000000000000000000000000000000000000000000000000"}'

# ========== 阶段三：监督与风控 ==========
# 读者举报违规广告（证据哈希上链，原文本地留存）
curl -s -X POST http://localhost:8000/api/reader/report \
  -H "Content-Type: application/json" \
  -d "{\"reader_id\":\"RD_001\",\"order_id\":\"$ORDER_ID\",
       \"reason\":\"广告内容疑似夸大宣传\",\"evidence\":\"页面截图已留存\"}"

# AI 抽检：素材一致性 + 违规关键词（仅辅助风控，结论以人工审核为准）
curl -s -X POST http://localhost:8000/api/ai/random-check \
  -H "X-API-Key: $REVIEW_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"order_id\":\"$ORDER_ID\",\"sample_size\":4}"

# ========== 阶段四：审核部处罚与退款 ==========
# 审核部执行处罚扣款（仅新增区块，历史不可改）
PEN=$(curl -s -X POST http://localhost:8000/api/review/penalty \
  -H "X-API-Key: $REVIEW_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"operator_role\":\"reviewer\",\"operator_id\":\"RV_001\",\"order_id\":\"$ORDER_ID\",
       \"penalty_coin\":50,\"reason\":\"素材夸大宣传，违反平台广告规范\"}")
PENALTY_ID=$(echo "$PEN" | grep -o '"penalty_id": *"[^"]*"' | cut -d'"' -f4)

# 登记处罚撤销退款（滚入下期结算，不修改原处罚区块）
curl -s -X POST http://localhost:8000/api/review/penalty-refund \
  -H "X-API-Key: $REVIEW_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"operator_id\":\"RV_001\",\"penalty_id\":\"$PENALTY_ID\",
       \"refund_coin\":50,\"reason\":\"申诉成立，撤销处罚\"}"

# ========== 阶段五：收益结算与对账 ==========
# 作家广告分成周结（8000 次曝光，扣固定 0.5 书币手续费，曝光明细只上链聚合哈希）
curl -s -X POST "http://localhost:8000/api/settlement/weekly/WRITER_001?exposure=8000" \
  -H "X-API-Key: $BOSS_KEY"

# 作家查询本人链上记录（收益对账透明）
# v2.0：需出示作家私钥做持有证明，私钥放请求体而非 URL
curl -s -X POST http://localhost:8000/api/writer/records \
  -H "Content-Type: application/json" \
  -d "{\"writer_id\":\"WRITER_001\",\"private_key_hex\":\"$WRITER_PRIVATE_KEY\"}"
# 反例：仅凭 writer_id 查询 -> 404（该路径已移除）
curl -s -o /dev/null -w "old GET path -> HTTP=%{http_code}\n" \
  http://localhost:8000/api/writer/WRITER_001/records

# 注：作家注销接口会结束该作家账号，必须放在所有结算之后调用（见阶段六末）

# ========== 阶段六：员工授权与月度工作上缴 ==========
# 老板授予审核部员工账号（内部角色不可自助注册）
curl -s -X POST http://localhost:8000/api/boss/staff \
  -H "X-API-Key: $BOSS_KEY" \
  -H "Content-Type: application/json" \
  -d '{"operator_id":"BOSS_001","staff_id":"REVIEWER_002","staff_name":"审核部员新",
       "staff_role":"reviewer","action":"grant"}'

# 反例：非老板无权授予账号（返回 403）
curl -s -o /dev/null -w "reviewer calls boss api -> HTTP=%{http_code}\n" \
  -X POST http://localhost:8000/api/boss/staff \
  -H "X-API-Key: $REVIEW_KEY" \
  -H "Content-Type: application/json" \
  -d '{"operator_id":"REVIEWER_001","staff_id":"X","staff_name":"Y","staff_role":"reviewer","action":"grant"}'

# 员工每月向老板上缴本月工作内容（正文只上链哈希，原文本地留存）
curl -s -X POST http://localhost:8000/api/staff/monthly-report \
  -H "X-API-Key: $REVIEW_KEY" \
  -H "Content-Type: application/json" \
  -d '{"staff_id":"REVIEWER_001","period":"2026-10",
       "work_summary":"本月处理违规广告37件，处罚12笔，撤销申诉5笔","case_count":37}'

# 老板查阅全部月度工作上缴记录
curl -s http://localhost:8000/api/boss/monthly-reports \
  -H "X-API-Key: $BOSS_KEY"

# 读者打赏（平台实时抽成30%，作家所得累计到 pending_tip_income）
curl -s -X POST http://localhost:8000/api/reader/tip \
  -H "Content-Type: application/json" \
  -d '{"reader_id":"RD_001","writer_id":"WRITER_001","tip_coin":100}'

# 读者打赏月结（发放 pending_tip_income，不收手续费）
# 注：月结只发放已累计的待结打赏，若从未打赏则返回 400「本月无待结算打赏」
curl -s -X POST "http://localhost:8000/api/settlement/monthly/WRITER_001" \
  -H "X-API-Key: $BOSS_KEY"

# 作家注销，未到期收益划转平台（历史记录全部保留）
# 放在最后：注销后该作家不可再结算，且重复注销会被拒绝
# v2.0：注销需出示该作家本人私钥，防止横向越权注销他人账号
curl -s -X POST http://localhost:8000/api/settlement/cancel-account/WRITER_001 \
  -H "X-API-Key: $WRITER_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"private_key_hex\":\"$WRITER_PRIVATE_KEY\"}"

# ========== 阶段七：独立审计 ==========
# 校验整条链完整性（六个维度逐项校验 + 篡改定位）
curl -s http://localhost:8000/api/auditor/verify-chain

# 审计员查询全量链上记录（只读）
curl -s http://localhost:8000/api/auditor/all

# ========== 阶段八：隐私隔离（接口 17）==========
# 广告商查自身备案与充值流水（私钥持有证明）
curl -s -X POST http://localhost:8000/api/advertiser/records \
  -H "Content-Type: application/json" \
  -d "{\"advertiser_id\":\"ADV_001\",\"private_key_hex\":\"$PRIV_KEY\"}"

# 反例：用 ADV_001 的私钥冒查 ADV_002 的流水 -> 403 拒绝
#（若对方只按 ID 过滤，这种情况下会直接返回别人的账）
# 前置：先为同行广告商 ADV_002 走一遍充值 + 申请，使其成为已注册广告商
curl -s -X POST http://localhost:8000/api/advertiser/deposit \
  -H "X-API-Key: $ADV_KEY" \
  -H "Content-Type: application/json" \
  -d '{"advertiser_id":"ADV_002","amount_coin":10000}'

curl -s -X POST http://localhost:8000/api/advertiser/apply \
  -H "X-API-Key: $ADV_KEY" \
  -H "Content-Type: application/json" \
  -d '{"advertiser_id":"ADV_002","advertiser_name":"同行广告","writer_id":"WRITER_001",
       "book_title":"青云剑歌","lock_amount_coin":500,
       "material_text":"同行广告素材内容"}' > /dev/null

curl -s -o /dev/null -w "impersonate peer -> HTTP=%{http_code}\n" \
  -X POST http://localhost:8000/api/advertiser/records \
  -H "Content-Type: application/json" \
  -d "{\"advertiser_id\":\"ADV_002\",\"private_key_hex\":\"$PRIV_KEY\"}"
```

### 答辩演示建议（3 分钟版）

| 阶段 | 演示动作 | 想让评委看到什么 |
|---|---|---|
| 1 | 跑阶段一 + 阶段二双签名 | 计费条款被双签固化，平台事后改价将导致验签失败 |
| 2 | 跑阶段七 `/api/auditor/verify-chain`，展示六项校验全绿 | 链可自证完整，审计员独立于平台 |
| 3 | **改`chain.json` 某块内容后重跑校验**（无需重启，见下方说明） | 精准定位到被篡改的区块高度与中文原因 |
| 4 | 跑阶段五周结 + 作家查记录 | 收益每一笔可对账，明细只上链哈希 |
| 5 | **用 A 广告商的私钥冒查 B 广告商的流水（返回 403）** | 权限隔离是密码学级，不是换个 ID 就能看 |

## 六、项目结构

```
adchain-trust/
├── main.py                    # 单文件全量代码（区块链核心 + 数据模型 + AI抽检 + FastAPI）
├── chain.json                 # 链数据持久化文件（自动生成，勿手改）
├── raw_exposure/              # 曝光/举报原始明细本地留存目录（只存哈希上链）
├── test_api.py                 # 全量回归测试（79 条断言，跑 test_api.py 即可验证）
├── requirements.txt
├── README.md
└── 项目设计文档.md
```

`main.py` 用注释分为四个部分：

- **第一部分 区块链核心**：`Wallet`（Ed25519 签名） / `Block`（区块+封块） / `Blockchain`（持久化、只追加、逐块校验、篡改定位） / `Ledger`（书币账本、聚合哈希存证、收益计算）
- **第二部分 数据模型**：`Role`（7 种角色及权限矩阵） / `Account`（账户） / `AdOrder`（订单与计费条款、双签载荷、收益算法）
- **第三部分 AI 抽检**：`AdInspector`（SimHash 感知哈希相似度、7 类违规关键词库、抽检报告上链）
- **第四部分 FastAPI 接口**：18 个接口 + Pydantic 请求模型
- **平台规则常量**：`PLATFORM_RULES` / `platform_cpm()` —— 计费条款唯一权威来源，客户端不可设定

## 六之二、跑一遍测试

```bash
python test_api.py
# 期望输出：TOTAL: PASS=79 FAIL=0
```

测试覆盖 18 个接口的主流程与关键反例，其中两条是 v2.0 的安全回归：

| 用例 | 验证点 |
|---|---|
| `注入恶意条款被拒(extra=forbid)` | 广告商多传 `writer_share_ratio=1.0` 等计费字段 → **422** |
| `用W1私钥查W2被拒403` | 冒用他人私钥查询收益 → **403** |
| `用W1私钥注销W2被拒403` | 冒用私钥注销他人账号 → **403**，状态仍为 active |
| `注销缺私钥被拒422` | 不出示私钥直接注销 → **422** |
| `无密钥查月报被拒403` | 无密钥读内部管理信息 → **403** |
| `审计校验仍公开可查` | 审计接口保持公开——验证权公开才谈得上不可篡改 |
| `作家正确私钥查记录` | 出示本人私钥 → 200，且仅返回本人记录 |
| `篡改检出` | 手改 `chain.json` → `chain_valid: false` 并定位到区块高度 |

---

## 七、系统边界（诚实声明）

- 本系统为**教学/竞赛演示原型**：链为单节点本地文件持久化，未接入真实联盟链网络（Fabric/长安链等）与共识算法。
- 私钥在演示中由服务端托管并返回给调用方，生产环境须由广告商自行保管、使用硬件钱包或 HSM。
- AI 抽检的"线上实际素材"由模拟器生成，真实环境需接入页面抓取 / 截图 OCR；AI 仅输出辅助报告，**最终违规认定与处罚由人工审核部作出**。
- 书币不可流通、不可提现，仅平台内部结算使用，不涉及任何真实虚拟资产交易。