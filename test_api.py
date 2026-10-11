# -*- coding: utf-8 -*-
"""AdChain Trust v2.0 全量接口测试（进程内 TestClient，含第5/7条安全回归）"""
import os, sys

TARGET = r"C:\Users\86187\WorkBuddy\2026-10-11-12-52-25\adchain-trust"
os.chdir(TARGET)
sys.path.insert(0, TARGET)

# ---- 必须在 import main 之前清链，保证测试从创世块开始 ----
for f in ("chain.json",):
    p = os.path.join(TARGET, f)
    if os.path.exists(p):
        os.remove(p)

from fastapi.testclient import TestClient
import main
from main import accounts, orders, ledger, chain, PLATFORM_RULES
from cryptography.hazmat.primitives import serialization

client = TestClient(main.app)
KEYS = {
    "boss": "demo-boss-key-2026",
    "reviewer": "demo-reviewer-key-2026",
    "advertiser": "demo-advertiser-key-2026",
    "writer": "demo-writer-key-2026",
}
H = lambda role: {"X-API-Key": KEYS[role]}

PASS = 0
FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS |", name, "|", detail)
    else:
        FAIL += 1
        print("FAIL |", name, "|", detail)

def priv_hex(acc_id):
    w = accounts[acc_id].wallet
    return w.private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()

# ============ 0. 越权前置 ============
r = client.post("/api/advertiser/deposit", json={"advertiser_id": "ADV_001", "amount_coin": 1000})
check("无API-Key写接口被拒", r.status_code == 403, f"status={r.status_code}")
r = client.post("/api/advertiser/deposit", json={"advertiser_id": "ADV_001", "amount_coin": 1000}, headers=H("boss"))
check("老板Key调广告商接口被拒", r.status_code == 403, f"status={r.status_code}")

# ============ 1. 充值（1元=10书币） ============
r = client.post("/api/advertiser/deposit", json={"advertiser_id": "ADV_001", "amount_coin": 1000}, headers=H("advertiser"))
check("广告商充值1000书币", r.status_code == 200, r.text[:160])
check("充值后余额=1000", ledger.balance_of("ADV_001") == 1000, str(ledger.balance_of("ADV_001")))
dep = [b.data for b in chain.blocks if b.data.get("type") == "deposit"]
check("充值区块real_amount=100元(10书币/元)", dep and dep[-1].get("real_amount_cny") == 100.0, str(dep[-1].get("real_amount_cny") if dep else None))
check("充值区块exchange_rate=10", dep and "10 book_coin" in dep[-1].get("exchange_rate", ""), str(dep[-1].get("exchange_rate") if dep else None))

# ============ 2. 投放申请（服务端锁定条款） ============
r = client.post("/api/advertiser/apply", headers=H("advertiser"), json={
    "advertiser_id": "ADV_001", "advertiser_name": "测试广告商", "writer_id": "WRITER_001",
    "book_title": "测试小说", "ad_type": "compliant_popup", "lock_amount_coin": 1000,
    "material_text": "暑假特惠，全网最低价！点我领取专属福利。",
})
check("投放申请(合规弹窗)", r.status_code == 200, r.text[:160])
j = r.json()
check("CPM=12(合规弹窗)", j.get("cpm_price") == 12.0, str(j.get("cpm_price")))
check("作家分成=40%", j.get("writer_share_ratio") == 0.4, str(j.get("writer_share_ratio")))
check("exchange_rate=10", "10 book_coin" in j.get("exchange_rate", ""), str(j.get("exchange_rate")))
order_id = j["order_id"]

# 尝试用 extra 字段注入条款（extra=forbid 应 422）
r = client.post("/api/advertiser/apply", headers=H("advertiser"), json={
    "advertiser_id": "ADV_001", "advertiser_name": "恶意广告商", "writer_id": "WRITER_001",
    "ad_type": "banner", "lock_amount_coin": 100, "material_text": "x",
    "writer_share_ratio": 1.0, "writer_daily_cap": 999999, "tip_platform_ratio": 0.0,
})
check("注入恶意条款被拒(extra=forbid)", r.status_code == 422, f"status={r.status_code}")

# 接口总数与作家接口形态（v2.0：接口④由 GET 改为 POST + 私钥持有证明）
_api = [rt for rt in main.app.routes if getattr(rt, "path", "").startswith("/api/")]
check("接口总数=18", len(_api) == 18, f"count={len(_api)}")
_paths = {getattr(rt, "path", "") for rt in _api}
check("作家记录接口为POST", any(
    getattr(rt, "path", "") == "/api/writer/records" and "POST" in getattr(rt, "methods", set())
    for rt in _api), "POST /api/writer/records 应存在")
check("旧GET作家路径已移除", "/api/writer/{writer_id}/records" not in _paths,
      "旧路径不应存在")

# ============ 3. 双签名 ============
r = client.post(f"/api/order/sign-agreement/{order_id}", headers=H("advertiser"),
                json={"advertiser_private_key_hex": priv_hex("ADV_001")})
check("订单双签名上链", r.status_code == 200, r.text[:200])
check("订单状态DUAL_SIGNED", orders[order_id].status == "DUAL_SIGNED", orders[order_id].status)
check("链上广告商公钥=登记公钥",
      orders[order_id].signatures["advertiser"]["public_key"]
      == accounts["ADV_001"].wallet.public_key_hex,
      "签名公钥必须与登记身份一致，否则「双签名保护广告商」语义失效")

# ---- v2.0 防代签：陌生私钥不得替他人签署订单（横向越权）----
# 背景：签名本身只证明「某把私钥签了」，不证明「签名人就是订单归属广告商」。
# 若只验签不验公钥归属，攻击者用自己的私钥签别人的订单，验签照样全 true。
_r = client.post("/api/advertiser/deposit",
                 json={"advertiser_id": "ADV_001", "amount_coin": 500}, headers=H("advertiser"))
_fake_order = client.post("/api/advertiser/apply", headers=H("advertiser"), json={
    "advertiser_id": "ADV_001", "advertiser_name": "测试广告商", "writer_id": "WRITER_001",
    "book_title": "代签测试小说", "ad_type": "banner", "lock_amount_coin": 100,
    "material_text": "代签越权测试素材。"}).json()["order_id"]
r = client.post(f"/api/order/sign-agreement/{_fake_order}", headers=H("advertiser"),
                json={"advertiser_private_key_hex": "11" * 32})
check("陌生私钥代签被拒403", r.status_code == 403, f"status={r.status_code}, {r.text[:120]}")
check("代签未改变订单状态", orders[_fake_order].status == "APPLIED", orders[_fake_order].status)
check("代签未产生双签生效区块", not any(
    b.data.get("type") == "ad_order_onchain" and b.data.get("order_id") == _fake_order
    for b in chain.blocks), "越权订单不应产生双签生效区块")

# ============ 4. 读者打赏（实时抽成30%+月结） ============
r = client.post("/api/reader/tip", json={"reader_id": "R_001", "writer_id": "WRITER_001", "tip_coin": 100})
check("打赏100书币", r.status_code == 200, r.text[:160])
check("打赏实时抽成30%", r.json().get("platform_cut") == 30.0, str(r.json().get("platform_cut")))
check("作家实时得70%", r.json().get("writer_get") == 70.0, str(r.json().get("writer_get")))
check("pending_tip=70", accounts["WRITER_001"].pending_tip_income == 70.0, str(accounts["WRITER_001"].pending_tip_income))

r = client.post("/api/reader/tip", json={"reader_id": "R_002", "writer_id": "WRITER_001", "tip_coin": 50})
check("再打赏50书币", r.status_code == 200, r.text[:160])
check("pending_tip累计=105", accounts["WRITER_001"].pending_tip_income == 105.0, str(accounts["WRITER_001"].pending_tip_income))

# 月结（boss 触发）：结算105，不二次抽成，无手续费
r = client.post("/api/settlement/monthly/WRITER_001", headers=H("boss"))
check("打赏月结", r.status_code == 200, r.text[:200])
mj = r.json()
check("月结金额=105(已实时抽成)", mj.get("tip_amount") == 105.0, str(mj.get("tip_amount")))
check("月结不再二次抽成", mj.get("platform_cut") == 0.0, str(mj.get("platform_cut")))
check("月结手续费=0", mj.get("fee") == 0.0, str(mj.get("fee")))
check("月结后作家实得=105", mj.get("writer_payout") == 105.0, str(mj.get("writer_payout")))
check("月结后pending清空", accounts["WRITER_001"].pending_tip_income == 0.0, str(accounts["WRITER_001"].pending_tip_income))

# 空打赏月结应拒绝
r = client.post("/api/settlement/monthly/WRITER_001", headers=H("boss"))
check("无待结算打赏月结被拒", r.status_code == 400, f"status={r.status_code}")

# ============ 5. 处罚 + 退款 + 周结（固定0.5手续费） ============
r = client.post("/api/review/penalty", headers=H("reviewer"), json={
    "operator_role": "reviewer", "operator_id": "REVIEWER_001", "order_id": order_id,
    "penalty_coin": 20, "reason": "素材违规测试", "penalty_id": "PN_001"})
check("审核部处罚扣款20", r.status_code == 200, r.text[:200])

r = client.post("/api/review/penalty-refund", headers=H("reviewer"), json={
    "operator_id": "REVIEWER_001", "penalty_id": "PN_001", "refund_coin": 20, "reason": "申诉成立退款"})
check("处罚退款20滚入下期", r.status_code == 200, r.text[:200])
check("退款进pending_income", accounts["WRITER_001"].pending_income == 20.0, str(accounts["WRITER_001"].pending_income))

r = client.post("/api/settlement/weekly/WRITER_001?exposure=8000", headers=H("boss"))
check("周结(8000曝光)", r.status_code == 200, r.text[:200])
wj = r.json()
check("毛分成=38.4(8000/1000*12*0.4)", wj.get("gross_income") == 38.4, str(wj.get("gross_income")))
check("周结手续费=固定0.5", wj.get("platform_fee") == 0.5, str(wj.get("platform_fee")))
check("滚动公式:38.4-20+20-0.5=37.9", wj.get("payout") == 37.9, str(wj.get("payout")))

# ---- v2.0 负数发放兜底：扣罚远超分成时不得产生负数 payout ----
# 先给 WRITER_002 建一张已双签订单，否则下面这段无从触发（v2.0 曾被 if 包裹而空跑）
r = client.post("/api/advertiser/deposit",
                json={"advertiser_id": "ADV_001", "amount_coin": 500}, headers=H("advertiser"))
check("为W2测试补充充值500", r.status_code == 200, r.text[:120])
r = client.post("/api/advertiser/apply", headers=H("advertiser"), json={
    "advertiser_id": "ADV_001", "advertiser_name": "测试广告商", "writer_id": "WRITER_002",
    "book_title": "欠款测试小说", "ad_type": "banner", "lock_amount_coin": 500,
    "material_text": "欠款结转机制测试素材。",
})
check("为W2创建投放订单", r.status_code == 200, r.text[:160])
w2_order_id = r.json()["order_id"]
r = client.post(f"/api/order/sign-agreement/{w2_order_id}", headers=H("advertiser"),
                json={"advertiser_private_key_hex": priv_hex("ADV_001")})
check("W2订单双签名完成", r.status_code == 200, r.text[:160])
check("W2订单状态DUAL_SIGNED",
      orders[w2_order_id].status == "DUAL_SIGNED", orders[w2_order_id].status)

# 扣罚 100 远超分成（曝光100 → 毛分成约 0.48），raw_payout 会算成负数
for _i in range(2):
    client.post("/api/review/penalty", headers=H("reviewer"), json={
        "operator_id": "REVIEWER_001", "order_id": w2_order_id,
        "penalty_coin": 50, "reason": f"欠款测试{_i}"})
_j = client.post("/api/settlement/weekly/WRITER_002?exposure=100",
                 headers=H("boss")).json()
check("扣罚超分成不发负数", _j.get("payout") == 0.0, f"payout={_j.get('payout')}")
check("差额结转为欠款", _j.get("carryover_debt", 0) > 0,
      f"carryover_debt={_j.get('carryover_debt')}")
_debt = _j.get("carryover_debt")
# 下一期高曝光应优先抵扣欠款
_j2 = client.post("/api/settlement/weekly/WRITER_002?exposure=50000",
                  headers=H("boss")).json()
check("下期抵扣历史欠款", abs(_j2.get("debt_offset", 0) - _debt) < 0.02,
      f"offset={_j2.get('debt_offset')} debt={_debt}")
check("抵扣后不再有欠款", _j2.get("carryover_debt") == 0.0,
      f"carryover_debt={_j2.get('carryover_debt')}")
check("抵扣后实发为正", _j2.get("payout", 0) > 0, f"payout={_j2.get('payout')}")
# 链上不得存在负数 payout 的结算区块
_neg = [b.index for b in chain.blocks
        if b.data.get("type") == "settlement_weekly" and b.data.get("payout", 0) < 0]
check("链上无负数发放区块", not _neg, f"negative_at={_neg}")

# ============ 6. 作家查记录（私钥持有证明） ============
r = client.post("/api/writer/records", json={"writer_id": "WRITER_001", "private_key_hex": priv_hex("WRITER_001")})
check("作家正确私钥查记录", r.status_code == 200, f"status={r.status_code}, 记录数={len(r.json().get('records', []))}")
r = client.post("/api/writer/records", json={"writer_id": "WRITER_001", "private_key_hex": "00" * 32})
check("作家错误私钥被拒403", r.status_code == 403, f"status={r.status_code}")
r = client.post("/api/writer/records", json={"writer_id": "WRITER_002", "private_key_hex": priv_hex("WRITER_001")})
check("用W1私钥查W2被拒403", r.status_code == 403, f"status={r.status_code}")

# ============ 7. 广告商查流水（隐私隔离） ============
r = client.post("/api/advertiser/records", json={"advertiser_id": "ADV_001", "private_key_hex": priv_hex("ADV_001")})
check("广告商正确私钥查流水", r.status_code == 200, f"status={r.status_code}")
r = client.post("/api/advertiser/records", json={"advertiser_id": "ADV_001", "private_key_hex": "11" * 32})
check("广告商错误私钥被拒403", r.status_code == 403, f"status={r.status_code}")

# ============ 8. AI 抽检（阈值0.6） ============
r = client.post("/api/ai/random-check", headers=H("reviewer"), json={"order_id": order_id, "sample_size": 1})
check("AI抽检", r.status_code == 200, r.text[:300])
check("抽检阈值=0.6", "0.6" in r.text, "阈值出现在响应中" if "0.6" in r.text else "未见0.6")

# ============ 9. 读者举报 ============
r = client.post("/api/reader/report", json={"reader_id": "R_001", "order_id": order_id, "reason": "广告疑似诈骗", "evidence": "截图证据"})
check("读者举报上链", r.status_code == 200, f"status={r.status_code}")

# ============ 10. 老板授权员工 + 员工月报 ============
r = client.post("/api/boss/staff", headers=H("boss"), json={
    "operator_id": "BOSS_001", "staff_id": "REVIEWER_002", "staff_name": "新审核员", "staff_role": "reviewer", "action": "grant"})
check("老板授予审核员", r.status_code == 200, r.text[:200])
r = client.post("/api/boss/staff", headers=H("reviewer"), json={
    "operator_id": "REVIEWER_001", "staff_id": "REVIEWER_003", "staff_name": "越权者", "staff_role": "reviewer", "action": "grant"})
check("非老板授权被拒403", r.status_code == 403, f"status={r.status_code}")

# v2.0 路径穿越回归：ID 会被拼进 raw_exposure/report_{staff_id}_{period}.json，
# 只限长度不限字符时 "../../pwned" 可让文件落到目录外——必须 422
for _bad in ("../../pwned", "..\\..\\pwned", "a/b"):
    _r = client.post("/api/boss/staff", headers=H("boss"), json={
        "operator_id": "BOSS_001", "staff_id": _bad, "staff_name": "穿越",
        "staff_role": "reviewer", "action": "grant"})
    check(f"路径穿越ID被拒422({_bad[:8]})", _r.status_code == 422, f"status={_r.status_code}")
# 纵深防御：即使绕过上层白名单，底层落盘也必须拒绝越界路径
try:
    ledger.write_raw_exposure("../../direct_pwn", [{"x": 1}])
    check("底层拒绝穿越路径", False, "未拦截")
except ValueError:
    check("底层拒绝穿越路径", True, "已拦截")

r = client.post("/api/staff/monthly-report", headers=H("reviewer"), json={
    "staff_id": "REVIEWER_001", "period": "2026-10", "work_summary": "本月处理违规举报23起", "case_count": 23})
check("员工月报上缴", r.status_code == 200, r.text[:200])
r = client.get("/api/boss/monthly-reports", headers=H("boss"))
check("老板查月报", r.status_code == 200, f"status={r.status_code}")
# v2.0：月报含员工姓名与案件量等内部管理信息，不应公开可查
r = client.get("/api/boss/monthly-reports")
check("无密钥查月报被拒403", r.status_code == 403, f"status={r.status_code}")
# 反之，审计接口必须保持公开——链的验证权公开才谈得上「不可篡改」
r = client.get("/api/auditor/verify-chain")
check("审计校验仍公开可查", r.status_code == 200, f"status={r.status_code}")

# ============ 11. 注销（未结算打赏一并划转） ============
client.post("/api/reader/tip", json={"reader_id": "R_001", "writer_id": "WRITER_002", "tip_coin": 50})
check("W2打赏后pending=35", accounts["WRITER_002"].pending_tip_income == 35.0, str(accounts["WRITER_002"].pending_tip_income))
# v2.0 横向越权回归：持作家密钥但出示W1私钥去注销W2 -> 必须403
r = client.post("/api/settlement/cancel-account/WRITER_002", headers=H("writer"),
                json={"private_key_hex": priv_hex("WRITER_001")})
check("用W1私钥注销W2被拒403", r.status_code == 403, f"status={r.status_code}")
check("越权注销未生效", accounts["WRITER_002"].status == "active",
      f"status={accounts['WRITER_002'].status}")
# 缺私钥 -> 422
r = client.post("/api/settlement/cancel-account/WRITER_002", headers=H("writer"), json={})
check("注销缺私钥被拒422", r.status_code == 422, f"status={r.status_code}")
# 本人私钥 -> 放行
r = client.post("/api/settlement/cancel-account/WRITER_002", headers=H("writer"),
                json={"private_key_hex": priv_hex("WRITER_002")})
check("作家本人私钥注销成功", r.status_code == 200, r.text[:250])
cj = r.json()
check("注销划转打赏35", cj.get("transfer_tip_coin") == 35.0, str(cj.get("transfer_tip_coin")))
check("注销后状态canceled", accounts["WRITER_002"].status == "canceled", accounts["WRITER_002"].status)

# 已注销作家不能打赏
r = client.post("/api/reader/tip", json={"reader_id": "R_001", "writer_id": "WRITER_002", "tip_coin": 10})
check("已注销作家打赏被拒400", r.status_code == 400, f"status={r.status_code}")

# ============ 12. 审计 ============
r = client.get("/api/auditor/all")
check("审计全量查询", r.status_code == 200 and r.json().get("readonly") is True and r.json().get("total", 0) > 0, f"total={r.json().get('total')}")
r = client.get("/api/auditor/verify-chain")
check("链完整性校验", r.status_code == 200 and r.json().get("chain_valid") is True, r.text[:300])

# ============ 13. 篡改检出 ============
import json as _json
chain_file = os.path.join(TARGET, "chain.json")
data = _json.load(open(chain_file, encoding="utf-8"))
if isinstance(data, dict) and "blocks" in data:
    blocks = data["blocks"]
else:
    blocks = data
tamper_idx = len(blocks) // 2
blocks[tamper_idx]["data"]["note"] = "攻击者篡改"
_json.dump(data, open(chain_file, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
r = client.get("/api/auditor/verify-chain")
check("篡改检出", r.status_code == 200 and r.json().get("chain_valid") is False and r.json().get("tamper_detected") is True, r.text[:300])

print("=" * 60)
print(f"TOTAL: PASS={PASS} FAIL={FAIL}")
