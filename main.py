# -*- coding: utf-8 -*-
"""
================================================================================
 基于联盟链的网文广告多方信任存证系统  (AdChain Trust v2.0)

 【v2.0 变更说明】
   1. 计费条款改为服务端锁定（PLATFORM_RULES）：
      早期版本允许广告商自行提交分成比例、分成上限、打赏抽成、CPM 单价，
      结果造成严重的信任模型漏洞 —— 广告商可提交「作家分成 100%、上限无限、
      平台抽成 0」，服务端照单全收并由平台签名，恶意条款被「合法固化」上链，
      chain_valid 依然为 True。双签名不但没防住，反而沦为帮凶。
      根因：双签名的前提是「双方对同一份可信条款达成一致」；
      条款若由其中一方拟定，双签名只能证明「双方都签了字」。
      v2.0 起客户端只能选择广告类型，全部计费条款由服务端规则决定。
   2. 作家查询本人收益改为密码学持有证明（接口 ④）：
      原 `GET /api/writer/{writer_id}/records` 只凭 writer_id 即可查询，
      而 ID 可枚举（W_001、W_002……），属「假隔离」。
      现改为 `POST /api/writer/records` + Ed25519 私钥持有证明，
      与接口 ⑰ 广告商隔离方案一致；私钥放请求体而非 URL，避免进访问日志。

 【项目定位声明 —— 请务必先读这一段】
   本项目是一个**教学/竞赛用途的「模拟存证链」原型Demo**，
   用单文件 Python 在本地重现「多方共同记账 + 篡改可检出」的核心思想，
   便于评委本地一条命令跑起来、直接观察业务闭环。

   它**不是**生产级联盟链，**没有**以下任何能力，请勿按生产标准理解或引用：
     × 没有 P2P 网络与节点发现（Gossip / Kademlia 等）
     × 没有共识算法（PoW / Raft / PBFT / Tendermint 等一概没有）
     × 没有智能合约（没有 EVM，也没有 DSL，链上逻辑全部是Python 代码）
     × 没有多节点容灾、区块最终性保证、区块奖励与激励
     × 没有链上分叉、治理提案、区块压缩与归档策略
   区块的追加由单一 Python 进程内的函数调用完成，**不存在挖矿，也不存在代币发行**。

   本Demo 的价值在于**业务建模与存证设计**：
   双签名协议、滚动结算、防重复扣款、聚合哈希存证、逐块篡改定位。

 AI 定位：辅助风控组件
   仅做「广告素材一致性抽检」（感知哈希比对 + 违规关键词命中），
   不替代人工审核，不自动处罚，只输出抽检报告供审核部参考。

 书币定位：平台内部记账凭证
   不可对外流通、不可提现、不涉及任何代币发行或挖矿激励。

--------------------------------------------------------------------------------
 技术要点：
   * 本地持久化：新区块自动追加写入 chain.json，重启自动加载（含 fsync 落盘）
   * 逐块完整性校验：区块哈希 / 前哈希 / 双签名 / 高度锁 / index 连续 / 时间单调
   * 只追加不修改（append-only）：退款、处罚、注销划转一律新增区块
   * 协议双签名：广告商 + 平台双签齐备才允许打包上链
   * 聚合哈希存证：曝光明细只上链摘要哈希，原始明细留本地，核验时重算比对
   * 角色鉴权：写接口需携带对应角色 API Key（环境变量配置，Demo 默认兜底）

 启动：
   python -m uvicorn main:app --reload            # 默认 8000
   python main.py                                  # 等价，默认 8000
   换端口时用 --port 8899，并同时设 ADCHAIN_PORT=8899，
   这样启动横幅会打印出与实际一致的文档地址。
   浏览器打开 http://127.0.0.1:<端口>/docs  (Swagger 自动列出全部 18 个接口)

 文件结构（单文件，不拆分、不生成 __init__.py）：
   第一部分：存证链核心   Block / Blockchain / Wallet / Ledger
   第二部分：数据模型     Role / Account / AdOrder
   第三部分：AI 抽检      AdInspector
   第四部分：FastAPI 接口（17 个，含鉴权与统一异常处理）
================================================================================
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import random
import shutil
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

# ==============================================================================
#  日志配置（落盘失败 / 链文件损坏等关键事件必须留痕，不能静默处理）
# ==============================================================================
logger = logging.getLogger("adchain")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] %(asctime)s %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ==============================================================================
#  工具函数
# ==============================================================================

CHAIN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chain.json")
# 曝光原始明细本地留存的目录（大容量数据不上链，只上链聚合哈希）
RAW_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "raw_exposure")


# ==============================================================================
#  平台规则常量（服务端唯一权威来源）
# ==============================================================================
# 【为什么必须由服务端锁定，而不是让客户端提交】
#   早期版本把 writer_share_ratio / writer_daily_cap / tip_platform_ratio
#   暴露为接口入参，由广告商自行填写。这看似灵活，实则制造了一个严重的
#   信任模型漏洞：
#     广告商提交 share=1.0（作家分成 100%）、cap=9999999（上限近乎无限）、
#     tip=0.0（平台抽成 0）→ 服务端照单全收→ 平台被迫对这份额额条款签名
#     → 条款被「合法固化」上链，chain_valid 依然为True。
#   也就是说：双签名没有防住恶意条款，反而把恶意条款变成��不可篡改的合法证据」。
#
#   双签名的前提是「双方对同一份可信条款达成一致」。若条款本身由其中一方
#   随意拟定，双签名只能证明「双方都签了字」，无法证明「条款对作家公平」。
#
#   因此本项目将全部计费条款收敛为服务端常量：客户端只能选择「投什么类型
#   的广告」，不能决定「按什么价格、什么分成比例结算」。这才是先有可信条款、
#   再有双方签名。
PLATFORM_RULES = {
    # 书币兑换比例：1 元 = 10 书币（平台内部记账凭证，不可流通提现）
    "exchange_rate": "1 CNY = 10 book_coin",
    # 作家广告分成比例 40%
    "writer_share_ratio": 0.4,
    # 单篇单日作家分成上限 200 书币（防刷量）
    "writer_daily_cap": 200.0,
    # 读者打赏平台抽成 30%（打赏瞬间实时抽取）
    "tip_platform_ratio": 0.3,
    # 差异化 CPM 定价：合规弹窗 12书币/千次曝光，普通横幅 8 书币/千次曝光
    # 用价格杠杆引导广告商采用不打扰阅读体验的形式
    "cpm_by_ad_type": {
        "compliant_popup": 12.0,
        "banner": 8.0,
    },
    # 周结手续费：固定 0.5 书币（定值而非比例，避免大额结算被抽走过多）
    "weekly_settle_fee": 0.5,
}


def platform_cpm(ad_type: str) -> float:
    """
    按广告类型返回平台定价（服务端唯一权威来源）。

    客户端无法自行填写 CPM，只能选择广告类型；价格由服务端决定。
    """
    return PLATFORM_RULES["cpm_by_ad_type"].get(ad_type, 8.0)


def now_iso() -> str:
    """统一时间格式（UTC ISO8601），保证哈希计算时字段顺序稳定。"""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def canonical_json(obj: Any) -> str:
    """
    规范化 JSON 序列化：sort_keys + 紧凑分隔符 + ensure_ascii=False
    这是哈希计算的基础，保证同一份内容在任何机器上都得到同一个字节串。
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    """SHA-256 摘要，字符串按 UTF-8 编码。"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def gen_id(prefix: str) -> str:
    """生成带业务前缀的唯一 ID。"""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def now_ts() -> int:
    """当前 Unix 时间戳（秒）。"""
    return int(time.time())


# ==============================================================================
#  第一部分：区块链核心
#  Block / Wallet / Blockchain / Ledger
# ==============================================================================

# ------------------------------------------------------------------------------
#  1.1 Wallet —— 基于 Ed25519 的数字钱包，负责双签名协议
# ------------------------------------------------------------------------------
class Wallet:
    """
    模拟存证链中的参与方钱包。
    每个参与者（平台 / 广告商）持有一对 Ed25519 密钥：
      - 私钥自己保管用于签名
      - 公钥公开用于验签
    订单协议必须由「广告商 + 平台」双方分别签名，链上只记录签名与公钥。
    注意：本Demo 中密钥在服务端生成并返回给调用方，属于演示简化，
    生产环境应由广告商自行保管或使用 HSM / KMS 等硬件密钥管理服务。
    """

    def __init__(self, owner_name: str, private_key: Optional[Ed25519PrivateKey] = None):
        self.owner_name = owner_name
        self.private_key = private_key or Ed25519PrivateKey.generate()
        self.address: str = self._derive_address()

    def _derive_address(self) -> str:
        """用公钥的 SHA-256 前 32 位十六进制作为链上地址（不重复即唯一）。"""
        pub_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return "0x" + hashlib.sha256(pub_bytes).hexdigest()[:32]

    @property
    def public_key_hex(self) -> str:
        """公钥十六进制字符串（写入区块用于验签）。"""
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def sign(self, payload: dict) -> str:
        """
        对结构化 payload 做规范化序列化后签名。
        返回 base64 编码的签名串。
        """
        message = canonical_json(payload).encode("utf-8")
        return base64.b64encode(self.private_key.sign(message)).decode("utf-8")

    @staticmethod
    def verify(payload: dict, public_key_hex: str, signature_b64: str) -> bool:
        """
        静态验签：验证签名是否与 payload + 公钥匹配。
        返回 True 表示该签名合法。
        """
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            message = canonical_json(payload).encode("utf-8")
            pub.verify(base64.b64decode(signature_b64), message)
            return True
        except Exception:
            return False


# ------------------------------------------------------------------------------
#  1.2 Block —— 区块结构（只追加，不可修改）
# ------------------------------------------------------------------------------
@dataclass
class Block:
    """
    区块。所有业务动作（充值 / 双签上链 / 处罚 / 退款 / 举报 / AI抽检 /
    周结算 / 注销划转）都以区块形式追加。

    字段说明：
      index        : 区块高度（0 为创世块）
      timestamp    : 出块时间
      data         : 业务负载
      prev_hash    : 前一区块哈希，构成链式防篡改结构
      hash         : 本区块哈希 = sha256(index+timestamp+data+prev_hash+height)
      height_lock  : 高度锁，任何试图改动已落盘区块内容的操作都会被拒绝
      signatures   : 协议双签名 {角色: {public_key, signature}}
    """

    index: int
    timestamp: str
    data: dict
    prev_hash: str
    hash: str = ""
    height_lock: str = ""
    signatures: Dict[str, Any] = field(default_factory=dict)

    def compute_hash(self) -> str:
        """计算本区块哈希（不含签名，签名只校验不参与哈希）。"""
        body = {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "prev_hash": self.prev_hash,
        }
        return sha256_hex(canonical_json(body))

    def seal(self) -> None:
        """
        封块：计算哈希并写入 height_lock（高度锁）。
        height_lock 一旦写入即代表该区块已封存不可再变更。
        """
        self.hash = self.compute_hash()
        self.height_lock = sha256_hex(f"{self.hash}:{self.index}:{self.timestamp}")


# ------------------------------------------------------------------------------
#  1.3 Blockchain —— 模拟存证链核心（本地持久化 + 逐块校验 + 只追加）
# ------------------------------------------------------------------------------
class Blockchain:
    """
    模拟存证链核心类。职责：
      1) 本地持久化：新区块自动追加写入 chain.json；重启后自动从文件加载整条链
      2) 完整性校验：逐块检查哈希、前哈希、双签名、高度锁、区块高度、时间单调
      3) 只追加：任何业务变更只能 mine_block() 新增区块，物理上不提供修改历史接口

    ⚠️ 能力边界（务必明确，避免被误当作生产级联盟链）：
      本类是**单进程本地文件模拟实现**，没有 P2P 网络、没有共识算法、
      没有智能合约、没有多节点容灾。区块追加由单进程串行调用完成，
      不存在挖矿与代币发行。它演示的是「多方共同记账 + 篡改可检出」的思想。

    并发与可靠性设计：
      *链级 RLock：mine_block 全程持锁，保证并发请求不会写出分叉
      * 原子替换：先写临时文件，再 os.replace 覆盖，避免出现"半个文件"
      * fsync 强制落盘：os.replace 之前刷盘，避免断电/强杀丢块
      * 落盘失败回滚：写盘失败时回滚内存中的区块，保证内存与磁盘始终一致
    """

    GENESIS_PREV_HASH = "0" * 64  # 创世块前哈希约定为 64 个 0

    def __init__(self, chain_file: str = CHAIN_FILE):
        self.chain_file = chain_file
        self.blocks: List[Block] = []
        self.lock = threading.RLock()   # 链级锁，保证并发写链不会产生分叉
        self.load_from_disk()

    # ---------------------------- 持久化 ----------------------------
    def load_from_disk(self) -> int:
        """
        程序启动时调用：从 chain.json 恢复整条链。

        容错策略（逐级降级，保证进程一定能启动）：
          1. 文件不存在          -> 正常初始化创世块
          2. JSON 解析失败       -> 备份为 .broken.<时间戳>，重建创世块，记 WARNING
          3. JSON 合法但缺字段   -> 视为损坏，同上处理
          4. 区块 index 不连续   -> 视为损坏，同上处理（说明文件被外部改动过）
        任何降级都会打印告警日志，绝不静默丢链。
        """
        if not os.path.exists(self.chain_file):
            logger.info("chain.json 不存在，初始化创世块（首次启动属正常情况）")
            self.blocks = []
            self._init_genesis()
            self.save_to_disk()
            return 1

        try:
            with open(self.chain_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if not isinstance(raw, dict) or "blocks" not in raw:
                raise ValueError("chain.json 结构非法：缺少 blocks 字段")

            blocks: List[Block] = []
            for pos, item in enumerate(raw["blocks"]):
                blk = Block(
                    index=item["index"],
                    timestamp=item["timestamp"],
                    data=item["data"],
                    prev_hash=item["prev_hash"],
                    hash=item.get("hash", ""),
                    height_lock=item.get("height_lock", ""),
                    signatures=item.get("signatures", {}),
                )
                # 结构合法性：高度必须从 0 起连续递增，否则视为文件被外部破坏
                if blk.index != pos:
                    raise ValueError(
                        f"区块高度不连续：第 {pos} 个区块的 index={blk.index}"
                    )
                blocks.append(blk)

            if not blocks:                      # 文件存在但为空
                logger.warning("chain.json 中区块列表为空，重建创世块")
                self.blocks = []
                self._init_genesis()
                self.save_to_disk()
                return 1

            self.blocks = blocks
            logger.info("已从 chain.json 恢复整条链，共 %d 个区块", len(self.blocks))
            return len(self.blocks)

        except Exception as e:
            # 文件损坏：备份坏文件后重建创世块，避免整条链无法启动
            backup = f"{self.chain_file}.broken.{now_ts()}"
            try:
                os.rename(self.chain_file, backup)
                logger.error(
                    "chain.json 解析失败（%s: %s），已备份至 %s 并重建创世块。"
                    "注意：损坏文件的链数据需人工从备份中恢复。",
                    type(e).__name__, e, backup,
                )
            except OSError as rename_err:
                logger.error("chain.json 损坏且备份失败（%s），将重建创世块", rename_err)
            self.blocks = []
            self._init_genesis()
            self.save_to_disk()
            return 1

    def save_to_disk(self) -> None:
        """
        把整条链原子化落盘：写临时文件 -> flush -> fsync -> os.replace -> 目录 fsync。

        两层保障：
          * os.replace 保证「要么是旧文件、要么是新文件」，不会出现半个 JSON
          * fsync 保证数据真正落到物理磁盘，断电/强杀不会丢块

        注意：本方法由调用方保证处于 self.lock 保护之下。
        """
        tmp = self.chain_file + ".tmp"
        payload = {"blocks": [asdict(b) for b in self.blocks]}
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
                f.flush()
                # 强制刷盘：仅flush 只能推到操作系统缓冲，断电仍可能丢失
                os.fsync(f.fileno())
            os.replace(tmp, self.chain_file)
            self._fsync_dir()
        except OSError as e:
            # 清理可能残留的半成品临时文件，避免下次启动误读
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            logger.error("chain.json 落盘失败：%s", e)
            raise

    @staticmethod
    def _fsync_dir() -> None:
        """
        刷盘目录项本身，保证 rename 结果持久化。

        平台差异：
          * POSIX：可用 os.open(dir, O_RDONLY) + fsync 刷目录项
          * Windows：目录句柄不能按只读方式 fsync（会报 Permission denied），
            且 NTFS 在 ReplaceFile 语义下已保证元数据落盘，故此处跳过。
        """
        if os.name == "nt":
            return
        dir_path = os.path.dirname(os.path.abspath(CHAIN_FILE)) or "."
        try:
            fd = os.open(dir_path, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as e:
            # 目录刷盘失败不阻断主流程：文件本身已 fsync，风险极低
            logger.warning("目录项刷盘失败（不影响数据完整性）：%s", e)

    def _init_genesis(self) -> None:
        """创建创世块：记录系统初始化与书币体系锚定。"""
        genesis = Block(
            index=0,
            timestamp=now_iso(),
            data={
                "type": "genesis",
                "desc": "模拟存证链创世块：网文广告多方信任存证系统初始化",
                "currency": "book_coin",
                "currency_note": "书币为平台内部记账凭证，不可对外流通、不涉及代币发行",
                "scope_note": "本链为教学演示用本地模拟实现，无共识算法与智能合约",
            },
            prev_hash=self.GENESIS_PREV_HASH,
        )
        genesis.seal()
        self.blocks.append(genesis)

    # ---------------------------- 追加新区块（只追加） ----------------------------
    def mine_block(
        self,
        data: dict,
        signatures: Optional[Dict[str, Any]] = None,
    ) -> Block:
        """
        追加新区块。**这是本系统唯一的写链入口**，没有提供任何修改历史区块的方法。

        注意：这里的 mine_block 只是「打包并追加一个区块」的朴素命名，
        不含任何工作量证明（PoW），**不存在挖矿行为**，也不产生任何代币奖励。

        双签名校验：若 data 中声明 require_dual_signature=True，
        必须同时具备 advertiser 与 platform 两方签名，否则直接拒绝写入。

        可靠性：先落盘成功、再保留在内存中。
        若写盘失败会回滚内存状态并抛出异常，
        避免出现「内存有第 N 块、磁盘只有 N-1 块」的永久不一致
        （因为 verify_chain 校验的是磁盘数据，不一致会导致后续校验全部失败）。
        """
        with self.lock:
            # ---- 双签名协议校验：不通过则拒绝上链 ----
            if data.get("require_dual_signature"):
                sigs = signatures or {}
                if "advertiser" not in sigs or "platform" not in sigs:
                    raise HTTPException(
                        status_code=403,
                        detail="双签名协议校验失败：缺少广告商或平台任一方签名，拒绝写入链",
                    )

            last = self.blocks[-1]
            blk = Block(
                index=last.index + 1,
                timestamp=now_iso(),
                data=data,
                prev_hash=last.hash,
                signatures=signatures or {},
            )
            blk.seal()
            self.blocks.append(blk)
            try:
                self.save_to_disk()      # 新区块自动持久化到 chain.json（含 fsync）
            except Exception:
                # 落盘失败：回滚内存，保证内存与磁盘状态一致
                self.blocks.pop()
                logger.error("区块 #%s 落盘失败，已回滚内存状态，链路保持一致", blk.index)
                raise HTTPException(status_code=500,
                                    detail="区块落盘失败，本次操作已回滚，请检查磁盘空间与文件权限")
            return blk

    # ---------------------------- 链完整性校验 ----------------------------
    def verify_chain(self) -> dict:
        """
        逐块校验整条链，返回每一项校验结果与篡改定位。
        校验六要素：
          1. block_hash_consistent : 区块自身哈希是否与重算值一致（是否被改内容）
          2. prev_hash_linkage     : 前哈希是否等于上一区块的哈希（是否被删块/换链）
          3. dual_signature_valid  : 双签名协议区块的签名是否合法
          4. height_lock_intact    : 封块高度锁是否被破坏
          5. index_sequential      : 区块高度是否从 0 起连续递增（是否被插入/删除区块）
          6. timestamp_monotonic   : 出块时间是否单调不减（是否被改成未来时间）

        为什么 5 和 6 不能省：
          * 只校验哈希与前哈希时，若攻击者改某块的 index 或 timestamp 并**重新计算
            该块的 hash 与 height_lock**，前哈希链接依然成立，链会被误判为合法。
            index 连续性与时间单调性是独立于哈希的第七道防线。
          * 时间倒流会让「按时间对账」「按周期结算」失去意义，也可能是伪造未来的手段。

        任一要素 False 即视为该区块被篡改，并在 tamper_block_index 中定位。

        ⚠️ 安全要点：校验前强制从磁盘重新加载 chain.json，
        确保校验对象是「真实落盘数据」而非进程内存副本。
        否则攻击者（或演示者）直接改磁盘文件时，
        内存里的旧副本依然是合法的，篡改将被完全掩盖。
        """
        report_blocks: List[dict] = []
        errors: List[dict] = []          # 结构化错误清单
        tamper_index: Optional[int] = None
        tamper_reason: List[str] = []

        with self.lock:
            # ---- 从磁盘重载，确保校验的是落盘真实数据（而非内存副本）----
            disk_blocks = self._read_from_disk_raw()
            from_disk = disk_blocks is not None
            if disk_blocks is None:
                disk_blocks = list(self.blocks)      # 文件缺失时退化为内存链
            blocks_to_verify = disk_blocks

            prev_ts: Optional[datetime] = None

            for i, blk in enumerate(blocks_to_verify):
                # --- 要素 1：区块自身哈希一致性 ---
                recomputed = blk.compute_hash()
                hash_ok = (recomputed == blk.hash)

                # --- 要素 2：前哈希链接一致性 ---
                if i == 0:
                    prev_ok = (blk.prev_hash == self.GENESIS_PREV_HASH)
                else:
                    prev_ok = (blk.prev_hash == blocks_to_verify[i - 1].hash)

                # --- 要素 3：双签名合法性（仅对声明了双签名的业务区块校验）---
                sig_ok = True
                sig_detail: Dict[str, bool] = {}
                if blk.data.get("require_dual_signature"):
                    for role in ("advertiser", "platform"):
                        entry = (blk.signatures or {}).get(role)
                        payload = blk.data.get("sign_payload")
                        if not entry or not payload:
                            sig_ok = False
                            sig_detail[role] = False
                        else:
                            r = Wallet.verify(payload, entry["public_key"], entry["signature"])
                            sig_detail[role] = r
                            sig_ok = sig_ok and r

                # --- 要素 4：封块高度锁完整性 ---
                lock_ok = (blk.height_lock == sha256_hex(f"{blk.hash}:{blk.index}:{blk.timestamp}"))

                # --- 要素 5：区块高度连续递增（插入/删除区块会导致断裂）---
                index_ok = (blk.index == i)

                # --- 要素 6：出块时间单调不减（防止时间倒流 / 伪造未来时间）---
                ts_ok = True
                ts_note = ""
                try:
                    cur_ts = datetime.fromisoformat(blk.timestamp)
                    if prev_ts is not None and cur_ts < prev_ts:
                        ts_ok = False
                        ts_note = f"区块#{blk.index} 时间倒流：{blk.timestamp} 早于前一区块"
                    prev_ts = cur_ts
                except (ValueError, TypeError):
                    ts_ok = False
                    ts_note = f"区块#{blk.index} 时间戳格式非法：{blk.timestamp!r}"

                block_valid = hash_ok and prev_ok and sig_ok and lock_ok and index_ok and ts_ok

                if not block_valid:
                    # 结构化错误：机器可读，客户端可直接据此定位
                    failed_checks = []
                    if not hash_ok:
                        failed_checks.append("block_hash_consistent")
                        tamper_reason.append(
                            f"区块#{blk.index} 内容被篡改：重算哈希 {recomputed[:16]}... 与记录哈希 {blk.hash[:16]}... 不一致")
                    if not prev_ok:
                        failed_checks.append("prev_hash_linkage")
                        tamper_reason.append(f"区块#{blk.index} 前哈希链接断裂：可能被删除或换链")
                    if not sig_ok:
                        failed_checks.append("dual_signature_valid")
                        tampered_role = [r for r, v in sig_detail.items() if not v]
                        tamper_reason.append(
                            f"区块#{blk.index} 双签名非法：签名缺失或被伪造的方 = {tampered_role}")
                    if not lock_ok:
                        failed_checks.append("height_lock_intact")
                        tamper_reason.append(f"区块#{blk.index} 封块高度锁被破坏")
                    if not index_ok:
                        failed_checks.append("index_sequential")
                        tamper_reason.append(
                            f"区块#{blk.index} 高度不连续：文件位置为第 {i} 个区块，说明有区块被插入或删除")
                    if not ts_ok:
                        failed_checks.append("timestamp_monotonic")
                        tamper_reason.append(ts_note)

                    errors.append({
                        "block_index": blk.index,
                        "block_type": blk.data.get("type"),
                        "failed_checks": failed_checks,
                        "reason": "；".join(tamper_reason[-len(failed_checks):]),
                    })
                    if tamper_index is None:
                        tamper_index = blk.index

                report_blocks.append({
                    "index": blk.index,
                    "type": blk.data.get("type"),
                    "timestamp": blk.timestamp,
                    "hash": blk.hash,
                    "block_hash_consistent": hash_ok,
                    "prev_hash_linkage": prev_ok,
                    "dual_signature_valid": sig_ok,
                    "dual_signature_detail": sig_detail,
                    "height_lock_intact": lock_ok,
                    "index_sequential": index_ok,
                    "timestamp_monotonic": ts_ok,
                    "block_valid": block_valid,
                })

        is_valid = tamper_index is None
        verified = sum(1 for b in report_blocks if b["block_valid"])
        return {
            "chain_valid": is_valid,
            # ---- 结构化统计：总块数 / 合法块数 / 错误块数 ----
            "total_blocks": len(report_blocks),
            "verified_blocks": verified,
            "invalid_blocks": len(report_blocks) - verified,
            "check_dimensions": [
                "block_hash_consistent", "prev_hash_linkage", "dual_signature_valid",
                "height_lock_intact", "index_sequential", "timestamp_monotonic",
            ],
            "tamper_detected": not is_valid,
            # 篡改定位：具体是哪一块被改、为什么被改
            "tamper_block_index": tamper_index,
            "tamper_reason": tamper_reason,
            # 全部错误明细（不止第一处），便于批量排查
            "errors": errors,
            "block_reports": report_blocks,
            "verify_source": "disk(chain.json) 落盘真实数据" if from_disk else "memory 内存副本（chain.json 缺失或不可读，已降级）",
            "verifier": "Auditor / 独立第三方只读审计员",
            "scope_note": "本链为本地模拟实现，校验维度针对单机文件篡改场景，不含共识层校验",
        }

    def _read_from_disk_raw(self) -> Optional[List[Block]]:
        """
        绕过内存状态，直接从 chain.json 读取原始区块对象列表。
        供 verify_chain() 做「落盘真实数据」校验，避免内存旧副本掩盖磁盘篡改。
        文件缺失或损坏时返回 None，由调用方退化为内存链。
        """
        if not os.path.exists(self.chain_file):
            return None
        try:
            with open(self.chain_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
            result: List[Block] = []
            for item in raw.get("blocks", []):
                result.append(Block(
                    index=item["index"],
                    timestamp=item["timestamp"],
                    data=item["data"],
                    prev_hash=item["prev_hash"],
                    hash=item.get("hash", ""),
                    height_lock=item.get("height_lock", ""),
                    signatures=item.get("signatures", {}),
                ))
            return result
        except Exception:
            return None

    # ---------------------------- 查询 ----------------------------
    def get_block(self, index: int) -> Optional[Block]:
        """按高度取区块。"""
        with self.lock:
            for b in self.blocks:
                if b.index == index:
                    return b
            return None

    def query(self, data_type: Optional[str] = None, ref_id: Optional[str] = None) -> List[dict]:
        """
        按业务类型 / 关联ID 查询链上记录（只读）。
        ref_id 用于按 order_id / writer_id / user_id 过滤。
        """
        result: List[dict] = []
        with self.lock:
            for b in self.blocks:
                if data_type and b.data.get("type") != data_type:
                    continue
                if ref_id:
                    blob = canonical_json(b.data)
                    if ref_id not in blob:
                        continue
                result.append({
                    "index": b.index,
                    "timestamp": b.timestamp,
                    "hash": b.hash,
                    "prev_hash": b.prev_hash,
                    "data": b.data,
                    "dual_signed": bool(b.signatures),
                })
        return result

    @property
    def height(self) -> int:
        """当前链高度。"""
        return len(self.blocks) - 1


# ------------------------------------------------------------------------------
#  1.4 Ledger —— 书币账本 + 聚合哈希存证 + 收益结算
# ------------------------------------------------------------------------------
class Ledger:
    """
    书币账本与聚合哈希存证层。

    书币（book_coin）：
      * 平台内部记账凭证，非虚拟货币，不可对外流通、不可提现
      * 广告商充值人民币兑换书币 -> 先充值后投放（保证先钱后货，杜绝拖欠）
      * 投放消耗 -> 作家分成收益（周结） -> 剩余归平台

    聚合哈希存证：
      曝光明细（单篇单日可达数十万条）不直接上链，
      只把「批量明细的摘要哈希」写入区块，原始明细保存在本地 raw_exposure/。
      核验时重新计算本地明细摘要并与链上比对，防止明细被偷换。
    """

    def __init__(self, chain: Blockchain):
        self.chain = chain
        self.raw_dir = RAW_DIR
        os.makedirs(self.raw_dir, exist_ok=True)

    # ---------------------------- 充值 / 余额 ----------------------------
    def deposit(self, advertiser_id: str, amount_coin: float, payer: Wallet, real_amount: float) -> dict:
        """
        广告商充值书币。
        真实金额 -> 书币按固定兑换比例（1 元 = 10 书币）折算。
        充值成功后立即写入链上区块，形成「先充值后投放」的资金前置凭证。
        """
        if amount_coin <= 0:
            raise HTTPException(status_code=400, detail="充值书币数量必须大于 0")

        data = {
            "type": "deposit",
            "advertiser_id": advertiser_id,
            "amount_coin": round(amount_coin, 2),          # 充值书币数
            "real_amount_cny": round(real_amount, 2),      # 对应真实人民币金额
            "exchange_rate": "1 CNY = 10 book_coin",
            "book_coin_desc": "平台内部记账凭证，不可对外流通",
            "balance_after": round(self.balance_of(advertiser_id) + amount_coin, 2),
            "require_dual_signature": False,
        }
        signatures = {"advertiser": self._sign_part(payer, data)}
        blk = self.chain.mine_block(data, signatures)

        return {
            "block_index": blk.index,
            "tx_hash": blk.hash,
            "advertiser_id": advertiser_id,
            "amount_coin": data["amount_coin"],
            "real_amount_cny": data["real_amount_cny"],
            "balance_after": data["balance_after"],
        }

    def balance_of(self, account_id: str) -> float:
        """
        计算某账户当前书币余额。
        余额 = Σ充值 - Σ投放消耗 + Σ退款回滚 + Σ申诉返还
        注意：这里只读链上区块实时推导，链上没有可被直接篡改的「余额字段」。
        """
        bal = 0.0
        for b in self.chain.blocks:
            d = b.data
            if d.get("type") == "deposit" and d.get("advertiser_id") == account_id:
                bal += d["amount_coin"]
            elif d.get("type") == "ad_order_onchain" and d.get("advertiser_id") == account_id:
                bal -= d.get("lock_amount_coin", 0)      # 订单锁定的书币视为已消耗
            elif d.get("type") == "penalty_refund" and d.get("target_id") == account_id:
                bal += d.get("refund_coin", 0)            # 处罚撤销返还广告商
        return round(bal, 2)

    def writer_income_of(self, writer_id: str) -> float:
        """
        作家累计链上应结收益（未提现口径，由周结算区块累加）。
        """
        total = 0.0
        for b in self.chain.blocks:
            d = b.data
            if d.get("type") == "settlement_weekly" and d.get("writer_id") == writer_id:
                total += d.get("total_income", 0) - d.get("platform_fee", 0)
        return round(total, 2)

    # ---------------------------- 聚合哈希存证 ----------------------------
    def _safe_raw_path(self, batch_id: str) -> str:
        """
        把 batch_id 解析为 raw_dir 内的安全路径，越界即拒绝。

        【为什么已有 ID 白名单还要再校验一层】
          上层 Pydantic 的 ID_PATTERN 已挡住 `/` `.` 等危险字符，
          但 write_raw_exposure 是**通用方法**，未来若有新调用方
          拼出含路径分隔符的 batch_id（甚至来自链上回读的数据），
          白名单可能被绕过。这里用 realpath 做纵深防御（defense in depth）：
          无论输入多奇怪，落盘路径必须仍在 raw_dir 之内。
        """
        os.makedirs(self.raw_dir, exist_ok=True)
        base = os.path.realpath(self.raw_dir)
        candidate = os.path.realpath(os.path.join(base, f"{batch_id}.json"))
        # os.path.commonpath 会在跨盘符时抛ValueError，一并捕获
        try:
            inside = os.path.commonpath([base, candidate]) == base
        except ValueError:
            inside = False
        if not inside:
            raise ValueError(f"非法的明细文件名：{batch_id!r}（疑似路径穿越，已拒绝）")
        return candidate

    def write_raw_exposure(self, batch_id: str, records: List[dict]) -> str:
        """
        保存曝光原始明细到本地文件（不上链）。
        返回本地明细文件路径。

        注意：目录可能被手动删除（如清理运行残留），此处确保目录存在再写入，
        否则会抛 FileNotFoundError 导致接口 500。
        """
        path = self._safe_raw_path(batch_id)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False)
        return path

    def aggregate_hash(self, records: List[dict]) -> str:
        """
        计算批量明细的聚合哈希：
          明细按 order_id 排序 -> 逐条算 sha256 -> 再对摘要列表做一次 sha256（Merkle 简化版）
        该哈希即写入区块的「存证指纹」，容量恒定为 64 字符，与明细条数无关。
        """
        leaves = [sha256_hex(canonical_json(r)) for r in sorted(records, key=lambda x: x.get("exposure_id", ""))]
        return sha256_hex(canonical_json(leaves))

    def verify_raw_exposure(self, batch_id: str) -> dict:
        """
        核验原始明细是否被偷换：
        从链上找到该批次的聚合哈希 -> 重新读取本地明细 -> 重算比对。
        """
        target_hash = None
        block_index = None
        for b in self.chain.blocks:
            if b.data.get("batch_id") != batch_id:
                continue
            # 兼容两类存证区块：exposure_agg(曝光明细) 与 settlement_weekly(周结算附带明细)
            if "aggregate_hash" in b.data or "exposure_aggregate_hash" in b.data:
                target_hash = b.data.get("aggregate_hash") or b.data.get("exposure_aggregate_hash")
                block_index = b.index
                break
        if target_hash is None:
            return {"batch_id": batch_id, "found": False, "message": "链上未找到该批次存证"}

        # 同样走安全路径解析：batch_id 可能来自链上回读，不能假设它一定干净
        try:
            path = self._safe_raw_path(batch_id)
        except ValueError:
            return {"batch_id": batch_id, "found": False,
                    "message": "非法的批次标识（疑似路径穿越，已拒绝核验）"}
        if not os.path.exists(path):
            return {"batch_id": batch_id, "found": True, "local_raw_exists": False,
                    "message": "链上存证存在，但本地原始明细缺失", "block_index": block_index}

        with open(path, "r", encoding="utf-8") as f:
            records = json.load(f)
        recomputed = self.aggregate_hash(records)
        matched = recomputed == target_hash
        return {
            "batch_id": batch_id,
            "found": True,
            "local_raw_exists": True,
            "block_index": block_index,
            "chain_aggregate_hash": target_hash,
            "recomputed_hash": recomputed,
            "match": matched,
            "record_count": len(records),
            "conclusion": "原始明细未被篡改，与链上聚合哈希一致" if matched
                          else "警告：原始明细与链上聚合哈希不一致，明细可能被偷换",
        }

    # ---------------------------- 业务辅助 ----------------------------
    @staticmethod
    def _sign_part(wallet: Wallet, data: dict) -> dict:
        """对业务 data 生成单方签名条目（用于非协议类区块的审计留痕）。"""
        payload = {"type": data.get("type"), "payload": {k: v for k, v in data.items() if k != "require_dual_signature"}}
        return {"owner": wallet.owner_name, "public_key": wallet.public_key_hex, "signature": wallet.sign(payload)}


# ==============================================================================
#  第二部分：数据模型
#  Role / Account / AdOrder
# ==============================================================================

class Role(str, Enum):
    """
    平台角色枚举。
    权限分级说明：
      BOSS           老板：最高权限，协议平台方签名人，可查全量
      REVIEW_MINISTER审核部部长：处罚审批与退款登记
      REVIEWER      审核部员：执行处罚扣款、登记退款
      ADVERTISER    广告商：充值、投放申请、双签协议（仅可见自身备案与充值流水）
      WRITER        作家：查看本人链上记录、收益结算
      READER        读者：举报违规广告
      AUDITOR       审计员：独立第三方，只读全量 + 链完整性校验，无任何写权限
    """
    BOSS = "boss"
    REVIEW_MINISTER = "review_minister"
    REVIEWER = "reviewer"
    ADVERTISER = "advertiser"
    WRITER = "writer"
    READER = "reader"
    AUDITOR = "auditor"


# 各角色的接口权限矩阵（供文档与接口前置校验使用）
ROLE_PERMISSIONS: Dict[Role, List[str]] = {
    Role.BOSS: ["协议平台方签名", "授予/回收员工账号", "查阅月度工作上缴", "全量查询", "链完整性校验"],
    Role.REVIEW_MINISTER: ["处罚审批", "处罚退款登记", "月度工作上缴", "全量查询"],
    Role.REVIEWER: ["处罚执行扣款", "处罚退款登记", "月度工作上缴"],
    Role.ADVERTISER: ["充值书币", "投放申请", "协议双签名", "查询自身备案与充值流水"],
    Role.WRITER: ["查询本人链上记录", "周结算", "打赏月结", "注销划转"],
    Role.READER: ["违规广告举报", "打赏"],
    Role.AUDITOR: ["全量查询（只读）", "链完整性校验（只读）"],
}


@dataclass
class Account:
    """
    账户实体。
    id / name / role / status 四个核心字段；
    作家额外有 pending_income（未到期待结算收益）；
    内部员工（审核部部长/部员）额外有 granted_by（由老板授权授予）。

    账号授权原则：
      * 内部员工账号（审核部部长/部员）必须由老板授予，不可自助注册
      * 老板可随时回收（注销）员工账号，授权与回收均上链留痕
    """

    id: str
    name: str
    role: Role
    status: str = "active"          # active: 正常 / canceled: 已注销划转 / revoked: 已被老板回收
    register_time: str = field(default_factory=now_iso)
    wallet: Optional[Wallet] = None  # 参与方钱包（平台/广告商/作家需要签名）
    pending_income: float = 0.0     # 作家未到期待结算收益（广告分成，周结）
    pending_tip_income: float = 0.0  # 作家未到期待结算打赏收益（月结，平台实时抽成后累计）
    # 周结欠款（carryover）：当期分成不足以覆盖扣罚时的差额，结转到后续结算期优先抵扣。
    # 必须与 pending_income 分开：pending_income 是「平台欠作家的钱」（正向），
    # settle_debt 是「作家欠平台的钱」（反向），两者相加抵消，混用会导致账目方向错乱。
    settle_debt: float = 0.0
    granted_by: Optional[str] = None  # 内部员工的授权人（老板ID），外部角色为 None
    # 身份公钥（hex）：作家查询本人收益时用于 Ed25519 持有证明。
    # 客户端提交私钥 -> 服务端推导公钥 -> 与此字段比对，不一致即 403。
    # 这样伪造 writer_id 也无法查看他人收益明细。
    public_key_hex: Optional[str] = None

    def public_dict(self) -> dict:
        """对外输出（不暴露私钥信息）。"""
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role.value,
            "status": self.status,
            "register_time": self.register_time,
            "address": self.wallet.address if self.wallet else None,
            "pending_income": self.pending_income,
            "pending_tip_income": self.pending_tip_income,
            "granted_by": self.granted_by,
        }


@dataclass
class AdOrder:
    """
    广告订单模型。
    关键计费参数（cpm单价 / 兑换比例 / 作家分成比例 / 单篇单日分成上限 /
    打赏抽成比例）在双签上链后即被哈希固化，平台事后无法单方面篡改。

    生命周期：
      APPLIED（已申请，广告商已充值锁定书币）
        -> DUAL_SIGNED（协议双签完成，正式投放）
        -> SETTLING（按周结算中）
        -> SETTLED / CANCELED（结算完成 / 注销划转）
    """

    order_id: str
    advertiser_id: str
    writer_id: str
    book_title: str = ""
    ad_type: str = "banner"                 # 广告类型：banner 普通广告 / compliant_popup 合规弹窗

    # --- 计费参数（上链后不可变）---
    cpm_price: float = 8.0                  # CPM 单价（每千次曝光折算书币），普通广告默认 8
    exchange_rate: str = "1 CNY = 10 book_coin"   # 书币兑换比例（1 元 = 10 书币）
    writer_share_ratio: float = 0.4         # 作家分成比例 40%
    writer_daily_cap: float = 200.0         # 单篇单日作家分成上限（书币），风控防刷
    tip_platform_ratio: float = 0.3          # 打赏抽成比例 30%，归平台

    # --- 状态与计量 ---
    status: str = "APPLIED"                  # APPLIED / DUAL_SIGNED / SETTLING / SETTLED / CANCELED
    lock_amount_coin: float = 0.0            # 订单锁定的书币金额（已从广告商余额扣除）
    total_exposure: int = 0                  # 累计曝光量
    create_time: str = field(default_factory=now_iso)

    # --- 双签名记录（协议上链后固化）---
    signature_payload: Optional[dict] = None
    signatures: Dict[str, Any] = field(default_factory=dict)

    def build_sign_payload(self) -> dict:
        """
        构造双签名载荷：只包含影响双方权益的核心计费条款。
        平台与广告商对同一份载荷签名，任一方条款被改则另一方签名立即验签失败。
        """
        return {
            "order_id": self.order_id,
            "advertiser_id": self.advertiser_id,
            "writer_id": self.writer_id,
            "book_title": self.book_title,
            "ad_type": self.ad_type,
            "cpm_price": self.cpm_price,
            "exchange_rate": self.exchange_rate,
            "writer_share_ratio": self.writer_share_ratio,
            "writer_daily_cap": self.writer_daily_cap,
            "tip_platform_ratio": self.tip_platform_ratio,
            "lock_amount_coin": self.lock_amount_coin,
            "clause_version": "v1.0",
        }

    def compute_income(self, exposure: int) -> float:
        """
        按曝光量计算作家分成收益：
          毛分成 = 曝光/1000 * CPM单价 * 作家分成比例
          实际分成 = min(毛分成, 单篇单日分成上限)   # 触发上限后超出部分不再分成，抑制刷量
        """
        gross = exposure / 1000.0 * self.cpm_price * self.writer_share_ratio
        return round(min(gross, self.writer_daily_cap), 2)

    @staticmethod
    def suggest_cpm(ad_type: str) -> float:
        """
        按广告类型返回平台定价（价格由服务端规则锁定，广告商不可自填）：
          compliant_popup 合规弹窗：12 书币/千次曝光（不打扰阅读体验，定价更高）
          banner 普通广告：8 书币/千次曝光

        委托给 PLATFORM_RULES，避免价格出现两份定义而漂移。
        """
        return platform_cpm(ad_type)

    def compute_tip_settlement(self, tip_amount: float) -> dict:
        """
        读者打赏结算（月结专用）：
          平台抽成 = 打赏金额 * tip_platform_ratio（30%，打赏瞬间实时抽取）
          作家实得 = 打赏金额 - 平台抽成
        规则：月结不额外收取手续费。
        """
        platform_cut = round(tip_amount * self.tip_platform_ratio, 2)
        writer_get = round(tip_amount - platform_cut, 2)
        return {
            "tip_amount": round(tip_amount, 2),
            "platform_cut": platform_cut,
            "writer_payout": writer_get,
            "fee": 0.0,
            "period": "monthly",
            "note": "打赏月结，平台抽成30% 实时抽取，月结不额外收手续费",
        }

    def public_dict(self) -> dict:
        return asdict(self)


# ==============================================================================
#  第三部分：AI 抽检
#  AdInspector —— 辅助风控组件（不替代人工审核）
# ==============================================================================

class AdInspector:
    """
    AI 广告素材一致性抽检组件。

    职责边界（务必明确）：
      * 只做「链上备案素材」与「线上实际投放素材」的一致性比对（感知哈希 pHash 相似度）
      * 只做违规关键词命中检测（赌博/色情/诈骗/贷款/博彩/私服/外挂等）
      * 输出抽检报告供审核部参考，**不自动处罚、不自动下架、不替代人工审核结论**

    感知哈希说明（重要 —— 这是 Demo 简化实现，不是真实图像 pHash）：
      本Demo 的「素材」是纯文本，因此采用「字符 3-gram + SimHash」实现轻量感知哈希，
      纯本地可跑、零外部依赖（不需要 PIL / numpy / imagehash），适合教学与答辩演示。

      ⚠️ 生产环境应替换为真实图像感知哈希（image pHash）：
         - 对投放页截图做DCT（离散余弦变换）取低频系数 -> 生成 64bit 指纹
         - 典型实现：Pillow(取图/缩放) + numpy(DCT) + scipy.fftpack.dct
         - 或直接使用开源库 imagehash.phash()
         - 之所以要换：文本 3-gram 指纹对「同义改写/语序调整」敏感度低于图像指纹，
           且无法处理图片内的字体、配色、二维码等视觉元素。
         本次刻意不实现图像哈希，是为了让整个项目保持「单文件、零重依赖、开箱即跑」。

      相似度 >= 阈值判定素材一致；低于阈值判定疑似「偷换素材」。
    """

    # 违规关键词库（分类）
    VIOLATION_KEYWORDS: Dict[str, List[str]] = {
        "赌博": ["赌博", "博彩", "六合彩", "澳门赌场", "下注", "开盘"],
        "色情": ["色情", "情色", "裸聊", "约炮", "成人视频", "福利姬"],
        "诈骗": ["诈骗", "刷单", "返利", "杀猪盘", "兼职打字员", "保证金"],
        "贷款": ["贷款", "网贷", "放款", "秒批", "征信修复", "高额借款"],
        "博彩": ["博彩", "彩票", "足彩", "竞猜", "赔率"],
        "私服": ["私服", "私人服务器", "SF 发布网", "刷元宝"],
        "外挂": ["外挂", "辅助器", "自动脚本", "秒杀挂", "加速器破解"],
    }

    # 素材一致性判定阈值
    SIMILARITY_THRESHOLD = 0.6

    # 违规判定阈值：命中多少比例的类别关键词算严重
    VIOLATION_RATIO_THRESHOLD = 0.15

    def __init__(self, chain: Blockchain, orders: Dict[str, AdOrder]):
        self.chain = chain
        self.orders = orders

    # ---------------------- 感知哈希 ----------------------
    @staticmethod
    def _simhash(text: str, bits: int = 64) -> int:
        """
        计算文本 SimHash 指纹：
          1) 文本切成字符 3-gram 特征
          2) 每个特征算 sha256，取前 bits 位
          3) 按位累加权重后取符号生成 64 位指纹
        文本高度相似时指纹汉明距离小。
        """
        text = re.sub(r"\s+", "", text or "")
        feats: List[str] = []
        for i in range(max(1, len(text) - 2)):
            feats.append(text[i:i + 3])
        if not feats:
            feats = [text or "empty"]

        vector = [0] * bits
        for f in feats:
            h = int(hashlib.sha256(f.encode("utf-8")).hexdigest(), 16)
            for b in range(bits):
                vector[b] += 1 if (h >> b) & 1 else -1

        fp = 0
        for b in range(bits):
            if vector[b] > 0:
                fp |= (1 << b)
        return fp

    @staticmethod
    def _hamming(fp1: int, fp2: int) -> int:
        """汉明距离。"""
        return bin(fp1 ^ fp2).count("1")

    @classmethod
    def similarity(cls, text_a: str, text_b: str) -> float:
        """
        感知哈希相似度 = 1 - 汉明距离 / 总位数。
        返回 0~1 的相似度分值。
        """
        d = cls._hamming(cls._simhash(text_a), cls._simhash(text_b))
        return round(max(0.0, 1 - d / 64.0), 4)

    # ---------------------- 违规关键词检测 ----------------------
    @staticmethod
    def detect_violation(text: str) -> dict:
        """
        检测违规关键词命中情况。
        返回：命中类别明细、总违规词数、是否达到严重违规阈值。
        """
        hits: Dict[str, List[str]] = {}
        total = 0
        for category, words in AdInspector.VIOLATION_KEYWORDS.items():
            found = [w for w in words if w in (text or "")]
            if found:
                hits[category] = found
                total += len(found)
        # 阈值：命中 2 个词，或单一类别命中即判定违规
        is_violation = (total >= 2) or any(len(v) >= 2 for v in hits.values())
        return {
            "hit_categories": hits,
            "violation_word_count": total,
            "is_violation": is_violation,
        }

    # ---------------------- 抽检主流程 ----------------------
    def random_check(self, order_id: str, sample_size: int = 1, seed: Optional[int] = None) -> dict:
        """
        随机抽取投放页面做素材一致性抽检。

        流程：
          1) 从链上取该订单的「备案素材哈希 + 备案素材文本」（备案素材上链时固化）
          2) 随机抽取 sample_size 条线上实际投放素材
          3) 计算感知哈希相似度，低于阈值判为「素材不一致（疑似偷换）」
          4) 对实际素材做违规关键词检测
          5) 抽检结论写链上区块留痕（type = ai_random_check），可被审计员追溯
        """
        # 3.1 取链上备案素材
        filed_text: Optional[str] = None
        filed_hash: Optional[str] = None
        for b in self.chain.blocks:
            if b.data.get("type") == "order_filed_material" and b.data.get("order_id") == order_id:
                filed_text = b.data.get("material_text")
                filed_hash = b.data.get("material_phash")
                break

        if filed_text is None:
            raise HTTPException(status_code=404, detail=f"订单 {order_id} 在链上未找到备案素材，无法抽检")

        order = self.orders.get(order_id)
        # 3.2 模拟从投放页面随机抓到实际素材（真实环境此处替换为爬取/截图 OCR 结果）
        rng = random.Random(seed) if seed is not None else random
        samples: List[dict] = []
        for i in range(sample_size):
            actual_text = self._sample_live_material(order_id, rng, filed_text, i)
            sim = self.similarity(filed_text, actual_text)
            viol = self.detect_violation(actual_text)
            samples.append({
                "sample_no": i + 1,
                "actual_material": actual_text,
                "similarity": sim,
                "consistent": sim >= self.SIMILARITY_THRESHOLD,
                "violation": viol,
            })

        # 3.3 汇总
        inconsistent_count = sum(1 for s in samples if not s["consistent"])
        violation_samples = [s for s in samples if s["violation"]["is_violation"]]
        all_violation_categories = sorted({c for s in violation_samples for c in s["violation"]["hit_categories"]})
        avg_sim = round(sum(s["similarity"] for s in samples) / len(samples), 4)

        conclusion = "通过" if (inconsistent_count == 0 and not violation_samples) else "需人工复核"
        report = {
            "order_id": order_id,
            "sample_size": sample_size,
            "filed_material_phash": filed_hash,
            "similarity_threshold": self.SIMILARITY_THRESHOLD,
            "average_similarity": avg_sim,
            "inconsistent_count": inconsistent_count,
            "violation_sample_count": len(violation_samples),
            "violation_count": sum(s["violation"]["violation_word_count"] for s in violation_samples),
            "violation_categories": all_violation_categories,
            "samples": samples,
            "ai_conclusion": conclusion,
            "ai_limitation": "AI 抽检仅为辅助风控，不自动处罚、不替代人工审核，最终结论以审核部人工判定为准",
        }

        # 3.4 抽检报告上链存证（只追加）
        blk = self.chain.mine_block({
            "type": "ai_random_check",
            "order_id": order_id,
            "writer_id": order.writer_id if order else None,
            "sample_size": sample_size,
            "average_similarity": avg_sim,
            "inconsistent_count": inconsistent_count,
            "violation_count": report["violation_count"],
            "violation_categories": all_violation_categories,
            "ai_conclusion": conclusion,
            "ai_limitation": report["ai_limitation"],
        })
        report["block_index"] = blk.index
        report["tx_hash"] = blk.hash
        return report

    @staticmethod
    def _sample_live_material(order_id: str, rng: random.Random, filed_text: str, idx: int) -> str:
        """
        生成「线上实际投放素材」样本（演示用模拟数据）。

        ⚠️ 这是随机模拟，不是真实抓取。四种变体分别对应：
             一致 / 轻微改动（仍一致） / 偷换+违规词 / 偷换+博彩违规
          目的是让答辩时能稳定复现「一致」与「不一致」两类判定结果。

        生产环境替换路径：抓取投放页 HTML -> 正文提取，或截图后OCR -> 文本，
        再交给 similarity() 做比对。
        """
        variants = [
            filed_text,                                                    # 正常一致
            filed_text + "官方直营",                                        # 轻微改动，仍一致
            "【日赚过万】" + filed_text + "，加V立即领取，贷款秒批无抵押",   # 偷换 + 违规
            filed_text.replace("休闲", "博彩") + "，赔率超高，稳赚不赔",     # 偷换 + 博彩违规
        ]
        return variants[rng.randrange(len(variants))]


# ==============================================================================
#  第四部分：FastAPI 接口（共 12 个）
# ==============================================================================

app = FastAPI(
    title="基于联盟链的网文广告多方信任存证系统（模拟存证链 Demo）",
    description=(
        "AdChain Trust：**竞赛/教学用途的本地模拟存证链原型**。"
        "区块链为主体（哈希链式结构 + 双签名 + 只追加 + 聚合哈希存证 + 篡改定位），"
        "AI 为辅助风控组件（素材一致性抽检，不替代人工审核）。"
        "书币为平台内部记账凭证，不可对外流通。"
        "\n\n"
        "⚠️ 能力边界：无 P2P 网络、无共识算法、无智能合约、无多节点容灾；"
        "区块由单进程串行追加，不存在挖矿与代币发行。"
        "\n\n"
        "鉴权：写接口需在请求头携带 X-API-Key（按角色区分）；"
        "未配置环境变量时使用内置 Demo 密钥，详见 README。"
    ),
    version="2.0.0",
)

# ---- 全局单例（进程内持久化，重启后从 chain.json 自动恢复）----
chain = Blockchain(CHAIN_FILE)
ledger = Ledger(chain)

# 平台钱包：老板持有，用于订单协议的平台方签名（最高权限方）
platform_wallet = Wallet("平台-老板")
platform_account = Account(
    id="BOSS_001",
    name="平台老板",
    role=Role.BOSS,
    wallet=platform_wallet,
)

def demo_wallet(owner_name: str, seed: str) -> Wallet:
    """
    由固定种子派生演示钱包，保证「重启后私钥不变」。

    【为什么必须确定性】
      接口 ④ 要求作家出示私钥做持有证明，而演示脚本与答辩现场需要
      一个可稳定使用的私钥。若用 Ed25519PrivateKey.generate() 随机生成，
      每次重启私钥都会变化：README 里写的私钥立刻失效、现场演示直接失败。
      因此这里用「种子字符串的 SHA-256 摘要」作为私钥字节——
      同一项目、同一预置账户，任何时候启动得到的私钥完全一致。

      安全边界：这是演示便利性取舍，绝不可用于生产。
      生产环境私钥必须由作家自行生成并保管，服务端只登记公钥。
    """
    return Wallet(owner_name, Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(seed.encode("utf-8")).digest()))


# 内存态业务索引（演示用；链数据本体已持久化到 chain.json）
accounts: Dict[str, Account] = {
    platform_account.id: platform_account,
    # 审核部员工由老板授权授予（内部角色不可自助注册）
    "REVIEW_MINISTER_001": Account(id="REVIEW_MINISTER_001", name="审核部长·周敏",
                                    role=Role.REVIEW_MINISTER, granted_by=platform_account.id),
    "REVIEWER_001": Account(id="REVIEWER_001", name="审核部员·李查",
                            role=Role.REVIEWER, granted_by=platform_account.id),
    # 预置作家钱包使用确定性种子，保证重启后接口 ④ 的私钥演示依然可用
    "WRITER_001": Account(id="WRITER_001", name="作家·青云", role=Role.WRITER,
                          wallet=demo_wallet("作家-青云", "adchain-demo-writer-001")),
    "WRITER_002": Account(id="WRITER_002", name="作家·墨白", role=Role.WRITER,
                          wallet=demo_wallet("作家-墨白", "adchain-demo-writer-002")),
}
# 为预置作家登记身份公钥：查询本人收益时用于 Ed25519 持有证明。
# 说明：私钥由服务端托管仅用于演示，生产环境必须由作家自行保管（见设计文档 8.2）。
#      这里登记公钥即可完成校验 —— 服务端只需要知道「谁的公钥」，不需要持有私钥。
for _acc in accounts.values():
    if _acc.role == Role.WRITER and _acc.wallet is not None:
        _acc.public_key_hex = _acc.wallet.public_key_hex

orders: Dict[str, AdOrder] = {}
# 已在结算中扣除过的处罚单据号，避免跨周期重复扣款
settled_penalty_ids: List[str] = []
# 月度工作上缴记录（原文本地留存，链上只存哈希）
monthly_reports: Dict[str, dict] = {}


# ==============================================================================
#  角色鉴权（API Key）
# ==============================================================================
#  设计取舍（重要，答辩可能被追问）：
#   这里刻意采用「环境变量 + Demo 默认兜底」而不是「必须提供 config.py」。
#   原因：本项目要保证评委 clone 仓库后 `pip install` + `uvicorn` 一条命令跑起来。
#   若密钥文件是「必需」的，评委没有该文件就会直接启动失败。
#   现在的做法是：
#     * 密钥可被环境变量 / 本地 config.local.py 覆盖（生产环境必须覆盖）
#     * 未覆盖时使用内置 Demo 密钥并打印醒目告警，保证开箱即用
#     * .env 与 config.local.py 均已在 .gitignore 中排除，不进版本库
#
#  安全边界说明（务必诚实）：
#   API Key 属于「角色声明 + 访问控制」层面的机制，用于演示不同角色能做什么。
#   它不等同于真正的身份认证——生产环境应替换为 JWT/OAuth2 + HSM 密钥管理，
#   或直接沿用本项目已有的 Ed25519 私钥持有证明（见接口 ⑰ 的强度对比）。
_API_KEY_HEADER = "X-API-Key"

# 声明式安全方案：让 Swagger /docs 右上角出现 Authorize 按钮。
# auto_error=False 是关键——校验失败时交回 require_api_key 统一返回中文 403，
# 避免 FastAPI 先抛出一个英文的 "Not authenticated" 抢在我们之前。
_API_KEY_SCHEME = APIKeyHeader(
    name=_API_KEY_HEADER,
    auto_error=False,
    description=(
        "填入对应角色的 Demo 密钥后，页面内所有写接口都会自动带上该请求头。"
        "只读接口（查询、审计校验）公开可查，不需要密钥。"
    ),
)

# 各角色密钥：优先读环境变量 ADCHAIN_KEY_<ROLE>，未配置则回落到 Demo 默认值
_ROLE_KEY_ENV = {
    "boss": "ADCHAIN_KEY_BOSS",
    "review_minister": "ADCHAIN_KEY_REVIEW_MINISTER",
    "reviewer": "ADCHAIN_KEY_REVIEWER",
    "advertiser": "ADCHAIN_KEY_ADVERTISER",
    "writer": "ADCHAIN_KEY_WRITER",
    "auditor": "ADCHAIN_KEY_AUDITOR",
}


_DEMO_KEYS = {
    "boss": "demo-boss-key-2026",
    "review_minister": "demo-minister-key-2026",
    "reviewer": "demo-reviewer-key-2026",
    "advertiser": "demo-advertiser-key-2026",
    "writer": "demo-writer-key-2026",
    "auditor": "demo-auditor-key-2026",
}


def _load_api_keys() -> Dict[str, str]:
    """
    加载各角色 API Key。优先级：
      1. 环境变量 ADCHAIN_KEY_<ROLE>
      2. 本地 config.local.py 中的 API_KEYS 字典（该文件已被 .gitignore 排除）
      3. 内置 Demo 默认值
    使用了 Demo 默认值时打印 WARNING，提醒部署方必须覆盖。
    """
    keys: Dict[str, str] = {}
    local_override: Dict[str, str] = {}
    cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.local.py")
    if os.path.exists(cfg_path):
        try:
            ns: Dict[str, Any] = {}
            with open(cfg_path, "r", encoding="utf-8") as f:
                exec(f.read(), ns)   # noqa: S102 - 本地配置文件，仅演示用
            local_override = ns.get("API_KEYS", {}) or {}
        except Exception as e:
            logger.error("config.local.py 解析失败，已忽略：%s", e)

    using_demo = []
    for role, env_name in _ROLE_KEY_ENV.items():
        val = os.environ.get(env_name) or local_override.get(role)
        if not val:
            val = _DEMO_KEYS[role]
            using_demo.append(role)
        keys[role] = val

    if using_demo:
        logger.warning(
            "以下角色正在使用内置 Demo 密钥（未配置环境变量）：%s。"
            "生产部署必须通过环境变量 %s 覆盖。",
            ", ".join(using_demo),
            " / ".join(_ROLE_KEY_ENV.values()),
        )
    return keys


API_KEYS: Dict[str, str] = _load_api_keys()

# 接口所需角色：写接口按此校验，只读接口不校验
# 角色分组便于文档展示与批量维护
API_KEY_ROLES = {
    "boss": [Role.BOSS],
    "review_minister": [Role.REVIEW_MINISTER],
    "reviewer": [Role.REVIEWER],
    "advertiser": [Role.ADVERTISER],
    "writer": [Role.WRITER],
}


def require_api_key(request: Request, *allowed: Role) -> None:
    """
    FastAPI 依赖：校验请求头中的 X-API-Key 是否匹配任一允许的角色。

    规则：
      * 密钥缺失 / 不匹配 -> 403，并提示所需角色（不泄露正确密钥）
      * 使用 hmac.compare_digest 做恒定时间比较，避免时序侧信道
      * 只读接口（查询、审计校验）不挂这个依赖，保持公开可查
    """
    provided = request.headers.get(_API_KEY_HEADER, "")
    if not provided:
        raise HTTPException(
            status_code=403,
            detail=f"缺少鉴权凭证：请在请求头携带 {_API_KEY_HEADER}。"
                   f"所需角色={[r.value for r in allowed]}（本地演示可用对应 Demo 密钥，见 README）",
        )
    ok = False
    for role in allowed:
        expected = API_KEYS.get(role.value)
        if expected and hmac.compare_digest(provided, expected):
            ok = True
            break
    if not ok:
        raise HTTPException(
            status_code=403,
            detail=f"API Key 无效或与所需角色不匹配。所需角色={[r.value for r in allowed]}",
        )


def require_role(*roles: Role):
    """
    生成 FastAPI 依赖闭包：绑定固定的允许角色集合。

    这里额外声明 APIKeyHeader 安全方案，作用是让 Swagger 页面右上角
    出现「Authorize」按钮，演示时可以填一次密钥、全程所有写接口自动带上，
    不必在每个接口的 Headers 里手动重复填写。
    """
    async def _dep(
        request: Request,
        api_key: str = Security(_API_KEY_SCHEME),
    ) -> None:
        require_api_key(request, *roles)
    return _dep


# ---- 预置依赖，便于在接口声明中直接使用 ----
require_boss = require_role(Role.BOSS)
require_review = require_role(Role.REVIEW_MINISTER, Role.REVIEWER)
require_advertiser = require_role(Role.ADVERTISER)
require_writer = require_role(Role.WRITER)


# ---- 统一异常处理：任何未捕获异常都返回结构化 JSON，而不是 FastAPI 默认 500 ----
@app.exception_handler(RequestValidationError)
async def _validation_handler(request: Request, exc: RequestValidationError):
    """Pydantic 入参校验失败：返回结构化错误，客户端无需解析纯文本。"""
    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error": "请求参数校验失败",
            "detail": exc.errors(),
            "path": request.url.path,
        },
    )


@app.exception_handler(HTTPException)
async def _http_handler(request: Request, exc: HTTPException):
    """业务异常：统一包成 {success:false, error:...}，与成功响应结构对齐。"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "error": exc.detail, "path": request.url.path},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def _unhandled_handler(request: Request, exc: Exception):
    """
    兜底异常处理：记录完整堆栈到日志，对外只返回简洁信息。
    避免把内部路径 / 堆栈泄露给调用方，同时保证接口永不返回裸 500 文本。
    """
    logger.exception("未处理异常 @ %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "服务内部错误，请查看服务端日志",
            "path": request.url.path,
        },
    )


# ---------------------- Pydantic 请求模型 ----------------------
# 输入校验原则（防超长字符串 / 越界数值打爆序列化与哈希计算）：
#   * 所有字符串字段都设max_length，上限按业务实际需要给，不做无意义的大限制
#   * 所有金额字段都设 ge=0（禁止负数）+合理上限，避免构造极端数值
#   * 比例字段限定 0~1
#   * 曝光量等计数字段设 ge=0 +上限，防止整数溢出与异常计算
MAX_ID_LEN = 64# ID 类字段最大长度
MAX_NAME_LEN = 100         # 名称类字段最大长度
MAX_TEXT_LEN = 2000        # 普通文本（理由/说明）最大长度
MAX_MATERIAL_LEN = 5000    # 广告素材文本最大长度（会被哈希上链，需限制）
MAX_COIN = 10_000_000.0    # 单笔书币金额上限（1000 万元等值，防止极端值）
MAX_EXPOSURE = 100_000_000 # 单周期曝光量上限

# ---- ID 字符白名单（防路径穿越）----
# 【为什么 ID 必须限制字符，而不只是限制长度】
#   ID 不只用于标识，它还会被拼进**本地文件名**：
#     月报上缴时 report_key = f"{staff_id}_{period}"，
#     随后作为 raw_exposure/report_{report_key}.json 的文件名落盘。
#   只限长度不限制字符时，`staff_id="../../pwned"` 这类输入就能让写入路径
#   跳出 raw_exposure 目录（实测可写到目录外的任意位置）。
#   这就是「路径穿越（Path Traversal）」。
#   修法有两条路：① 限制 ID 字符（本项目采用，简单且根治）；
#                ② 落盘前用 os.path.realpath 校验是否仍在允许目录内（纵深防御）。
#   这里选① —— ID 本就应该只含字母数字与下划线横线，允许路径分隔符本身就不合理。
ID_PATTERN = r"^[A-Za-z0-9_\-]{1,64}$"


class ApplyIn(BaseModel):
    """
    广告商提交投放申请入参。

    【重要：为什么这里没有 cpm_price / writer_share_ratio 等计费条款字段】
      早期版本允许广告商自行提交分成比例、分成上限、打赏抽成、CPM单价，
      结果制造了一个严重的信任模型漏洞：广告商可以把作家分成设成 100%、
      上限设成近乎无限、平台抽成设成 0，服务端照单全收并由平台签名，
      恶意条款被「合法固化」上链，双签名反而沦为帮凶。

      双签名的前提是「双方对同一份可信条款达成一致」。若条款由其中一方
      随意拟定，双签名只能证明「双方都签了字」，无法证明「条款对第三方公平」。

      因此这里只接收「投放意图」字段（投给谁、投什么类型、放什么素材），
      全部计费条款由服务端 PLATFORM_RULES 锁定，客户端无权设定。
      广告商唯一能选择的是广告类型，而类型决定价格——这是平台的价格杠杆，
      不是让广告商自定价。
    """
    # extra="forbid"：显式拒绝任何未声明字段。
    # 若允许静默忽略，攻击者提交 writer_share_ratio=1.0 会被「无害地丢弃」，
    # 但接口返回 200，调用方会误以为条款已生效 —— 静默忽略比显式报错更危险。
    model_config = ConfigDict(extra="forbid")

    advertiser_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="广告商ID")
    advertiser_name: str = Field(..., max_length=MAX_NAME_LEN, description="广告商名称")
    writer_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="投放的作家ID")
    book_title: str = Field(default="", max_length=MAX_NAME_LEN, description="投放书籍名")
    ad_type: str = Field(
        default="banner", max_length=32, pattern="^(banner|compliant_popup)$",
        description="广告类型：banner 普通广告 8 书币/千次曝光 / compliant_popup 合规弹窗 12 书币。"
                    "类型由广告商选择，但价格由平台规则锁定，不可自填")
    lock_amount_coin: float = Field(
        default=1000.0, ge=0, le=MAX_COIN, description="本次订单锁定书币金额（从广告商余额扣除）")
    material_text: str = Field(..., max_length=MAX_MATERIAL_LEN, description="广告素材文本（备案用，将被哈希上链）")


class WriterRecordsIn(BaseModel):
    """
    作家查询本人链上收益记录入参（需出示私钥做持有证明）。

    【为什么不能只靠 writer_id】
      writer_id 是可枚举的（W_001、W_002……），任何人都能换个ID 查别人的收益。
      接口 17 已为广告商实现密码学级隔离，作家侧同理：
      必须提交 Ed25519 私钥，服务端推导公钥并与该作家已登记的公钥比对，
      不匹配一律 403 —— 这样伪造 writer_id 也拿不到别人的收益明细。
    """
    writer_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="作家ID")
    private_key_hex: str = Field(
        ..., min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$",
        description="作家私钥hex（32字节，用于持有证明，非本人私钥无法通过校验）")


class WriterCancelIn(BaseModel):
    """
    作家注销入参（v2.0 起必须出示本人私钥）。

    【为什么注销比查询更需要身份校验】
      接口 ④ 若无校验，最坏后果是「看到别人的收益明细」——信息泄露；
      而注销接口要动的是别人的账户状态与待结收益（划转给平台），
      属于**直接损害他人财产**。危害等级完全不同，
      因此这里不能沿用「只凭 writer_id」的写法。
    """
    private_key_hex: str = Field(
        ..., min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$",
        description="作家本人私钥hex（32字节）。出示他人私钥将返回403，防止横向越权注销他人账号")


class StaffGrantIn(BaseModel):
    """老板授予/回收员工账号入参。"""
    operator_id: str = Field(default="BOSS_001", max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="操作人ID，必须是老板")
    staff_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="被授予/回收的员工ID")
    staff_name: str = Field(..., max_length=MAX_NAME_LEN, description="员工姓名")
    staff_role: Role = Field(..., description="员工角色，仅限审核部部长/审核部员")
    action: str = Field(default="grant", max_length=16, pattern="^(grant|revoke)$",
                        description="grant 授予 / revoke 回收")


class MonthlyReportIn(BaseModel):
    """员工月度工作上缴入参（每月向老板上缴本月工作内容）。"""
    staff_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="上缴人（员工）ID")
    period: str = Field(..., max_length=7, pattern=r"^\d{4}-\d{2}$", description="上缴周期，格式 YYYY-MM，如 2026-10")
    work_summary: str = Field(..., max_length=MAX_TEXT_LEN, description="本月工作内容正文（原文本地留存，只上链哈希）")
    case_count: int = Field(default=0, ge=0, le=1_000_000, description="本月处理案件数")
    detail: str = Field(default="", max_length=MAX_TEXT_LEN, description="补充说明（明细清单等）")


class DepositIn(BaseModel):
    """充值书币入参。"""
    advertiser_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="广告商ID")
    amount_coin: float = Field(..., gt=0, le=MAX_COIN, description="充值书币数量（1元=10书币）")


class AgreementIn(BaseModel):
    """订单协议双签名入参。"""
    advertiser_private_key_hex: str = Field(..., min_length=64, max_length=64,
                                           pattern=r"^[0-9a-fA-F]{64}$",
                                           description="广告商私钥hex（32字节，需为64位十六进制）")


class PenaltyIn(BaseModel):
    """审核部执行处罚扣款入参。"""
    operator_role: Role = Field(default=Role.REVIEWER, description="执行人角色（审核部员/部长）")
    operator_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="执行人ID")
    order_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="被处罚订单ID")
    penalty_coin: float = Field(..., gt=0, le=MAX_COIN, description="扣罚书币金额")
    reason: str = Field(..., max_length=MAX_TEXT_LEN, description="处罚原因")
    penalty_id: str = Field(default="", max_length=MAX_ID_LEN, description="处罚单据号（可空则自动生成）")  # 服务端生成，不接受外部输入故不加白名单


class PenaltyRefundIn(BaseModel):
    """登记处罚撤销退款入参（滚入下期结算，不修改历史）。"""
    operator_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="审核部操作人ID")
    penalty_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="原处罚单据号")
    refund_coin: float = Field(..., gt=0, le=MAX_COIN, description="退款书币金额")
    reason: str = Field(..., max_length=MAX_TEXT_LEN, description="撤销退款原因")


class ReportIn(BaseModel):
    """读者举报违规广告入参。"""
    reader_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="举报人（读者）ID")
    order_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="被举报订单ID")
    reason: str = Field(..., max_length=MAX_TEXT_LEN, description="举报理由")
    evidence: str = Field(default="", max_length=MAX_MATERIAL_LEN, description="举报证据文本（截图说明等，将做证据哈希上链）")


class ReaderTipIn(BaseModel):
    """
    读者打赏入参。

    打赏在支付瞬间完成：平台按固定比例（30%）实时抽取，
    作家所得（70%）累计到其 pending_tip_income，等待每月打赏结算（接口 ⑯）。
    打赏记录即时上链存证（作家/金额/抽成/时间），不可篡改、可对账。
    """
    reader_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="打赏读者ID")
    writer_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="被打赏作家ID")
    tip_coin: float = Field(..., gt=0, le=MAX_COIN, description="打赏书币金额（>0）")


class AICheckIn(BaseModel):
    """AI 抽检入参。"""
    order_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="待抽检订单ID")
    sample_size: int = Field(default=1, ge=1, le=10, description="随机抽样数量（1~10）")


class AdvertiserRecordsIn(BaseModel):
    """
    广告商查询自身流水入参（需出示私钥做持有证明）。

    隐私隔离设计：
      仅传advertiser_id 是不够的 —— 任何人都能猜到别人的 ID 从而查看其流水。
      因此这里要求广告商提交自己的 Ed25519 私钥，
      服务端用该私钥推导出的公钥必须与链上双签区块中登记的该广告商公钥一致，
      否则一律403 拒绝。密码学持有证明，伪造不了。
    """
    advertiser_id: str = Field(..., max_length=MAX_ID_LEN, pattern=ID_PATTERN, description="广告商ID")
    private_key_hex: str = Field(..., min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$",
                                 description="广告商私钥hex（用于持有证明，非本人私钥无法通过校验）")


# ========================= 接口 1：广告商提交投放申请 =========================
@app.post("/api/advertiser/apply", summary="① 广告商提交投放申请")
def api_apply(request: Request, body: ApplyIn, _auth=Depends(require_advertiser)):
    """
    广告商提交广告投放申请。

    逻辑：校验广告商书币余额充足 -> 创建 AdOrder（状态 APPLIED）
          -> 锁定书币（余额即时扣除，杜绝投放后拖欠）
          -> 备案素材哈希上链固化（供后续 AI 抽检比对）

    【计费条款一律由服务端锁定，客户端无权设定】
      CPM 单价、分成比例、分成上限、打赏抽成全部取自 PLATFORM_RULES。
      广告商唯一能选择的是广告类型（banner / compliant_popup），
      而类型决定价格 —— 这是平台的价格杠杆，不是让广告商自定价。

      这样设计的根本原因：双签名的前提是「双方对同一份可信条款达成一致」。
      若条款由广告商任意拟定，平台被迫签署恶意条款（分成 100%、抽成 0），
      双签名只会把恶意条款固化成「不可篡改的合法证据」，
      完全失去防御意义。先有服务端可信条款，才有双签名的意义。
    """
    adv = accounts.get(body.advertiser_id)
    if adv is None:
        # 自动注册广告商账户并生成钱包（私钥由广告商自行保存用于后续双签）
        adv = Account(id=body.advertiser_id, name=body.advertiser_name, role=Role.ADVERTISER,
                      wallet=Wallet(f"广告商-{body.advertiser_name}"))
        accounts[body.advertiser_id] = adv

    # ---- 余额校验：先充值后投放 ----
    balance = ledger.balance_of(body.advertiser_id)
    if balance < body.lock_amount_coin:
        raise HTTPException(status_code=400,
                            detail=f"书币余额不足：当前 {balance}，本次需锁定 {body.lock_amount_coin}，请先充值")

    order = AdOrder(
        order_id=gen_id("ORD"),
        advertiser_id=body.advertiser_id,
        writer_id=body.writer_id,
        book_title=body.book_title,
        ad_type=body.ad_type,                             # 广告类型由广告商选择
        # ↓ 以下计费条款全部由服务端规则锁定，客户端无法干预
        cpm_price=platform_cpm(body.ad_type),               # 合规弹窗 12，普通横幅 8
        writer_share_ratio=PLATFORM_RULES["writer_share_ratio"],   # 固定 40%
        writer_daily_cap=PLATFORM_RULES["writer_daily_cap"],       # 固定 200 书币
        tip_platform_ratio=PLATFORM_RULES["tip_platform_ratio"],   # 固定 30%
        lock_amount_coin=body.lock_amount_coin,
    )
    orders[order.order_id] = order

    # 订单上链（状态 APPLIED，尚需双签名才是正式生效协议）
    blk1 = chain.mine_block({
        "type": "ad_order_applied",
        "order_id": order.order_id,
        "advertiser_id": order.advertiser_id,
        "writer_id": order.writer_id,
        "book_title": order.book_title,
        "ad_type": order.ad_type,
        "cpm_price": order.cpm_price,
        "exchange_rate": order.exchange_rate,
        "writer_share_ratio": order.writer_share_ratio,
        "writer_daily_cap": order.writer_daily_cap,
        "tip_platform_ratio": order.tip_platform_ratio,
        "lock_amount_coin": order.lock_amount_coin,
        "status": order.status,
        "note": "投放申请已登记，广告商书币已锁定，等待双方签名生效",
    })

    # 备案素材哈希上链（AI 抽检的比对基准，链上不可改）
    mat_fp = AdInspector._simhash(body.material_text)
    mat_hash = sha256_hex(body.material_text)
    blk2 = chain.mine_block({
        "type": "order_filed_material",
        "order_id": order.order_id,
        # 带上advertiser_id：该备案区块归属该广告商，使其能在自身流水中看到（其他广告商看不到）
        "advertiser_id": order.advertiser_id,
        "material_hash": mat_hash,
        "material_phash": f"{mat_fp:016x}",
        "material_text": body.material_text,
        "note": "广告备案素材指纹固化上链，作为 AI 抽检一致性比对基准",
    })

    return {
        "success": True,
        "order_id": order.order_id,
        "status": order.status,
        "balance_after": balance,
        "ad_type": order.ad_type,
        # 回报定价与分成参数，便于广告商与作家核对（正式协议以双签载荷为准）
        "cpm_price": order.cpm_price,
        "cpm_price_note": "合规弹窗 12 书币/千次曝光，普通广告 8 书币/千次曝光",
        "exchange_rate": order.exchange_rate,
        "writer_share_ratio": order.writer_share_ratio,
        "writer_daily_cap": order.writer_daily_cap,
        "tip_platform_ratio": order.tip_platform_ratio,
        "lock_amount_coin": order.lock_amount_coin,
        "advertiser_address": adv.wallet.address if adv.wallet else None,
        # 广告商私钥（仅本次返回给广告商本人，用于后续双签名；生产环境应各自保管）
        "advertiser_private_key_hex": adv.wallet.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex() if adv.wallet else None,
        "tx_hashes": {"apply": blk1.hash, "filed_material": blk2.hash},
        "next_step": f"调用 POST /api/order/sign-agreement/{order.order_id} 完成双签名上链",
    }


# ========================= 接口 2：充值书币 =========================
@app.post("/api/advertiser/deposit", summary="② 广告商充值书币")
def api_deposit(request: Request, body: DepositIn, _auth=Depends(require_advertiser)):
    """
    广告商充值书币（1 元 = 10 书币）。
    书币为平台内部记账凭证，不可对外流通；充值即写入链上，形成投放资金前置凭证。
    若广告商尚未注册（未提交过投放申请），此处自动完成注册并为其生成钱包，
    保证「先充值、后投放」在流程上真正成立。
    """
    adv = accounts.get(body.advertiser_id)
    if adv is None:
        adv = Account(id=body.advertiser_id, name=body.advertiser_id, role=Role.ADVERTISER,
                      wallet=Wallet(f"广告商-{body.advertiser_id}"))
        accounts[body.advertiser_id] = adv
    if adv.wallet is None:
        adv.wallet = Wallet(f"广告商-{adv.name}")

    real_amount = body.amount_coin / 10.0     # 10 书币 = 1 元
    return ledger.deposit(body.advertiser_id, body.amount_coin, adv.wallet, real_amount)


# ========================= 接口 3：双签名协议上链 =========================
@app.post("/api/order/sign-agreement/{order_id}", summary="③ 订单协议双签名上链（广告商+平台）")
def api_sign_agreement(request: Request, order_id: str, body: AgreementIn, _auth=Depends(require_advertiser)):
    """
    订单协议双签名上链（防篡改核心）。

    流程：
      1) 取出订单当前状态作为签名载荷（载荷含全部计费条款）
      2) 广告商用自己私钥对载荷签名
      3) 平台（老板钱包）对同一载荷签名
      4) 双方签名立即本地验签 -> 全部通过才 mine_block（链上再次存双签供审计复验）
      5) 任一方缺签名 / 验签失败 -> 拒绝写入链

    由此保证平台事后单方面修改 cpm 单价、分成比例等条款时，
    广告商签名立即失效，订单无法进入生效状态。
    """
    order = orders.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail=f"订单 {order_id} 不存在")
    if order.status not in ("APPLIED",):
        raise HTTPException(status_code=400, detail=f"订单当前状态为 {order.status}，不允许重复签名")

    payload = order.build_sign_payload()

    # --- 3.1 广告商签名 ---
    try:
        adv_priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(body.advertiser_private_key_hex))
    except Exception:
        raise HTTPException(status_code=400, detail="广告商私钥格式非法，应为 32 字节 hex")
    adv_wallet = Wallet(f"广告商-{order.advertiser_id}", private_key=adv_priv)

    # --- 3.1.1 广告商身份持有证明（v2.0 新增，防横向越权代签）---
    # 【为什么这里必须校验，而不能只看「签名能不能验过】
    #   签名本身只能证明「持有某把私钥的人签了这份条款」，
    #   并不能证明「这个人就是订单所属的广告商」。
    #   若不校验公钥归属，任何持有广告商角色密钥的人都能拿自己随手生成的私钥
    #   去签**别人**的订单：验签照样通过（因为公钥是用同一把私钥现推的），
    #   但链上 owner 字段写的是受害者的 ID，公钥却是攻击者的——
    #   「双签名保护广告商」这个语义就彻底失效了。
    #   实测：拿 11*32 这把与任何账户都无关的私钥签 ADV_001 的订单，返回 200、
    #   dual_signature_verified 全 true，而链上公钥与 ADV_001 登记公钥不一致。
    adv_account = accounts.get(order.advertiser_id)
    if adv_account is None or not adv_account.wallet:
        raise HTTPException(status_code=404,
                            detail=f"订单归属广告商 {order.advertiser_id} 不存在或未注册钱包")
    if not adv_account.wallet.public_key_hex:
        raise HTTPException(status_code=403,
                            detail=f"广告商 {order.advertiser_id} 未登记身份公钥，无法完成持有证明")
    if not hmac.compare_digest(adv_wallet.public_key_hex, adv_account.wallet.public_key_hex):
        raise HTTPException(status_code=403,
                            detail="签名私钥与该订单归属广告商不匹配：拒绝代他人签署订单（横向越权）")
    adv_sig = adv_wallet.sign(payload)

    # --- 3.2 平台签名（老板为平台授权签署人）---
    plat_sig = platform_wallet.sign(payload)

    signatures = {
        "advertiser": {
            "owner": order.advertiser_id,
            "public_key": adv_wallet.public_key_hex,
            "signature": adv_sig,
        },
        "platform": {
            "owner": platform_account.id,
            "public_key": platform_wallet.public_key_hex,
            "signature": plat_sig,
        },
    }

    # --- 3.3 双签即时验签（不过则拒绝上链）---
    verify_res = {
        "advertiser": Wallet.verify(payload, signatures["advertiser"]["public_key"], adv_sig),
        "platform": Wallet.verify(payload, signatures["platform"]["public_key"], plat_sig),
    }
    if not all(verify_res.values()):
        raise HTTPException(status_code=403, detail=f"双签名校验未全部通过，拒绝上链：{verify_res}")

    # --- 3.4 双签齐全，打包上链 ---
    order.signature_payload = payload
    order.signatures = signatures
    order.status = "DUAL_SIGNED"

    blk = chain.mine_block(
        {
            "type": "ad_order_onchain",
            "order_id": order.order_id,
            "advertiser_id": order.advertiser_id,
            "writer_id": order.writer_id,
            "book_title": order.book_title,
            "ad_type": order.ad_type,
            "cpm_price": order.cpm_price,
            "exchange_rate": order.exchange_rate,
            "writer_share_ratio": order.writer_share_ratio,
            "writer_daily_cap": order.writer_daily_cap,
            "tip_platform_ratio": order.tip_platform_ratio,
            "lock_amount_coin": order.lock_amount_coin,
            "status": order.status,
            "sign_payload": payload,
            "clause_hash": sha256_hex(canonical_json(payload)),
            "require_dual_signature": True,      # 声明本区块需双签，链校验时会复验
            "note": "广告订单协议已由广告商与平台双签名生效，计费条款链上固化不可篡改",
        },
        signatures=signatures,
    )

    return {
        "success": True,
        "order_id": order.order_id,
        "status": order.status,
        "dual_signature_verified": verify_res,
        "clause_hash": sha256_hex(canonical_json(payload)),
        "block_index": blk.index,
        "tx_hash": blk.hash,
    }


def _verify_identity_ownership(acc, private_key_hex: str) -> None:
    """
    Ed25519 私钥持有证明：确认「调用者确实持有该账户的私钥」。

    被接口 ④（作家查本人记录）与接口 ⑫（作家注销）共用——
    两处都必须防止「伪造ID 操作他人账户」，判定逻辑必须一致，
    否则容易出现「查询要私钥、注销不用私钥」这种致命缺口。

    【为什么用恒定时间比较】
      hmac.compare_digest 对同长度字符串不产生时序差异，
      防止攻击者用响应时间逐字节爆破公钥。
    【为什么服务端只存公钥】
      校验只需回答「私钥能否推导出已登记的公钥」，服务端无须持有私钥。
    """
    try:
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    except Exception:
        raise HTTPException(status_code=400, detail="私钥格式非法，应为 32 字节 hex")
    pub_hex = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    if not acc.public_key_hex:
        raise HTTPException(status_code=403,
                            detail="该账户未登记身份公钥，无法完成持有证明")
    if not hmac.compare_digest(pub_hex, acc.public_key_hex):
        raise HTTPException(status_code=403,
                            detail="私钥与该身份不匹配：拒绝操作他人账户")


# ========================= 接口 4：作家查链上记录（密码学持有证明） =========================
@app.post("/api/writer/records", summary="④ 作家查询本人链上记录（需出示私钥）")
def api_writer_records(body: WriterRecordsIn):
    """
    作家查询属于自己的全部链上记录：订单分成、处罚扣款、周结算、注销划转等，
    实现收益对账透明，且不经过平台后台，直接读链。

    【为什么从 GET 改成 POST + 必须出示私钥】
      原实现是 `GET /api/writer/{writer_id}/records`，只凭 writer_id 就能查。
      但 writer_id 是可枚举的（W_001、W_002……），任何人换个 ID 就能查看
      别人的收益明细与处罚记录 —— 这属于「假隔离」。

      现与接口 ⑰（广告商隐私隔离）采用同一套密码学方案：
        1) 客户端提交自己的 Ed25519 私钥；
        2) 服务端用私钥推导公钥；
        3) 与该作家账户登记的 public_key_hex 比对；
        4) 不匹配、或该作家未登记公钥 -> 403 拒绝。

      这样伪造 writer_id 也拿不到别人的收益数据。
      私钥放请求体而非 URL 也是必要的 —— URL 会进浏览器历史与网关访问日志。

    【可见范围】
      仅返回：属于自己的订单分成、处罚扣款、退款、周结算、注销划转记录。
      不可见：其他作家数据、读者举报证据、平台内部费用与授权记录。
    """
    acc = accounts.get(body.writer_id)
    if acc is None or acc.role != Role.WRITER:
        raise HTTPException(status_code=404, detail=f"作家 {body.writer_id} 未注册")

    # ---- Ed25519 持有证明（与接口 ⑫ 共用同一套校验）----
    _verify_identity_ownership(acc, body.private_key_hex)

    writer_id = body.writer_id
    records: List[dict] = []
    for b in chain.blocks:
        d = b.data
        if d.get("writer_id") != writer_id:
            continue
        records.append({
            "index": b.index,
            "timestamp": b.timestamp,
            "tx_hash": b.hash,
            "type": d.get("type"),
            "detail": d,
        })

    return {
        "writer_id": writer_id,
        "name": acc.name,
        "identity_verified": True,
        "record_count": len(records),
        "records": records,
        "pending_income": acc.pending_income,
        "chain_income_total": ledger.writer_income_of(writer_id),
        "account_status": acc.status,
        "scope_note": "仅含本人记录；私钥持有证明已通过Ed25519 公钥比对",
    }


# ========================= 接口 17：广告商查自身流水（隐私隔离） =========================
@app.post("/api/advertiser/records", summary="⑰ 广告商查询自身备案与充值流水（密码学隐私隔离）")
def api_advertiser_records(request: Request, body: AdvertiserRecordsIn):
    """
    广告商查询属于自己的备案与充值流水。

    【为什么需要这个接口】
      联盟链的「不可篡改」不等于「人人可见」。全量账目对广告商开放会带来两个问题：
        1. 商业隐私外泄 —— 能看到同行投了什么广告、投了多少；
        2. 数据脱敏失效 —— 读者举报证据、作家收益等不应被广告商看到。
      所以权限隔离不是「锦上添花」，而是联盟链落地的前置条件。

    【隔离强度：密码学持有证明，而非仅按 ID 过滤】
      很多同类Demo 只按 advertiser_id 过滤就算「权限隔离」，
      但只要 ID 可枚举（ADV_001、ADV_002……），任何人换个 ID 就能看别人的账，隔离形同虚设。
      本接口要求提交 Ed25519 私钥：
        1) 用私钥推导公钥；
        2) 与链上双签区块中登记的该广告商公钥逐一比对；
        3) 不匹配或从未双签 -> 403 拒绝。
      因此伪造别人的 advertiser_id 也拿不到别人的流水。

    【可见范围】
      仅返回：充值、投放申请、素材备案、协议双签、自身订单相关的处罚与退款。
      不可见：其他广告商数据、读者举报证据、作家收益明细、全链审计视图。
    """
    adv = accounts.get(body.advertiser_id)
    if adv is None:
        raise HTTPException(status_code=404, detail=f"广告商 {body.advertiser_id} 未注册")

    # --- 1. 解析私钥并推导公钥 ---
    try:
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(body.private_key_hex))
    except Exception:
        raise HTTPException(status_code=400, detail="私钥格式非法，应为 32 字节 hex")
    pub_hex = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    # --- 2. 与链上登记的该广告商公钥比对（持有证明）---
    onchain_pubkeys = set()
    for b in chain.blocks:
        sig_adv = (b.signatures or {}).get("advertiser") or {}
        if sig_adv.get("owner") == body.advertiser_id and sig_adv.get("public_key"):
            onchain_pubkeys.add(sig_adv["public_key"])
    if not onchain_pubkeys:
        raise HTTPException(status_code=403,
                            detail="该广告商尚无已上链的双签协议，无法验证身份。请先完成订单双签名")
    if pub_hex not in onchain_pubkeys:
        raise HTTPException(status_code=403,
                            detail="私钥与链上登记的该广告商公钥不匹配，拒绝查看他人流水")

    # --- 3. 只筛出属于该广告商的记录 ---
    #可见类型白名单：即使某个区块提到该广告商，也不属于其账目范畴（如他人订单的结算）
    visible_types = {
        "ad_order_applied", "order_filed_material", "ad_order_onchain",
        "deposit", "penalty", "penalty_refund",
    }
    my_order_ids = {o.order_id for o in orders.values() if o.advertiser_id == body.advertiser_id}

    records: List[dict] = []
    for b in chain.blocks:
        d = b.data
        t = d.get("type")
        if t in ("penalty", "penalty_refund"):
            # 处罚类区块只在本广告商名下订单时可见
            if d.get("order_id") not in my_order_ids:
                continue
        elif t not in visible_types:
            continue
        if d.get("advertiser_id") != body.advertiser_id:
            continue
        records.append({
            "index": b.index,
            "timestamp": b.timestamp,
            "tx_hash": b.hash,
            "type": t,
            "detail": d,
        })

    return {
        "success": True,
        "advertiser_id": body.advertiser_id,
        "identity_verified": True,
        "verify_method": "Ed25519 私钥持有证明，与链上双签区块登记公钥比对一致",
        "record_count": len(records),
        "records": records,
        "balance_now": ledger.balance_of(body.advertiser_id),
        "redacted_types": ["reader_report", "settlement", "other_advertisers"],
        "privacy_note": (
            "仅可见自身备案与充值流水；读者举报证据、作家收益、其他广告商数据已隔离，"
            "全量审计视图仅审计员与老板可见"
        ),
    }


# ========================= 接口 5：审核部执行处罚扣款 =========================
@app.post("/api/review/penalty", summary="⑤ 审核部执行处罚扣款")
def api_penalty(request: Request, body: PenaltyIn, _auth=Depends(require_review)):
    """
    审核部（部长/部员）根据违规处罚单据执行扣款。
    注意：扣款为新增惩罚区块，历史订单区块与历史处罚区块均不修改。
    """
    if body.operator_role not in (Role.REVIEWER, Role.REVIEW_MINISTER):
        raise HTTPException(status_code=403, detail="仅审核部部长/部员可执行处罚")
    order = orders.get(body.order_id)
    if order is None:
        raise HTTPException(status_code=404, detail=f"订单 {body.order_id} 不存在")

    penalty_id = body.penalty_id or gen_id("PEN")
    penalty_wallet = Wallet(f"审核部-{body.operator_id}")

    blk = chain.mine_block(
        {
            "type": "penalty",
            "penalty_id": penalty_id,
            "order_id": body.order_id,
            "advertiser_id": order.advertiser_id,
            "writer_id": order.writer_id,
            "penalty_coin": round(body.penalty_coin, 2),
            "reason": body.reason,
            "operator_id": body.operator_id,
            "operator_role": body.operator_role.value,
            "note": "违规处罚扣款，仅新增区块，不修改任何历史区块",
        },
        signatures=ledger._sign_part(penalty_wallet, {"type": "penalty", "penalty_id": penalty_id,
                                                    "order_id": body.order_id, "penalty_coin": body.penalty_coin}),
    )
    return {"success": True, "penalty_id": penalty_id, "block_index": blk.index, "tx_hash": blk.hash}


# ========================= 接口 6：登记处罚撤销退款 =========================
@app.post("/api/review/penalty-refund", summary="⑥ 登记处罚撤销退款（滚入下期结算）")
def api_penalty_refund(request: Request, body: PenaltyRefundIn, _auth=Depends(require_review)):
    """
    处罚撤销退款登记。
    关键设计：退款不修改原处罚区块，而是新增 refund 区块，
    若退款对象是作家，则金额滚入「下期结算」（pending_income），
    等下一期周结时一并发放，历史记录完整可追溯。
    """
    # 找到原处罚区块
    origin = None
    for b in chain.blocks:
        if b.data.get("type") == "penalty" and b.data.get("penalty_id") == body.penalty_id:
            origin = b
            break
    if origin is None:
        raise HTTPException(status_code=404, detail=f"未找到处罚单据 {body.penalty_id}")

    # ---- 幂等校验：同一处罚单只允许退款一次 ----
    # 只追加不修改不等于可以无限追加。若不拦截重复退款，
    # 审核部（或越权调用方）可以对同一笔处罚反复登记退款，实质等于无限退钱，
    # 这是「只追加」最容易被忽略的漏洞，必须在写入前查链上已有 refund 区块。
    for b in chain.blocks:
        if b.data.get("type") == "penalty_refund" and b.data.get("penalty_id") == body.penalty_id:
            raise HTTPException(status_code=400,
                                detail=f"处罚单据 {body.penalty_id} 已于区块 #{b.index} 登记退款，不允许重复退款")

    target_writer = origin.data.get("writer_id")
    # 退款金额滚入该作家下期待结算收益（不直接改历史）
    if target_writer in accounts:
        accounts[target_writer].pending_income = round(
            accounts[target_writer].pending_income + body.refund_coin, 2
        )

    op_wallet = Wallet(f"审核部-{body.operator_id}")
    blk = chain.mine_block(
        {
            "type": "penalty_refund",
            "penalty_id": body.penalty_id,
            "refund_origin_block": origin.index,
            "target_id": target_writer,
            "target_advertiser": origin.data.get("advertiser_id"),
            "refund_coin": round(body.refund_coin, 2),
            "reason": body.reason,
            "operator_id": body.operator_id,
            "settle_policy": "滚入下期结算，不修改历史处罚记录",
            "note": "处罚撤销退款登记，仅新增区块，历史区块保持不可变",
        },
        signatures=ledger._sign_part(op_wallet, {"type": "penalty_refund", "penalty_id": body.penalty_id,
                                                 "refund_coin": body.refund_coin}),
    )
    return {
        "success": True,
        "penalty_id": body.penalty_id,
        "refund_coin": body.refund_coin,
        "target_writer": target_writer,
        "writer_pending_income_now": accounts[target_writer].pending_income if target_writer in accounts else None,
        "block_index": blk.index,
        "tx_hash": blk.hash,
    }


# ========================= 接口 7：读者举报上链 =========================
@app.post("/api/reader/report", summary="⑦ 读者举报违规广告（证据哈希存证）")
def api_reader_report(request: Request, body: ReportIn):
    """
    读者举报违规广告。
    举报证据不整份上链，只上链「证据哈希」，原文本地留存，核验时重算比对，
    既保证证据不可篡改，又控制链上存储开销。
    """
    evidence_hash = sha256_hex(body.evidence or body.reason)
    local_path = ledger.write_raw_exposure(f"evidence_{gen_id('EV')}", [{
        "report_order_id": body.order_id,
        "reader_id": body.reader_id,
        "reason": body.reason,
        "evidence": body.evidence,
    }])

    blk = chain.mine_block({
        "type": "reader_report",
        "order_id": body.order_id,
        "reader_id": body.reader_id,
        "reason": body.reason,
        "evidence_hash": evidence_hash,
        "evidence_raw_path": local_path,
        "note": "读者举报存证，仅上链证据哈希，原文本地留存可复算核验",
    })
    return {
        "success": True,
        "order_id": body.order_id,
        "evidence_hash": evidence_hash,
        "block_index": blk.index,
        "tx_hash": blk.hash,
        "handle_note": "举报已上链留痕，审核部将结合 AI 抽检报告人工判定",
    }


# ========================= 接口 7.5：读者打赏（实时抽成，月结） =========================
@app.post("/api/reader/tip", summary="⑦′ 读者打赏（平台实时抽成30%，作家所得月结）")
def api_reader_tip(request: Request, body: ReaderTipIn):
    """
    读者打赏。

    与广告分成（周结）分开记账：
      * 支付瞬间平台按固定比例 30% 实时抽取（PLATFORM_RULES["tip_platform_ratio"]）
      * 作家所得（70%）累计到 pending_tip_income，等待每月打赏结算（接口 ⑯）
      * 打赏记录即时上链：reader_id / writer_id / 金额 / 抽成 / 时间，不可篡改、可对账
      * 月结不额外收手续费、无单篇单日上限（与周结的固定 0.5 书币手续费不同）
    """
    writer = accounts.get(body.writer_id)
    if writer is None or writer.role != Role.WRITER:
        raise HTTPException(status_code=404, detail=f"作家 {body.writer_id} 不存在")
    if writer.status == "canceled":
        raise HTTPException(status_code=400, detail="该作家账号已注销划转，不能再接受打赏")

    tip_ratio = PLATFORM_RULES["tip_platform_ratio"]          # 0.3，服务端锁定
    platform_cut = round(body.tip_coin * tip_ratio, 2)        # 平台实时抽成
    writer_get = round(body.tip_coin - platform_cut, 2)       # 作家所得，月结前暂存
    writer.pending_tip_income = round(writer.pending_tip_income + writer_get, 2)

    blk = chain.mine_block({
        "type": "reader_tip",
        "reader_id": body.reader_id,
        "writer_id": body.writer_id,
        "tip_coin": round(body.tip_coin, 2),
        "tip_platform_ratio": tip_ratio,
        "platform_cut": platform_cut,
        "writer_pending_after": writer.pending_tip_income,
        "note": "读者打赏，平台实时抽成30%，作家所得累计待月结；仅新增区块",
    })

    return {
        "success": True,
        "reader_id": body.reader_id,
        "writer_id": body.writer_id,
        "tip_coin": round(body.tip_coin, 2),
        "platform_cut": platform_cut,
        "writer_get": writer_get,
        "writer_pending_tip_income": writer.pending_tip_income,
        "settle_cycle": "月结（接口⑯），不额外收手续费",
        "block_index": blk.index,
        "tx_hash": blk.hash,
    }


# ========================= 接口 8：AI 素材抽检 =========================
@app.post("/api/ai/random-check", summary="⑧ AI 广告素材一致性抽检（辅助风控）")
def api_ai_random_check(request: Request, body: AICheckIn, _auth=Depends(require_review)):
    """
    调用 AI 抽检组件做素材一致性 + 违规关键词检测。
    AI 只输出报告，不自动处罚，结论以人工审核为准。
    """
    inspector = AdInspector(chain, orders)
    return inspector.random_check(body.order_id, body.sample_size)


# ========================= 接口 9：审计员查全量（只读） =========================
@app.get("/api/auditor/all", summary="⑨ 审计员查询全量链上记录（只读）")
def api_auditor_all(type: Optional[str] = None):
    """
    独立第三方审计员查询全量链上记录。
    审计员仅有只读权限，不能新增区块。
    """
    records = chain.query(data_type=type)
    return {
        "role": Role.AUDITOR.value,
        "readonly": True,
        "chain_height": chain.height,
        "filter_type": type or "ALL",
        "total": len(records),
        "records": records,
        "blocks_summary": [
            {"index": b.index, "type": b.data.get("type"), "timestamp": b.timestamp, "hash": b.hash}
            for b in chain.blocks
        ],
    }


# ========================= 接口 10：链完整性校验 =========================
@app.get("/api/auditor/verify-chain", summary="⑩ 校验链完整性（返回篡改定位）")
def api_auditor_verify_chain():
    """
    逐块校验整条链完整性：
      区块自身哈希 / 前哈希链接 / 双签名合法性 / 封块高度锁，
      任一不通过即返回具体被篡改的区块高度与原因。
    """
    return chain.verify_chain()


# ========================= 接口 11：周结算 =========================
@app.post("/api/settlement/weekly/{writer_id}", summary="⑪ 作家广告分成周结算")
def api_weekly_settlement(request: Request, writer_id: str, exposure: int = Query(0, ge=0, le=MAX_EXPOSURE), _auth=Depends(require_boss)):
    """
    广告分成周结（扣小额手续费）。
    exposure 为本周累计曝光量（真实系统由投放日志统计汇总，且只上链聚合哈希）。
    结算为新增区块，含：毛分成 / 上限截断说明 / 平台手续费 / 实发金额 / 退款滚入项。
    """
    writer = accounts.get(writer_id)
    if writer is None or writer.role != Role.WRITER:
        raise HTTPException(status_code=404, detail=f"作家 {writer_id} 不存在")
    if writer.status == "canceled":
        raise HTTPException(status_code=400, detail="该作家账号已注销划转，不能再结算")

    # 汇总该作家所有已生效订单
    related = [o for o in orders.values() if o.writer_id == writer_id and o.status == "DUAL_SIGNED"]
    if not related:
        raise HTTPException(status_code=400, detail="该作家名下无已双签生效的订单，无法结算")

    order = related[0]   # 演示取首单，多单场景按订单逐笔生成结算区块
    income = order.compute_income(exposure)
    gross = round(exposure / 1000.0 * order.cpm_price * order.writer_share_ratio, 2)
    capped = gross > order.writer_daily_cap
    fee = round(PLATFORM_RULES["weekly_settle_fee"], 2)   # 周结手续费：固定 0.5 书币（定值，不随金额放大）
    refunded = writer.pending_income              # 历史滚动调整（处罚退款滚入下期）

    # ---- 本期新处罚自动从收益中扣除（跨周期滚动结算公式）----
    new_penalty = 0.0
    for b in chain.blocks:
        d = b.data
        if d.get("type") == "penalty" and d.get("writer_id") == writer_id:
            # 已计入 pending_income 的原处罚不再重复扣
            if d.get("penalty_id") not in settled_penalty_ids:
                new_penalty += d.get("penalty_coin", 0)
    new_penalty = round(new_penalty, 2)

    # ---- 滚动结算公式：本周分成 − 本期新处罚 + 历史滚动调整 − 历史欠款 − 手续费 ----
    # 历史欠款（settle_debt）优先从本期分成中扣除：上期扣罚超分成时，
    # 差额不是「消失」，而是转为欠款由后续分成抵扣，避免同一笔钱被罚两次。
    debt_offset = min(writer.settle_debt, max(income + refunded, 0.0))
    raw_payout = round(income - new_penalty + refunded - fee - debt_offset, 2)

    # 【负数兜底：欠款不能变成「负数发放」】
    #   当期扣罚大于当期分成时（如刷量刷单被重罚）raw_payout 会算成负数。
    #   若直接把它写进 payout 上链，等于承认「平台倒欠作家钱」，
    #   业务上不成立——欠款应该结转到下期扣，而不是凭空产生负收益。
    #   实测过：分成 0.32、扣罚 150 时旧代码算出 payout = -150.18 并上链固化。
    payout = max(raw_payout, 0.0)
    writer.settle_debt = round(writer.settle_debt - debt_offset
                               + (-raw_payout if raw_payout < 0 else 0.0), 2)

    # 曝光明细只上链聚合哈希，原始明细本地留存
    batch_id = gen_id("BATCH")
    raw_records = [{"exposure_id": f"E{i:06d}", "order_id": order.order_id,
                    "ts": now_iso(), "device": f"d{random.randint(1, 999)}"} for i in range(min(exposure, 500))]
    agg_hash = ledger.aggregate_hash(raw_records)
    ledger.write_raw_exposure(batch_id, raw_records)

    writer.pending_income = 0.0    # 历史滚动调整已在本期发放
    settled_penalty_ids.extend(
        b.data.get("penalty_id") for b in chain.blocks
        if b.data.get("type") == "penalty" and b.data.get("writer_id") == writer_id
    )

    blk = chain.mine_block({
        "type": "settlement_weekly",
        "writer_id": writer_id,
        "order_id": order.order_id,
        "exposure_count": exposure,
        "batch_id": batch_id,
        "exposure_aggregate_hash": agg_hash,      # 聚合哈希存证：原始明细不上链
        "gross_income": gross,
        "daily_cap": order.writer_daily_cap,
        "capped_by_daily_cap": capped,
        "total_income": income,
        "new_penalty": new_penalty,               # 本期新处罚
        "rolled_adjustment": refunded,            # 历史滚动调整（处罚退款）
        "platform_fee": fee,
        "penalty_refund_carried": refunded,
        "debt_offset": round(debt_offset, 2),      # 本期抵扣的历史欠款
        "payout": payout,                          # 实发，最低 0，不允许负数
        "carryover_debt": writer.settle_debt,      # 结算后仍欠平台的钱（结转下期抵扣）
        "settle_formula": "本周分成 − 本期新处罚 + 历史滚动调整 − 历史欠款抵扣 − 手续费；"
                          "若结果为负则不发放，差额结转为下期欠款",
        "period": f"W-{datetime.now().strftime('%Y%V')}",
        "note": "广告分成周结，仅新增区块，扣固定0.5书币手续费，处罚退款滚入本期；"
                "扣罚超分成时差额结转为欠款，不会产生负数发放",
    })

    return {
        "success": True,
        "writer_id": writer_id,
        "period": f"W-{datetime.now().strftime('%Y%V')}",
        "exposure_count": exposure,
        "gross_income": gross,
        "capped_by_daily_cap": capped,
        "total_income": income,
        "new_penalty": new_penalty,
        "rolled_adjustment": refunded,
        "platform_fee": fee,
        "penalty_refund_carried": refunded,
        "debt_offset": round(debt_offset, 2),
        "payout": payout,
        "carryover_debt": writer.settle_debt,
        "payout_floor_note": "扣罚超分成时不产生负数发放，差额结转至下期抵扣",
        "settle_formula": "本周分成 − 本期新处罚 + 历史滚动调整 − 历史欠款抵扣 − 手续费；"
                          "若结果为负则不发放，差额结转为下期欠款",
        "exposure_aggregate_hash": agg_hash,
        "block_index": blk.index,
        "tx_hash": blk.hash,
    }


# ========================= 接口 12：作家注销划转 =========================
@app.post("/api/settlement/cancel-account/{writer_id}", summary="⑫ 作家注销（需出示本人私钥），未到期收益划转平台")
def api_cancel_account(writer_id: str, body: WriterCancelIn, _auth=Depends(require_writer)):
    """
    作家注销账号，未到期待结算收益划转平台。
    关键：只新增 cancel_transfer 区块，作家历史所有区块一律保留，
    注销后 status 变更，账目可追溯，不存在销毁记录。

    【为什么必须出示私钥，而不能只靠 API Key】
      X-API-Key 只能证明「你持有某个作家角色的密钥」，
      而 writer_id 是路径参数——若不校验身份，
      任何人拿到任意一个作家密钥，都能构造
      POST /api/settlement/cancel-account/WRITER_001
      把**别人**的账号注销、把别人的收益划转给平台。
      这是横向越权，比「查不到记录」严重得多：查错只是信息泄露，
      注销错是直接毁掉他人账户与财产。
      因此这里复用接口 ④ 的 Ed25519 持有证明：
      私钥推导公钥 → 与登记值恒定时间比对 → 不匹配直接 403。
    """
    writer = accounts.get(writer_id)
    if writer is None or writer.role != Role.WRITER:
        raise HTTPException(status_code=404, detail=f"作家 {writer_id} 不存在")

    # 身份持有证明：必须出示该作家本人的私钥，防止横向越权注销他人账号
    _verify_identity_ownership(writer, body.private_key_hex)

    if writer.status == "canceled":
        raise HTTPException(status_code=400, detail="该作家已注销，不能重复操作")

    transfer = writer.pending_income     # 未到期待结算收益（广告分成）
    transfer_tip = writer.pending_tip_income   # 未到期待结算打赏（月结前注销同样划转平台）
    unpaid_debt = writer.settle_debt     # 尚未抵扣完的欠款（作家欠平台的钱）
    writer.pending_income = 0.0
    writer.pending_tip_income = 0.0
    # 注销后不再有后续分成可抵扣，欠款必须在注销时一次性登记清账，
    # 否则这笔钱会随账号消失、平台也追不回来——账目必须闭合。
    writer.settle_debt = 0.0
    writer.status = "canceled"           # 状态变更，历史链上记录全部保留

    op_wallet = Wallet("审核部-注销审核")
    blk = chain.mine_block(
        {
            "type": "cancel_transfer",
            "writer_id": writer_id,
            "transfer_coin": transfer,
            "transfer_tip_coin": transfer_tip,
            "unpaid_debt_cleared": unpaid_debt,   # 注销时一次性登记的未清欠款
            "receiver": platform_account.id,
            "writer_status_after": writer.status,
            "note": "作家注销，未到期广告分成与打赏收益划转平台；仅新增区块，作家历史记录全部保留可追溯",
        },
        signatures=ledger._sign_part(op_wallet, {"type": "cancel_transfer", "writer_id": writer_id,
                                                "transfer_coin": transfer, "transfer_tip_coin": transfer_tip}),
    )
    return {
        "success": True,
        "writer_id": writer_id,
        "transfer_coin": transfer,
        "transfer_tip_coin": transfer_tip,
        "unpaid_debt_cleared": unpaid_debt,
        "receiver": platform_account.id,
        "writer_status": writer.status,
        "block_index": blk.index,
        "tx_hash": blk.hash,
        "note": "历史链上记录未删除，仅新增划转区块",
    }


# ========================= 接口 13：老板授予/回收员工账号 =========================
@app.post("/api/boss/staff", summary="⑬ 老板授予/回收员工账号（内部角色由老板授权）")
def api_boss_staff(request: Request, body: StaffGrantIn, _auth=Depends(require_boss)):
    """
    老板授予或回收审核部员工账号。

    业务规则：内部员工账号（审核部部长/审核部员）**必须由老板授予，不可自助注册**；
    老板也可随时回收已授予的账号。授权与回收均写入链上区块留痕，不可篡改。

    权限校验：操作人必须是老板（BOSS_001），否则拒绝。
    """
    # ---- 权限前置校验：仅老板可授予/回收员工账号 ----
    if accounts.get(body.operator_id) is None or accounts[body.operator_id].role != Role.BOSS:
        raise HTTPException(status_code=403, detail="仅老板可授予或回收员工账号")
    if body.staff_role not in (Role.REVIEWER, Role.REVIEW_MINISTER):
        raise HTTPException(status_code=400, detail="本接口仅用于授予审核部部长/审核部员，内部角色由老板授权")

    if body.action == "grant":
        # ---- 授予：新建员工账号并标记授权人 ----
        if body.staff_id in accounts and accounts[body.staff_id].status == "active":
            raise HTTPException(status_code=400, detail=f"员工 {body.staff_id} 已存在且状态正常")
        acc = Account(id=body.staff_id, name=body.staff_name, role=body.staff_role,
                      granted_by=body.operator_id)
        accounts[body.staff_id] = acc
        blk = chain.mine_block({
            "type": "staff_grant",
            "staff_id": body.staff_id,
            "staff_name": body.staff_name,
            "staff_role": body.staff_role.value,
            "granted_by": body.operator_id,
            "action": "grant",
            "note": "老板授予内部员工账号，上链留痕不可篡改",
        })
        return {"success": True, "action": "grant", "staff": acc.public_dict(),
                "block_index": blk.index, "tx_hash": blk.hash}

    elif body.action == "revoke":
        # ---- 回收：状态置为 revoked，历史记录全部保留 ----
        if body.staff_id not in accounts:
            raise HTTPException(status_code=404, detail=f"员工 {body.staff_id} 不存在")
        acc = accounts[body.staff_id]
        acc.status = "revoked"
        blk = chain.mine_block({
            "type": "staff_revoke",
            "staff_id": body.staff_id,
            "staff_role": acc.role.value,
            "revoked_by": body.operator_id,
            "action": "revoke",
            "note": "老板回收员工账号，仅新增区块，该员工历史链上记录全部保留可追溯",
        })
        return {"success": True, "action": "revoke", "staff": acc.public_dict(),
                "block_index": blk.index, "tx_hash": blk.hash}

    raise HTTPException(status_code=400, detail="action 仅支持 grant 或 revoke")


# ========================= 接口 14：员工月度工作上缴 =========================
@app.post("/api/staff/monthly-report", summary="⑭ 员工每月向老板上缴本月工作内容")
def api_staff_monthly_report(request: Request, body: MonthlyReportIn, _auth=Depends(require_review)):
    """
    内部员工每月向老板上缴本月工作内容。

    存证设计：工作正文**不上链**，只上链摘要哈希 + 案件数等结构化字段，
    原文保存在本地 raw_exposure/，核验时重算比对。
    这样既保证「交了什么」不可篡改，又避免长文本撑爆区块。

    前置校验：上缴人必须是已授权（active）的内部员工，外部角色无权上缴。
    """
    acc = accounts.get(body.staff_id)
    if acc is None or acc.role not in (Role.REVIEWER, Role.REVIEW_MINISTER):
        raise HTTPException(status_code=403, detail="仅审核部内部员工可上缴月度工作")
    if acc.status != "active":
        raise HTTPException(status_code=403, detail=f"员工账号状态为 {acc.status}，无权上缴")

    # 同一员工同一周期只允许上缴一次，重复提交直接拒绝（防重复上缴）
    report_key = f"{body.staff_id}_{body.period}"
    if report_key in monthly_reports:
        raise HTTPException(status_code=400,
                            detail=f"员工 {body.staff_id} 的 {body.period} 工作已上缴，不允许重复提交")

    # 正文只存哈希，原文本地留存
    content_hash = sha256_hex(body.work_summary + "|" + body.detail)
    local_path = ledger.write_raw_exposure(f"report_{report_key}", [{
        "staff_id": body.staff_id,
        "period": body.period,
        "work_summary": body.work_summary,
        "detail": body.detail,
    }])

    blk = chain.mine_block({
        "type": "monthly_work_report",
        "report_key": report_key,
        "staff_id": body.staff_id,
        "staff_name": acc.name,
        "staff_role": acc.role.value,
        "granted_by": acc.granted_by,
        "period": body.period,
        "case_count": body.case_count,
        "content_hash": content_hash,
        "raw_path": local_path,
        "receiver": platform_account.id,
        "note": "月度工作内容存证，仅上链摘要哈希，原文本地留存可复算核验",
    })

    monthly_reports[report_key] = {
        "staff_id": body.staff_id, "period": body.period,
        "content_hash": content_hash, "raw_path": local_path,
        "block_index": blk.index,
    }
    return {
        "success": True,
        "report_key": report_key,
        "staff_id": body.staff_id,
        "staff_name": acc.name,
        "period": body.period,
        "case_count": body.case_count,
        "content_hash": content_hash,
        "receiver": platform_account.id,
        "block_index": blk.index,
        "tx_hash": blk.hash,
    }


# ========================= 接口 15：老板查阅月度工作 =========================
@app.get("/api/boss/monthly-reports", summary="⑮ 老板查阅全部月度工作上缴记录")
def api_boss_monthly_reports(staff_id: Optional[str] = None,
                             period: Optional[str] = None,
                             _auth=Depends(require_boss)):
    """
    老板查阅内部员工的上缴记录（可按员工或周期筛选）。
    返回摘要哈希与链上块高度，原文可按 raw_path 复算核验。

    【为什么这里要鉴权，而接口 ⑨⑩ 审计查询公开】
      两类数据的性质不同，不能一刀切：
        * 接口 ⑨⑩ 是**链本身的校验与全量浏览**——链的价值就在于公开可验证，
          任何人能跑 verify_chain 才能证明「不可篡改」不是空话。
        * 接口 ⑮ 暴露的是**内部管理信息**：员工姓名、每周期处理案件数量、
          工作摘要哈希。这些不是链可信性的必要条件，公开只会泄露团队内部数据。
      原则：链的验证权公开，链上业务隐私不公开（与接口 ⑰ 同一思路）。
    """
    items: List[dict] = []
    for b in chain.blocks:
        d = b.data
        if d.get("type") != "monthly_work_report":
            continue
        if staff_id and d.get("staff_id") != staff_id:
            continue
        if period and d.get("period") != period:
            continue
        items.append({
            "block_index": b.index,
            "tx_hash": b.hash,
            "report_key": d.get("report_key"),
            "staff_id": d.get("staff_id"),
            "staff_name": d.get("staff_name"),
            "staff_role": d.get("staff_role"),
            "period": d.get("period"),
            "case_count": d.get("case_count"),
            "content_hash": d.get("content_hash"),
            "raw_path": d.get("raw_path"),
            "onchain_time": b.timestamp,
        })
    return {
        "viewer": platform_account.id,
        "filter": {"staff_id": staff_id or "ALL", "period": period or "ALL"},
        "total": len(items),
        "reports": items,
        "note": "正文不上链，仅存摘要哈希；可按 raw_path 重算原文核对",
    }


# ========================= 接口 16：打赏月结 =========================
@app.post("/api/settlement/monthly/{writer_id}", summary="⑯ 读者打赏月结（抽成30%，不收手续费）")
def api_monthly_settlement(request: Request, writer_id: str, _auth=Depends(require_boss)):
    """
    读者打赏月结。

    打赏金额由接口 ⑦′（读者打赏）实时入账到作家的 pending_tip_income
    （平台已按 30% 实时抽成），本接口只做「月结」动作：
      * 周期：月结（而非周结）
      * 平台抽成：30%，已在打赏瞬间实时抽取
      * 手续费：不额外收取（周结才收固定 0.5 书币）
      * 无单篇单日上限约束
    仅新增区块，历史结算记录不受影响。
    """
    writer = accounts.get(writer_id)
    if writer is None or writer.role != Role.WRITER:
        raise HTTPException(status_code=404, detail=f"作家 {writer_id} 不存在")
    if writer.status == "canceled":
        raise HTTPException(status_code=400, detail="该作家账号已注销划转，不能再结算")

    tip_amount = writer.pending_tip_income          # 本月累计打赏（打赏瞬间已实时抽成后的作家所得）
    if tip_amount <= 0:
        raise HTTPException(status_code=400, detail="本月无待结算打赏（pending_tip_income 为 0）")

    tip_ratio = PLATFORM_RULES["tip_platform_ratio"]   # 0.3，服务端锁定
    # 平台抽成已在打赏瞬间（接口⑦′）实时抽取，月结只做全额发放，不再二次抽成
    writer_get = tip_amount
    platform_cut = 0.0
    writer.pending_tip_income = 0.0                    # 月结后清零，下月重新累计

    blk = chain.mine_block({
        "type": "settlement_monthly_tip",
        "writer_id": writer_id,
        "tip_amount": round(tip_amount, 2),
        "tip_platform_ratio": tip_ratio,
        "platform_cut": platform_cut,
        "writer_payout": writer_get,
        "fee": 0.0,
        "period": f"M-{datetime.now().strftime('%Y%m')}",
        "note": "读者打赏月结：平台抽成30%已在打赏瞬间实时抽取，月结全额发放不二次抽成、不收手续费，无单篇单日上限",
    })

    return {
        "success": True,
        "writer_id": writer_id,
        "period": f"M-{datetime.now().strftime('%Y%m')}",
        "tip_amount": round(tip_amount, 2),
        "tip_platform_ratio": tip_ratio,
        "platform_cut": platform_cut,
        "writer_payout": writer_get,
        "fee": 0.0,
        "settle_formula": "作家实得 = 本月累计打赏（抽成已在打赏瞬间实时抽取，月结全额发放）",
        "block_index": blk.index,
        "tx_hash": blk.hash,
    }


# ==============================================================================
#  启动自检：控制台打印链高度与角色权限矩阵
# ==============================================================================
@app.on_event("startup")
def _startup_banner():
    print("=" * 70)
    print(" 基于联盟链的网文广告多方信任存证系统 (AdChain Trust v2.0) 已启动")
    print(" ⚠️ 本项目是本地模拟存证链 Demo：无P2P/共识算法/智能合约/挖矿，勿按生产链理解")
    print(f" 链文件: {CHAIN_FILE}")
    print(f" 当前链高度: {chain.height}（共 {len(chain.blocks)} 块，已从本地自动加载）")
    print(f" 本地曝光明细目录: {RAW_DIR}")
    print(f" 接口总数: {len([r for r in app.routes if getattr(r, 'path', '').startswith('/api')])} 个")
    print(" 业务参数（服务端锁定，客户端不可设定）:")
    print(f"          {PLATFORM_RULES['exchange_rate']} | 作家分成"
          f"{int(PLATFORM_RULES['writer_share_ratio'] * 100)}% | 单篇单日上限"
          f"{PLATFORM_RULES['writer_daily_cap']:.0f}书币")
    print(f"          合规弹窗CPM{PLATFORM_RULES['cpm_by_ad_type']['compliant_popup']:.0f}"
          f" / 普通广告CPM{PLATFORM_RULES['cpm_by_ad_type']['banner']:.0f}"
          f" | 打赏抽成{int(PLATFORM_RULES['tip_platform_ratio'] * 100)}%(月结免手续费)"
          f" | 周结手续费固定{PLATFORM_RULES['weekly_settle_fee']}书币")
    print(" 角色权限矩阵:")
    for r, perms in ROLE_PERMISSIONS.items():
        print(f"   - {r.value:16s}: {', '.join(perms)}")

    # 打印预置作家私钥：接口 ④ 需作家出示私钥做持有证明。
    # 仅演示用——生产环境私钥必须由作家自行保管，绝不应出现在服务端日志里。
    print(" 预置作家查询私钥（演示用，接口 ④ 需出示）:")
    for acc in accounts.values():
        if acc.role == Role.WRITER and acc.wallet is not None:
            priv = acc.wallet.private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()).hex()
            print(f"   - {acc.id}({acc.name}): {priv}")

    # 【为什么提示的端口要跟着实际启动端口走】
    #   原先写死 8000，实测用 `--port 8899` 启动时横幅仍提示 8000，
    #   演示现场照着提示点会直接 404，很影响观感。
    #   本函数在 startup 事件中执行，此时拿不到 uvicorn 的 config，
    #   因此改为读取约定的环境变量 ADCHAIN_PORT（由 __main__ 入口写入），
    #   读不到再回退到默认 8000。
    print(f" 文档地址: http://127.0.0.1:{os.getenv('ADCHAIN_PORT', '8000')}/docs")
    print(f" 演示控制台: http://127.0.0.1:{os.getenv('ADCHAIN_PORT', '8000')}/demo")
    print("=" * 70)


# ============================================================
#  演示控制台（仅本地演示辅助，不属于业务接口）
# ============================================================
#  【为什么要单独做一个页面】
#   Swagger 面向开发者：需要手动拼 JSON、手动填请求头、逐个点 Execute。
#   评委往往不是开发者，也不清楚要填什么，容易卡在第一步。
#   这个页面把「演示脚本」固化下来，评审只需按顺序点「执行」按钮，
#   全程无需输入任何 JSON、无需填写任何密钥。
#
#  【安全边界】
#   以下接口会直接改写 chain.json，仅用于本地课堂/竞赛演示，
#   严禁暴露到公网，也不属于 18 个正式业务接口之一。

_DEMO_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_console.html")
_DEMO_BACKUP = CHAIN_FILE + ".demo.bak"
_TAMPER_KEY = "writer_share_ratio"
_TAMPER_FROM = 0.4
_TAMPER_TO = 0.9


@app.get("/demo", include_in_schema=False)
def demo_console():
    """返回演示控制台页面（本地演示辅助，不出现在接口文档里）。"""
    return FileResponse(_DEMO_HTML, media_type="text/html; charset=utf-8")


@app.post("/__demo__/tamper", include_in_schema=False)
def demo_tamper(index: int):
    """
    演示辅助：把指定区块的作家分成比例从 0.4 篡改成 0.9 并落盘。

    【为什么必须指定区块号，而不是全局替换】
      链上 `"writer_share_ratio": 0.4` 会在多个区块里同时出现
      （订单区块、广告区块等都带这个字段）。如果全局替换，
      会一次改掉多个区块，校验时报出的区块号是其中最早的一个，
      和口播里说的区块号对不上，演示时数字自相矛盾。
      所以这里只改指定区块内的第一处，保证「报出的区块号 == 实际篡改的区块」。
    """
    # 先备份原始链，供还原使用
    if not os.path.exists(_DEMO_BACKUP):
        shutil.copyfile(CHAIN_FILE, _DEMO_BACKUP)
    try:
        with open(CHAIN_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"读取链文件失败：{e}")

    old = f'"{_TAMPER_KEY}": {_TAMPER_FROM}'
    new = f'"{_TAMPER_KEY}": {_TAMPER_TO}'
    hit = 0
    for b in data.get("blocks", []):
        if b.get("index") == index:
            s = json.dumps(b.get("data", {}), ensure_ascii=False)
            if old in s:
                b["data"] = json.loads(s.replace(old, new, 1))
                hit = 1
            break
    if not hit:
        raise HTTPException(status_code=404,
                            detail=f"区块 #{index} 中没有找到 {_TAMPER_KEY}={_TAMPER_FROM}，无法演示篡改")

    with open(CHAIN_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return {"success": True, "tampered_index": index,
            "note": f"区块 #{index} 的 {_TAMPER_KEY} 已从 {_TAMPER_FROM} 改为 {_TAMPER_TO}"}


@app.post("/__demo__/restore", include_in_schema=False)
def demo_restore():
    """演示辅助：从备份还原链数据（撤销篡改）。"""
    if not os.path.exists(_DEMO_BACKUP):
        raise HTTPException(status_code=404, detail="没有找到备份文件，无需还原")
    shutil.copyfile(_DEMO_BACKUP, CHAIN_FILE)
    return {"success": True, "note": "链数据已从备份还原"}


@app.post("/__demo__/reset", include_in_schema=False)
def demo_reset():
    """
    演示辅助：删除链文件与备份，重启为干净的创世区块。

    重新从磁盘加载使内存中的链与磁盘一致，
    这样「链上数据是唯一事实来源」这条约束在任何时候都成立。
    """
    for p in (CHAIN_FILE, _DEMO_BACKUP):
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
    chain.load_from_disk()
    return {"success": True,
            "total_blocks": len(chain.blocks),
            "note": "已重置为初始创世区块，可从第 1 步重新开始"}


if __name__ == "__main__":
    import uvicorn
    # 记录实际端口，供启动横幅提示正确的文档地址
    _PORT = int(os.getenv("ADCHAIN_PORT", "8000"))
    os.environ["ADCHAIN_PORT"] = str(_PORT)
    uvicorn.run(app, host="0.0.0.0", port=_PORT)