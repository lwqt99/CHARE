# 输出字段和统计口径

每个结果目录独占创建，不覆盖之前运行。`config.json` 是解析后的有效配置；`parameters.txt` 是本次实际使用的公共参数字节。`manifest.json` 包含 schema、时间、运行状态、参数 SHA、实际位长、编码长度、环境与 Go build info。环境只读取明确白名单，不导出整份环境变量。

`implementation_version`、实际测量层的 `protocol_version` 常量与 `protocol_profile` 记录实现配置，不能代替源码身份。`source_manifest.json` 覆盖实际运行目录中的 Go 源码、模块校验、配置与说明文件哈希，明确记录完整/部分/不可用状态。`functional_validation` 明确区分实现一致性检查与理论安全证明。

v0.2.0 起 source_manifest 也覆盖 vendor 中的 Go/C 绑定、头文件及许可证；外部已安装 native 库不是该源码目录的一部分。`transport_profile` 明确额外缓存实验的范围。所有 `transport_*` 行均按 TRANSPORT.md 解释，不能将本地恢复大小再收费为网络发送，也不能只取热包而忽略签名条目及全员安装。

v0.3.0 的 `DH-explicit-list` 包含独立生命周期。`CHARE-auth` 替代旧版 `shared-auth`，明确费用属于 CHARE；缓存存储按双方分别记录。新操作和客户端获取口径见 BASELINE_LIFECYCLE.md。新旧结果不应混合为同一个测量序列；manifest 版本和实际源码哈希均需保留。合成名单输入、完整传输、缓存传输及功能压力检查分别取数，不从全表无差别求和推导部署总费用。


v0.4.0 增加 `workload_schedule=synthetic-active-only-slot-major-v1`，`revocations` 现在要求不同资格实际发生1→0。每个案例的 `workload_evidence` 保存逐次真实安装/发布和完成计数，失败案例也保留已执行部分。成功汇总与Python读取均检查事件。此前版本的拒绝记录更新次数不自动代表有效撤销次数，不能跨版本合并样本。详见 WORKLOAD.md。

## raw.csv

v0.4.1 重验目录根证书、离线追赶清单及独立冷审计的根证书/清单签名。原行名和撤销调度不变，但这些操作的实际范围增加；旧版样本不能混为同一序列。完整主负载汇总见 ACCOUNTING.md；它核对原始 CSV 与逐案例测量/检查的一致性，并以固定次数清单拒绝漏项和重复计费。

v0.5.0 新增 CHARE `sender_snapshot_acquisition`，每个主策略在初始与更新后各一次。快照升为 v2，包含原始记录及完整公开发送者输入；大小变化按实际序列化记录。新行不嵌套在 `prepare_policy` 内。获取与策略操作不混入初始化/撤销两阶段；`sender_acquisitions.csv` 单独提供逐行账本，见 SENDER.md。

一行是 `internal/bench.RunCase` 返回的一条实际测量，字段为：

| 字段 | 含义 |
|---|---|
| `run_id`, `case_id` | 唯一运行及案例标识 |
| `capacity`, `attributes`, `replicate` | 本次容量、属性维数及从 1 开始的重复编号 |
| `revocations`, `acquisitions` | 本例请求的工作负载次数 |
| `scheme`, `operation`, `mode` | 实际方案、阶段与冷热/工作模式；由协议测量层给出 |
| `duration_ns` | 本行操作范围的实测纳秒，不包含 Go 编译或曲线参数准备 |
| `bytes` | 测量层报告的实际字节数，范围由 `operation/detail` 指定 |
| `source_ops`, `pairings` | 测量层记录的源群操作和配对次数；不是墙钟时间估计 |
| `count` | 本行包含的操作次数；不擅自当作独立统计样本数 |
| `detail` | 测量层给出的范围与限制 |

零值原样保留。`detail` 含 `no timing sample` 的字节/存储观测没有计时，其原始 `duration_ns=0` 是占位，不是实测零延迟；不得画成 0 ms。调用者不能仅从零字节或零操作数推断不存在未实现的费用；应结合操作标签和本次实现范围。不同单位不加成一个“总分”。

## checks.csv 与 cases

`checks.csv` 保存 `case_id,name,passed,detail`。`cases/<id>/result.json` 保存原始 `bench.Result`，包括 `measurements` 和 `checks`；`checks.json` 单独保存检查数组。`status.json` 记录配置、开始/结束、通过/失败/跳过、错误。

检查失败、返回错误、panic、没有返回任何检查、负数测量字段，都会使案例失败。Panic 恢复不涵盖 native 库进程崩溃。没有测量的检查案例不产生性能样本。失败案例的已有测量仍在 raw 中，但不进入 summary。预检查/参数错误会留下运行级失败记录，但无法产生未执行案例的测量。

## summary.csv

只纳入通过案例，按容量、属性维数、撤销次数、获取次数、方案、操作和模式分组。`sample_count` 是进入该组的原始测量行数，**不是** `count` 的总和。若同一案例在同组返回多行，这些行都保留为行样本，不能未经确认视为独立试验。

`duration_sample_count` 仅计入不带 `no timing sample` 标记的行。没有计时样本时该列为 0，所有耗时统计单元格留空。耗时均值、中位数、最小、最大及最近秩 p95 均基于有计时行的完整操作范围；均值不除以 `count`。字节、源群操作、配对和 `count` 各自报告全部行的算术均值。若需要每操作延迟，应从原始行结合实际测量定义另行计算并说明权重。

初始化、固定集合准备、暖在线加密、撤销与帮助获取必须使用不同标签；不能只抽取最便宜的阶段冒充总成本。所有重复来自同一保存的公共曲线参数，协议秘密使用新随机数。

`first_acquisition / cold_full_manifest` 在目录全量验证之后运行，包含客户端清单签名及自身帮助验证；它不重复全目录每一条根/记录的全部验证。`cold_audit / stress_one_client` 是单个客户端的一次独立全目录检查，单列计费；若报告全员冷审计，必须另按实际获取与检查次数核算，不能把这一行直接当成全员总量。

## 完整性和回传

`SHA256SUMS` 覆盖 ZIP 前已有结果文件（排除自身、ZIP 及临时文件）。ZIP 包含这些文件和 SHA 清单；`return.zip.sha256` 是 ZIP 的外置校验值。它们提供传输一致性，不是机构签名或实验真实性的密码学认证。

运行异常停止后可能没有最终 ZIP；保留整个目录仍有价值。不得删除失败样本后声称完整网格通过。Python 端只读取这些实际字段并绘图，不能填补测量层尚未提供的结果。

汇总或最终元数据写入失败会回写非成功状态。打包失败单独标为 `packaging_failed`，现有不完整档案改为 `return.zip.partial`，不保留宣称该档案已完成的 SHA 清单。任何不可写存储设备都可能阻止最后一次状态写入，此时命令退出错误必须保留，不能仅看之前的 JSON 宣称运行完成。
# v0.5.1 兼容说明

运行清单标记 `chare-go-pbc-v0.5.1`。原 CSV 字段和主快照 v2 不变；新增两个压力模式的实际发送者获取，CHARE 改变集合另有完整分支快照发布和存储行。新分支快照域为 `CHARE/cohort-sender-snapshot/v1`。DH 单个授权视图改用 `DH/independent-registry/authorization/v2`，签名内容增加历史命名空间。旧版本记录不能补零后冒充新增测量，完整输入哈希继续写入回传包。


## v0.6.0 冷审计证据
案例 configuration 新增布尔 `cold_audit_all_users`。result.json 新增 `cold_audit_evidence`，包含 profile、实际 clients 及每方案/槽位的 sequence/bytes。raw.csv 的 cold_audit 每行 count=1，detail 含 cold_client_slot 与 cold_sequence。Python 核对覆盖、重复、配对计数、序号与字节，对完整独立审计输出 cold_audits.csv；旧版行保留旧范围而不补造数据。

## 启动器时长保护

`cmd/goland` 的日志与状态在结果父目录 `_launches/<编号>/`，独立于批次目录及其 SHA256SUMS。状态 `timed_out` 表示被时间预算终止，不是完成测量。原生批次在每个案例完成后刷出 CSV、result/checks/status；强制终止时当前案例可能仍为 running，批次可能缺少最终 summary、SHA256SUMS 和 ZIP。不要补造最终状态或把不完整批次送入完整归档验证；保留并同步原文件。已有完整案例可单独审查，但不能称整批通过。
