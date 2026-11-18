## 2026-11-07 v0.7.0 原生实验验收

完整 `go test -mod=vendor ./... -count=1` 在本机真实PBC/GMP环境通过。新N=4/8/16各三次的小参数功能网格九例全部通过，共1704项检查；包含增量帮助精确一致、旧状态不变、候选集改变拒绝、原生树/环贡献和旧KDF密钥恢复。此网格使用64/256功能参数，保存在忽略的build/study-validation，仅用于实现和回传流水线验收，不能用于论文性能。

Python的37项核验测试通过；四组预览图的PDF宽度/字体检查通过。新正式配置为Type-A256/1536，九例、三次重复，仍待用户虚拟机实际运行。PAPER_STUDY.md给出完整范围。以上检查不提供密码学安全证明，也不校准安全位数。

# 2026-11-06 receiver refresh correction (v0.6.2)

Three new actual PBC regression cases failed against v0.6.1: authentic unrelated
snapshot, authentic old snapshot after a new installation, and partial mask
replacement when a later signed delivery decodes outside the canonical range.
The corrected full suite passed **77 Go/PBC tests**. Result ingestion passed
**35 Python checks**, including rejection of a missing v0.6.2 refresh profile.

An actual native N=4/N=8, m=2, R=A=N, one-replicate batch reused the exact public
parameters from the preceding validation (actual r=160 bits, q=513 bits).
Both cases passed all **261 functional checks**, producing **1,276 raw rows**
and **634 summaries**. The complete ZIP was independently imported and audited.
Full snapshot reserialization/binding is inside each measured receiver-refresh
interval. These new samples are separate; old timings are not reinterpreted.

This is local implementation validation, not the user's full VM paper grid,
calibrated security strength, a new security proof or a matched baseline advantage.
Source evidence is archived in `[local path removed]`.

## 历史版本 v0.6.1：参数结构准入

完整 74 项 Go/PBC 测试、32 项 Python 检查通过。新版参数解析覆盖原生入口与 runner，回传端核对原始参数及报告。保留所有历史结果原有源码身份；正式安全强度未校准。详见 PARAMETER_ADMISSION.md。

新版实际批次 `20261106T031747.892740600Z_parameter-admission-validation_76301cd5` 使用原始公开参数字节，实际 r=160 位、q=513 位；N=4/8、m=2、R=A=N、各一次。261 项检查通过，1276 行原始观测、634 行汇总及24个实际逐客户端冷审计已校验回传。该批次单独保存，不与旧版拼接，也不是用户虚拟机完整论文网格。

# 本地验证记录

日期：2026-11-06。主机：Windows amd64，Go 1.23.3，MinGW GCC 8.1.0。

## 当前补充：v0.6.0 + ledger-audit-v1

本机完整 Go/PBC 测试 **69 项通过**：auth 7、transport 5、runner 7、core 16、
bench 26、ledger 8。新增系数审计器及真实 PBC 失败见证检查，详见
[系数审计](LEDGER_AUDIT.md)。测试验证实现对应关系，不验证安全定理。
该包未接入协议计时流程，本轮没有产生新的批量性能样本。下面的 v0.6.0
原始测量继续保留其运行源码哈希；源码包增加审计文件后不能冒充同一份源码。
Python 端保持上轮已验证的 27 项检查及传输核算版本，本次未重复运行。

## v0.6.0 原始交付：独立历史重放与全员冷审计通过

本机完整 Go/PBC 测试 60 项通过：auth 7、transport 5、runner 7、core 15、bench 26。Python 回传/核算测试 19 项通过。实际批次 `20261106T013742.536955000Z_independent-cold-audit-validation_bdfa1275` 的 N=4/8、m=2、R=A=N 两案例通过 261 项检查，记录 1276 行原始观测、634 行汇总以及双方共 24 个逐客户端冷审计区间。完整回传包已独立校验并生成 `cold_audits.csv`，没有将单客户端时间乘以 N。

新反例检查确认：旧签名/当前记录检查可接受一份真实签署但与完整发行历史不一致的聚合快照；新独立重放拒绝它。删除审计器以外的私钥、资格真值、缓存、当前行表与发行签名者后，公开输入审计仍成功。以上验证实现覆盖，不能替代密码学安全证明。

源文件与实际运行匹配，随后仅更新 README.md、COLD_AUDIT.md 和本验证记录。两份稿件、加密核心、认证、传输与 native 封装未改动。参数为真实 160/512 功能配置，尚无具体安全位数结论。完整 Linux VM 网格、实际曲线校准和同功能比较仍待完成。详细重建论证与差额见 `[local path removed]`。

## 历史状态：v0.5.1 压力入口和原生对象生命周期修复通过

本机完整 Go/PBC 测试 56 项通过：auth 7、transport 5、runner 6、core 15、bench 23。Python 回传与核算测试 16 项通过。最终运行 `20261106T005920.097371700Z_stress-sender-acquisition-validation_6fce290c` 的 N=4/8、m=2、R=A=N 两案例通过 259 项检查，保留 1256 行原始观测和 634 行分组汇总。实际源文件哈希与最终实现一致；随后仅更新说明文件。参数沿用真实 160/512 功能配置，不作具体安全位数判断。

本轮先复现并修正 DH 授权视图未直接绑定历史分支的问题。测试构造两个各自真实签署、局部版本相同而名单不同的视图；修复前可交叉使用，加入分支字段和 v2 格式后拒绝。此缺陷属于本地对照实现，不代表来源方案不安全或 CHARE 具有新颖性。

随后的一次批处理（ID `20261106T005108.167434600Z_stress-sender-acquisition-validation_3e9a2e3e`）N=8 在初始记录验证时失败，退出码为 1；该案例按原机制排除，不重标为成功。新增强制 GC 回归在第 0 次临时群元素双线性检查失败。封装层 Go 对象及 GMP 临时所有者缺少 C 调用期间的存活保护；修补后该测试 32 次迭代、完整测试和最终批处理均通过。精确 finalizer 调度未恢复，因此不声称逐指令证实了之前那次批处理的全部故障链。修复依据和范围见 VENDOR_PATCHES.md。

修复前的成功批次、失败批次和最终成功批次均保留各自源码身份，不混合成重复样本。失败及修复日志保存在本地研究目录 `[local path removed]`。测试本身修改 GC 压力并在退出恢复；正式测量不关闭 GC，也没有通过修改参数或重试失败案例让它通过。

最终回传包已通过双层校验、工作负载一致性审查及独立表格导入；没有据此生成论文性能结论。完整 Linux VM 网格、同安全强度参数校准和论文比较仍待完成。

## 历史状态：v0.5.0 发送者获取测试已通过

真实 native 测试 52 项通过：auth 7、transport 5、runner 6、core 14、bench 20。新增公开发送者副本的功能一致性、不可变性、完整上下文绑定、错误签名/状态拒绝及无需持有人秘密的检查。Python 结果读取/核算 9 项测试通过。

实际 N=4/8、m=2、R=A=N 各一例运行完成，257 项流程检查通过，1214 行原始观测、604 行分组汇总。双方主要策略的发送者获取均有逐行账本。运行标识：`20261105T233916.204266400Z_sender-acquisition-validation_f1bd031f`；目录 `build/native/v050-results`。这不是目标虚拟机完整网格或密码学安全实验。完整证据在 `[local path removed]`。参数未作具体安全强度校准，部分短计时间隔为零值并如实保留。下文旧版本记录不改变含义。
## 历史状态：v0.4.0 有效撤销测试已通过

真实 native 测试45项通过：auth 7、transport 5、runner 6、core 12、bench 15。新增完整RunCase检查包括N=4的三次撤销（槽位3仍保有B）和四次撤销（所有正资格撤销），以及旧状态保持。无法满足有效撤销数量的配置在原生设置前拒绝；Python端3项结果接收测试通过。正式批量网格仍由目标虚拟机运行。

随后使用原160/512功能参数执行N=4/8、m=2、各一例的完整有效撤销/获取负载：
`20261105T222150.986747100Z_effective-withdrawals-validation_1bdc8e0b`。
两例通过，257项检查通过，1198行原始观测；逐事件核验分别为4/8个不同资格的1→0和4/8次双方获取，均有完整回传ZIP。Python实际读取通过。
运行位置为 `build/native/v040-results`，原参数字节与来源均保存在结果中。
这仍是小规模功能/流程验证，不是目标虚拟机完整性能网格。新旧案例的检查数会随授权名单及实际执行路径变化，不能将数量差当作性能或安全强度差。

## 历史状态：v0.3.0 独立对照生命周期已验证

实际原生测试共 **41 项通过**：auth 7、transport 5、runner 5、core 12、bench 12。
新增五项针对独立接收键与证书、部分撤销/新鲜性、失败发布原子性、空名单/旧密文/重新授予，以及跨历史分支隔离。测试执行真实 PBC；没有用替身群或公式计时代替。

完整一键脚本重新执行测试与编译后，生成
`20261105T213131.686644400Z_sanity_94234815`：N=4/8、m=2、每例一次，
2 次撤销和 2 次自适应获取，**2 案例通过、270 项功能检查通过**，
1272 行原始观测、678 行汇总。时间戳为 UTC。

这两个默认短调度中的拒绝更新碰到原已拒绝资格，因此另运行一个有针对性的 N=4、m=2、4 次撤销/4 次获取案例：
`20261105T213417.543484300Z_lifecycle_actual_revocation_2981b4b4`，
**106 项检查通过**，514 行原始观测、324 行汇总。
该调度实际撤销槽位 3 的 B，而其 A 仍然有效；最后 A∧B 为空。这个额外配置和原始结果分开保留，没有合并成多次独立重复来缩小误差条。

v0.3.0 结果位于忽略目录 `build/native/v030-results`，两个运行均生成完整 `return.zip` 与校验文件。
源码和研究核验账本另存 `[local path removed]`。
这些小规模运行验证可执行性、状态与记录口径，不能证明密码学安全、给出稳定性能结论，或替代用户 VM 的完整网格。

## 历史状态：v0.2.1 原生测试已通过

在项目的忽略目录 `build/native` 中，实际编译了官方 PBC 0.5.14 源码，
使用官方 MSYS2 的 GMP 6.3.0-2 开发包（校验 SHA-256），没有安装系统软件。
构建日志及依赖清单独立保存；源码 ZIP 不包含这些 Windows 二进制。

实际执行 `go test ./... -count=1 -timeout=90s -json`，退出码 0：
auth 7 项、transport 5 项、runner 5 项、core 11 项、bench 7 项，合计 35 项。
这是新增大参数回归测试之前的记录，其中 18 项直接执行原生 PBC 操作。日志为
`build/native/final-tests.jsonl`。

新增参数导出测试先发现 `Params.String()` 返回空串。单独 C 程序确认
MSVCRT `tmpfile()` 因权限不足失败。已修复 Windows 临时文件路径，以及
源代码审查发现的字符缓冲区终止指针错误，见 `VENDOR_PATCHES.md`。
第一次失败和后续通过日志均保留，没有删除失败记录。

随后通过实际一键批量运行进一步发现并修复两处平台问题：

- `run.ps1` 的 Windows 路径转义导致 cgo 生成错误链接指令；改成正斜线并对完整参数加引号。
- PBC 0.5.14 在当前 LLP64/GMP 配置中的 Montgomery 常量被截断；首次 N=4/8 批量均未通过投影检查，未纳入性能汇总。原生库单行修复、依据和实际环境见 `PBC_WINDOWS.md`。

加入 `TestNativeLargeFieldBilinearity` 后，一键脚本重新完成 **36 项测试**
（core 12、bench 7、其他 17），随后 **N=4 和 N=8 的两个实际案例全部通过**。
成功日志为 `build/native/one-click-sanity-final.log`。每案例都运行初始化、
首次获取、策略封装、撤销、追赶、重新授予及缓存相关检查；实际范围以配置和逐案例输出为准。
成功运行 ID 为 `20261105T201902.036214400Z_sanity_cfbb32b8`，时间戳使用 UTC。
该运行已经产生真实本机测量和 `return.zip`，但不属于另一台 VM 的论文完整网格。

这些是实现和平台验证，不是密码学安全证明。下面保留早期记录，说明此前阻塞及其解除过程。

## 早期记录（已被上面的原生验证更新）

已经实际执行：

- 固定提交的 `go mod download` 成功，`go.sum` 已保存实际模块校验值。
- `go mod verify` 返回 `all modules verified`。
- `gofmt` 成功解析并格式化 runner 的 Go 源码。
- 对实际 `config.go` 与 `config_test.go` 的五项配置单元测试通过：工作负载冲突、重复网格、属性维数 64/65 边界、未知/尾随 JSON、相对参数路径。此步骤没有编译虚假 PBC 替身。
- PowerShell `run.ps1` 的语法树解析未报告错误。
- 一次完整项目仅编译检查 `go test ./... -run '^$'` 已尝试，**失败**于真实 PBC 依赖：`fatal error: pbc/pbc.h: No such file or directory`。
- 小修后实际执行 `go test ./... -count=1`，退出码 1：`internal/auth` 的功能测试通过；主程序、core、bench、runner 仍在真实 PBC 编译阶段因同一缺失头文件失败。原始输出保存在本地忽略目录 `build/native_test_20261106.log`，未生成性能数据。

因此尚不能声称整个项目已经完成 native 编译、通过完整功能检查或取得性能数据。用户虚拟机仍需在实际 GMP/PBC 环境中编译并运行。此文档是已观察状态，不把尚未执行的检查写成通过。

本记录不包含密码学安全实验。代码检查与功能测试只用于实现一致性；论文的安全证明独立成立于其明示模型及条件。

v0.2.0 缓存交付增量（同日）：

- 7 项 auth 与 5 项 transport 测试在真实 Go 标准库环境通过；其中 transport 覆盖精确恢复、签名/版本/不可变 ID 冲突、截断和溢出长度、策略权重排除及双方独立格式。
- 5 项独立配置测试再次通过。合计 17 项不依赖 PBC 的测试通过。
- 新增 `TestNativeCiphertextPrefixAdapter`，用真实 PBC 生成双方密文后检查缓存恢复；原生测试现在共 17 项，尚未执行成功。
- `go test ./... -count=1` 再次实际执行，退出码 1，原因仍为 vendor 绑定找不到 `pbc/pbc.h`。auth/transport 通过不代表 core/bench/runner 已编译。日志在忽略目录 `build/native_transport_20261106.log`。
- 所有修改后的 Go 文件已 gofmt；Python 绘图入口已通过语法解析，没有生成任何性能数据或示例图。

核心密码学文件 `internal/core` 未修改；缓存读取完整已生成密文并恢复相同字节。新的原生集成与批量计时必须在 VM 中验证，不能将上述字节测试当作其替代。

## v0.4.1 认证与计费补齐

本机真实原生测试48项通过，其中新增3项覆盖固定信任根、证书移植/替换、已签名但投影不一致的根，以及在打开私密材料前拒绝无效清单。新的N=4/8、R=A=N批量运行全部通过。认证函数仍处理生成的类型化对象，不是恶意网络字节解析器。签名不替代可信当前快照。完整证据及源码身份保存在 [local path removed]
