# 构建环境

## Linux 虚拟机

需要 Go 1.23 或更高版本、CGO、C 编译器、GMP 开发头/库，以及 PBC 开发头/库。绑定编译时引用 `gmp.h`、`pbc/pbc.h`，链接 `-lpbc -lgmp`。只存在 `libpbc.so` 而没有开发头文件还不够。

本项目不自动安装系统软件。先使用你已有的安装配置，确认以下条件：

```bash
go version
gcc --version
go env CGO_ENABLED
```

`run.sh` 与 `run.ps1` 会先运行完整功能测试 `go test ./... -count=1`，通过后才构建并启动批量测量。GoLand 推荐入口 `cmd/goland/main.go` 同样先执行完整测试；根目录旧 `main.go` 只保留每案例检查。

若 PBC/GMP 安装在标准搜索路径，直接运行 `bash run.sh sanity`。如果安装在自定义前缀，例如 `/opt/pbc`，可在当前终端设置：

```bash
export CGO_ENABLED=1
export CGO_CFLAGS='-I/opt/pbc/include'
export CGO_LDFLAGS='-L/opt/pbc/lib -lpbc -lgmp'
export LD_LIBRARY_PATH="/opt/pbc/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
bash run.sh sanity
```

这些路径只是示例，应替换为实际安装位置。代码没有要求为了运行而切换 PBC 版本；结果包应记录实际库来源。`pkg-config` 不存在时元数据会注明，不能据此推出 PBC 不可用。

依赖获取可以显式执行 `go mod download`。`go.mod` 固定 Go 绑定提交，`go.sum` 保存代理校验值。首次下载需要网络；断网 VM 可以预先准备合法的 Go 模块缓存。不要临时把其他项目源码改名来满足依赖。

## GoLand

用 CHARE 作为模块根打开，选择已有 Go SDK 和 PBC 环境。共享配置 `.run/CHARE Batch.run.xml` 启动 `cmd/goland`：先运行完整测试并构建原生批次，再直接执行默认 9 案例配置，合计 10 分钟超时保护。`CHARE Sanity` 使用小规模配置。

也可直接点击 `cmd/goland/main.go` 中 main 左侧运行按钮，无参数默认有界网格。它不需要额外下载 Go 依赖，使用随仓库同步的 vendor。原生 GMP/PBC 仍须在运行设备安装。

运行参数可设 `-profile sanity` 或 `-params /path/to/public.params`。非标准库目录要在运行配置的 Environment 中提供 CGO_CFLAGS、CGO_LDFLAGS 和 LD_LIBRARY_PATH。启动器继承环境并开启 CGO；不会复制本机 Windows 路径到 Linux。

所有运行入口默认将结果写到源码项目内的 `CHARE/results/<运行编号>/`，与 `main.go` 同属一个项目目录，不随 GoLand 工作目录改变。`-out` 相对路径以 CHARE 为基准，显式绝对路径保持原样。源码位置、可执行文件位置和工作目录均无法定位 CHARE 时，须显式指定绝对输出路径。

发布包的归档测量位于仓库根目录的 `results/native/`。本机重跑可用 `-out` 指定独立目录，原生模块的默认输出目录与构建缓存由 Git 忽略。见 [原生入口](../README.md)。

## Windows（可选）

需要同一架构的 MinGW 编译器、GMP/PBC 头文件、导入库和运行 DLL。`run.ps1 -PbcPrefix ...` 只设置当前进程的编译/运行搜索路径，不安装、不修改系统。前缀须有 `include\pbc\pbc.h`、`lib` 和相应 `bin`。

当前主机默认 GOPATH 与旧源码树不同。本模块用 `go.mod` 固定依赖，不依赖全局修改 GOPATH 或关闭 modules。附近项目的运行 DLL 不自动证明 CHARE 能链接；不要把其 DLL 版本当作已测环境事实。

本机已经完成一次隔离原生构建及一键小规模验证。PBC 0.5.14 与某些 Windows GMP 字长组合需要兼容修复，详见 [PBC_WINDOWS.md](PBC_WINDOWS.md)；Go 绑定的临时文件修复见 [VENDOR_PATCHES.md](VENDOR_PATCHES.md)。小整数测试通过不足以证明大字段后端可用，脚本包含实际大字段检查，不应绕过。

## 边界

`160/512` 等参数是曲线尺寸，不是经过审定的安全位数。主核使用对称 Type A，与周边 Type F 项目不可直接互换。参数文件是可信的公共配置输入；本项目尚未给底层 C 参数解析器增加针对任意恶意文件的隔离层。

功能检查只用于发现实现错误。理论安全结论仍来自论文中的具体模型、定理和假设，不由测试通过率获得。

导入参数在原生解析前必须满足 [Type-A 参数准入](PARAMETER_ADMISSION.md)；仅有正确的 q/r 位长不够。不支持的格式直接报告错误，不自动修复或换组。

启动器结果日志在 `results/_launches/`；仅 `cmd/goland` 提供总时长保护，旧 run.sh/run.ps1 与根 main.go 不提供。超时结果不标为完成批次。
