[English](README.md) | **简体中文翻译**

# iDrive7/8 SSH root — 简体中文操作说明

本工具通过 **ENET** 诊断接口启用 BMW MGU 主机的 **root SSH**，支持原项目列出的 iDrive 7 / MGU ID7、ID8-BDC3 和 ID8-BCP。提供调试镜像刷写、身份注册、SSH 持久化以及恢复原厂 SSH 行为等操作。

原项目：[cauliflowermossgrape/idrive7-8-ssh-root](https://github.com/cauliflowermossgrape/idrive7-8-ssh-root)。

**翻译者：抖音：小白科技杂物社 · BiliBili：小白151 · GitHub：[JackieZ123430](https://github.com/JackieZ123430)**。

## 使用前准备

> 仅用于自己的车辆或已获授权的测试设备。刷写可能清空主机编码/CAFD，严重时可能导致模块无法启动。首次刷写前，请先备份主机编码，并在操作期间保持供电稳定、车辆唤醒。

- ENET 线缆及电脑，车辆点火或测试平台保持唤醒。
- 从源码运行需要 **Python 3.9+**；打包后的 Windows 程序无需安装 Python。
- 系统需提供 OpenSSH 客户端，运行 `ssh -V` 检查。Windows 10/11 可在“设置 → 应用 → 可选功能”中安装 OpenSSH 客户端。
- 按原项目要求，在 Windows 上以管理员身份运行终端或程序，以便 ENET 网卡使用 `169.254.x.x` 本地链路地址。

## 从源码启动

下载或克隆仓库，保留完整目录结构，然后在项目根目录运行：

```powershell
python -m pip install -r requirements.txt
python gui.py
```

程序每次启动默认使用 **English**。在窗口**右上角语言下拉框**选择 **简体中文**，即可切换按钮、说明、状态栏、确认对话框和已知日志提示；不会改变已填写的连接参数、复选框状态或正在进行的操作。

所有语言下，窗口标题均保持 `MGU iDrive SSH Tool`。翻译者署名仅保留在本说明文档中；界面和诊断日志不显示署名。切回 English 后，界面和日志恢复英文。

日志中的已翻译消息会保留下一行 `[EN]` 原文，便于搜索及向上游反馈。IP、VIN、密钥路径、命令、错误码和原始协议数据保留原值。未收录的底层错误、远端脚本输出及第三方工具输出仍显示原文。命令行程序本身保持原来的英文输出。

## 界面如何填写

| 项目 | 填写方法 |
| --- | --- |
| VIN | 点击“读取 VIN”，或手动输入该主机对应的 17 位 VIN；刷写时必填，且会写入主机。 |
| 网关 | 通常保留 `auto`，通过 UDP 6811 自动搜索；也可填实际 ENET 网关 IP。 |
| 架构 | 按硬件选择 `id7`、`id8-bdc3` 或 `id8-bcp`；不要仅按屏幕外观判断。 |
| MGU IP | 可留空，由诊断流程读取；只有确认实际主机 IP 后才手动指定。**网关 IP 不等于 MGU IP。** |

“读取 VIN”只发现 ENET 网关并填写 VIN/网关地址，**不会同时填写 MGU IP**。因此这时 MGU IP 为空属于正常现象，不能据此判断 SSH 已开放。

## 先检查连接

首次操作先运行只读检查：

```powershell
python ssh_enable.py status
```

此命令读取软件版本、MGU IP、调试状态故障码并检测 SSH 端口，不进行刷写。若自动发现失败，检查 ENET 线缆、网卡地址和主机唤醒状态；已知实际网关时可以使用 `--gateway` 指定。

## 三个操作按钮

### 刷写并启用（Flash + Enable）

用于需要安装调试包的首次设置。先备份编码，填写并核对 VIN、选择正确架构，再点击按钮。确认框会提示进入编程模式及重启，并显示即将写入的 VIN。

工具写入调试包、等待主机重启、注册身份，随后按勾选项设置 SSH 持久化。不要因等待而重复点击或中断供电。

刷写后如出现功能异常或编码复位，请用此前备份编码的同一工具恢复。原项目曾实际遇到编码被清空的情况；BimmerCode、ISTA/E-Sys 等工具的具体备份及恢复操作请按相应工具说明执行。

### 启用 SSH（Enable）

用于已经刷入所需调试包的主机，执行身份注册和 SSH 启用，**不重新刷写**。如果 SSH 已经能登录，不需要为了切换中文而再执行一次启用或刷写。

请以日志中端口开放及 `SSH OK as root: uid=0(root)...` 的验证结果确认成功，仅有 VIN 或网关发现成功不代表 SSH 登录成功。

### 停用 SSH（Disable）

尝试撤销 SSH 持久化并停止调试/SSH，恢复原厂仅在调试模式下运行 SSH 的行为。操作会要求确认。若 SSH 不可达，持久化撤销可能失败，请核对日志，不能仅凭按钮点击判断已完全恢复。

## 两个复选框

**启用后关闭调试模式（默认勾选，推荐）**

图形界面的启用和刷写操作始终请求 SSH 持久化。勾选此项会在持久化完成后关闭调试模式，以清除 `B7F8E5` 调试激活故障，同时保持 SSH 可用。不勾选则保持 SSH 持久化和调试模式开启。持久化验证失败时，程序会保留调试模式，避免丢失访问权限。

原厂 SSH 由 `debug.target` 和防火墙共同控制。持久化脚本通过 `/etc` 中的 systemd 覆盖和防火墙保持服务维持端口开放；防火墙规则约每 15 秒复查，因此关闭调试后可能短暂无法连接，工具会等待并重试。

**为此车辆使用独立 SSH 密钥（默认不勾选，不推荐）**

此项会通过 SSH 修改主机实际使用的 `AuthorizedKeysFile`，先添加新密钥、验证新密钥，再尝试删除共享开发密钥。它不是普通的“导出密钥”操作。原作者提示只能执行一次，丢失密钥或重新刷写后可能无法重新建立身份；除非明确了解用途并能妥善保管密钥，否则保持关闭。

如果换密钥后暂时不能连接，原项目建议按住音量/电源旋钮约 20–30 秒，让主机重启后加载新密钥。

## 启用后如何连接

工具会将密钥和连接信息保存到：

```text
data/enrollments/<VIN>/
```

主要文件：

| 文件 | 用途 |
| --- | --- |
| `connect.txt` | 实际 MGU IP 和可直接使用的 SSH 命令。 |
| `id_rsa` | OpenSSH 私钥。 |
| `id_rsa.pkcs1.pem` | PKCS#1 PEM 私钥，供兼容客户端使用。 |
| `id_rsa.pkcs8.pem` | PKCS#8 PEM 私钥。 |
| `id_rsa.ppk` | PuTTY / WinSCP 私钥。 |
| `id_rsa.pub`、`id_rsa.pub.pem` | 公钥，不能代替私钥登录。 |
| `fingerprints.txt`、`metadata.json` | 指纹及注册元数据。 |

优先复制 `connect.txt` 中的命令，例如将以下占位值换成真实 VIN、IP：

```powershell
ssh -i "data/enrollments/<VIN>/id_rsa" root@<MGU-IP>
```

使用 FinalShell 等客户端时，填写实际 MGU IP、端口 **22**、用户名 **root**，选择**公钥/私钥认证**并导入兼容格式的私钥。原项目生成的普通密钥没有额外的私钥口令；不要把车辆 VIN 当成登录密码。

请保存整个车辆密钥目录，勿公开上传。`data/assets/01_PRIVATE_KEY.pem` 是注册流程使用的密钥，**不是 SSH 登录私钥**；默认 SSH 使用调试镜像信任的共享开发密钥，工具会将其导出到上述目录。完整原理见[英文说明](README.md#the-ssh-key-and-connect-info)。

## 命令行操作

命令及参数保持英文，和原项目一致：

```powershell
python ssh_enable.py status
python ssh_enable.py flash --vin WBS1234ABCDX12345 --persist
python ssh_enable.py enable --persist
python ssh_enable.py persist
python ssh_enable.py close
python ssh_enable.py disable
```

示例 VIN 仅为占位，不能直接用于真实主机。`close` 停止调试/SSH，`disable` 还会尝试撤销持久化。命令行 `enable` / `flash` 需要显式加上 `--persist` 才请求持久化；GUI 会自动添加。

| 参数 | 用途 |
| --- | --- |
| `--gateway auto` 或实际 IP | 自动搜索或指定 ENET 网关。 |
| `--mgu-ip <IP>` | 手动指定 MGU IP。 |
| `--vin <VIN>` | 指定 VIN，刷写时必填。 |
| `--arch id7` / `id8-bdc3` / `id8-bcp` | 指定主机架构。 |
| `--persist` | 设置关闭调试模式后仍保持 SSH。 |
| `--keep-debug` | 持久化后仍保留调试模式。 |
| `--unique-key` | 启用高级独立密钥替换，默认关闭。 |
| `--yes` | 跳过命令行确认提示。 |
| `--verbose` | 输出诊断帧用于排查。 |

## 构建 Windows 程序

在项目根目录运行：

```bat
build_exe.bat
```

输出为 `dist\MGU-SSH\MGU-SSH.exe`。必须保留整个 `MGU-SSH` 文件夹，不能只复制 EXE。语言 JSON 通过 PyInstaller 打包，运行所需的 `data\assets` 和 `sshd-always-on.sh` 由构建脚本复制到 EXE 旁；车辆密钥保存在同目录的 `data\enrollments` 下。

## 增加其他语言

界面语言由 `locales/*.json` 映射，无需复制一份 GUI。新增语言的结构和测试方法见 [locales/README.md](locales/README.md)。新增 JSON 后，从源码重新启动即可出现在右上角列表中；EXE 需要重新打包。每次启动仍默认英文。

中文翻译：**抖音：小白科技杂物社 · BiliBili：小白151 · GitHub：JackieZ123430**。翻译者署名仅保留在 README 中；其他语言的贡献者也请在相应 README 中署名。

## 许可

沿用原项目的 [The Unlicense](LICENSE)。署名用于标注翻译贡献，不改变上游许可，也不新增强制署名条件。
