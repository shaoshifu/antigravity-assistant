# antigravity-assistant
Antigravity Windows 登录联动助手，支持链接捕获与一键结束客户端。非官方工具。

## 项目说明

当前助手版本为 **v1.3.1**。这是非官方兼容维护项目，与 Google 官方无隶属关系。
原作者为 **伽马AI**，保留程序和源码中的原署名及主页：<https://www.16688.com.cn/shop/S444368>。
本仓库不新增 MIT、Apache、GPL 等许可证；公开可见不代表获得任意复制、修改或再分发授权。

## 下载

以下地址仅在对应 GitHub Release 成功公开后生效：

- [v1.3.1 版本页面](https://github.com/shaoshifu/antigravity-assistant/releases/tag/v1.3.1)
- [Windows x64 EXE](https://github.com/shaoshifu/antigravity-assistant/releases/download/v1.3.1/AntigravityAssistant-v1.3.1.exe)
- [Windows x64 ZIP](https://github.com/shaoshifu/antigravity-assistant/releases/download/v1.3.1/AntigravityAssistant-v1.3.1-windows-x64.zip)
- [SHA256SUMS.txt](https://github.com/shaoshifu/antigravity-assistant/releases/download/v1.3.1/SHA256SUMS.txt)

原样发布的 EXE SHA256：

```text
525039e33df41e01b94abcc3d381bc5845469396eb558c25849a6bad54efd61a
```

EXE 未做代码签名，Windows 可能显示未知发布者。应核对来源和哈希，不要关闭杀毒软件或系统安全保护。

## 功能与使用

1. 保存客户端未保存内容，关闭旧助手，运行本版本 EXE。
2. 默认客户端目录为 `%LOCALAPPDATA%/Programs/antigravity`；其他安装路径未验证。
3. 在“补丁”页查看客户端状态；需要结束客户端时，点击“一键结束客户端”，核对 PID 和完整路径后再确认。
4. 此操作只处理当前安装路径的 Antigravity.exe，核验 PID、路径和创建时间；不会自动提权或自动打补丁。
5. 确认全部退出后，按界面提示手动打补丁。未知结构会拒绝修改，不应强行绕过结构检查。
6. 启动客户端，重新点击 Continue with Google，按界面完成本人授权链接及回调搬运。不要继续提交结束客户端之前的旧回调。
7. 如需恢复，使用工具的恢复功能并保留对应原包备份。客户端更新后应重新检查兼容性。

强制结束可能丢失未保存内容，并使当前登录会话失效。不会自动结束其他安装目录的同名程序。
本工具不绕过订阅、账号限制、产品权限、state 或 PKCE；授权码换票仍由官方客户端完成。
只支持 IPv4 localhost/127.0.0.1 回调，不支持 IPv6 `[::1]` 回调搬运。

## 兼容性与验证边界

本版本针对 Antigravity **2.31.2** 的已验证结构适配。外链使用 `externalUrl.openExternalSafely`，只修改已验证出口，保留官方安全门，不承诺兼容未来版本。

- 原交付记录：37 项 Python 回归（包含 JS harness）、14 项进程模拟、30 项登录检查及 EXE GUI 自检通过。
- 本次发布准备复跑：14 项进程模拟、30 项登录检查、45 项 JS 场景通过。JS harness 与 Python 套件内的同一组 JS 测试不重复计数。
- 本次当前客户端真实包回归：结构检查报错 `/dist/utils.js 安全出口引用 预期命中 1 处，实际 0 处`，因此**不能宣称当前安装包兼容性已通过复验**。本次读取的 app.asar 哈希与原交付验证记录不同，具体原因尚未确认。
- 独立运行合成夹具部分：32 项 Python 测试通过；真实官方包部分不包含在该结果中。
- 未验证：真实点击结束客户端、补丁后真实客户端完整启动、真实 Google 授权换票；发布不等于这些功能已通过端到端验收。

## 隐私边界

最新授权请求会保存到本机 `captured_url.json` 并进入剪贴板，可能包含敏感 state 等会话信息。
不记录完整 URL 历史，不广播给旧捕获器，回调授权码不主动落盘。不要分享捕获文件、回调 URL 或含会话信息的日志。

## 源码运行与离线自检

Python 标准库及 Tkinter 用于 GUI，Node.js 用于 JS 自检；源码文件位于 `src/`。

```powershell
python -B src/assistant_gui.py
python -B src/selftest_process.py
python -B src/selftest_login.py
node src/selftest_interceptor.js
python -B src/selftest_v13.py "<本机只读官方 app.asar 路径>"
```

`selftest_v13.py` 的真实包用例需要兼容的官方包及对应 `.unpacked`，只读原包，在隔离目录构建测试产物。不在仓库或下载包分发官方样本、内部验证记录、授权数据或构建目录。
