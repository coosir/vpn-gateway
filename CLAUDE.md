# 项目执行规则

这些是本仓库固定的工作方式，除非当次明确另有说明，一律按此执行。

## 1. 客户端编译：默认只编译 Windows

```
make windows
```

产物在 `dist/windows-amd64/`（`vpn-gateway-desktop.exe` 内含 `vpn-gateway.exe`）。

macOS 的 `make app` / `make desktop`、Linux 的桌面构建，只有在明确要求时才做。

## 2. agent 变化：构建 docker 镜像，默认只 amd64 并推送

改动涉及 `cmd/vg-agent/`、被 agent 引用的 `internal/`、`pkg/`，或 `images/*/Dockerfile` 时：

```
make push PLATFORMS=linux/amd64
```

发布 `mock`、`sangfor`、`openconnect` 三个镜像到 `coosir/vg-*:latest`。
`inode` 属于厂商层，不发布，不用管。
需要 arm64 时才去掉 `PLATFORMS` 覆盖（默认值是 amd64+arm64）。

## 3. 每完成一个需求变更：升 build 号 → 编译 → 提交并推送

顺序固定：

1. `internal/version/version.go` 里的 `Build` 加一（四位补零，如 `0046` → `0047`）；
   `Version` 只在明确要求发版时才动。
   纯文档变更（`*.md`、`docs/`、注释）不升 build，也不用编译，直接提交推送，
   提交类型用 `docs:`。
2. 编译验证：`make check`（build + vet + test）；涉及客户端时再按规则 1 编译 Windows；
   涉及 agent 时再按规则 2 构建并推送镜像。
3. 提交并推送到默认分支 `master`（origin: `git@github.com:coosir/vpn-gateway.git`）。

提交信息沿用现有格式，一句话描述行为变化，末尾带版本：

```
feat(agent): a gateway that signs you in through Microsoft (v1.0 build 0046)
fix(client): the window and the menu bar show the same thing (v1.0 build 0044)
```

scope 用 `agent` / `client` / `server` / `openconnect` 等，纯版本号变更用 `chore:`。
