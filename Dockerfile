# syntax=docker/dockerfile:1
#
# 多阶段构建：前端静态导出 → Go 单二进制（内嵌前端）→ 运行镜像。
# 原 Docker Hub 镜像源（autumn27/artex）已失效，本仓库自此支持从纯源码自助构建：
#   docker compose build        # 或 docker build -t artex:local .
# TARGETARCH 由 buildx 自动注入（amd64/arm64），Go 交叉编译无需 QEMU；
# 运行层只装工具，编译全部在构建阶段完成。
# 国内网络可覆盖模块源（默认已对国内友好）：
#   --build-arg GOPROXY=https://goproxy.cn,direct
#   --build-arg NPM_REGISTRY=https://registry.npmmirror.com
# Release 使用 --build-arg ARTEX_BINARY_SOURCE=prebuilt，复用校验过的发布二进制；
# 默认仍从源码构建，无需下载任何预编译的 ARTEX 产物。
ARG ARTEX_BINARY_SOURCE=source
ARG TARGETARCH

########## 阶段 1：前端静态导出 ##########
FROM --platform=$BUILDPLATFORM node:22-bookworm AS web
ARG NPM_REGISTRY=https://registry.npmmirror.com
WORKDIR /web
# --ignore-scripts：跳过 prepare(husky)——容器里没有 .git，husky 会失败；
# Next.js/Biome 的平台二进制走 optionalDependencies，不依赖生命周期脚本。
COPY web/package.json web/package-lock.json ./
RUN npm config set registry "$NPM_REGISTRY" && npm ci --ignore-scripts
COPY web/ ./
RUN NEXT_EXPORT=1 npm run build:static

########## 阶段 2：Go 后端（内嵌前端，静态编译）##########
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS gobuild
ARG TARGETOS
ARG TARGETARCH
ARG ARTEX_BUILD_VERSION=dev
ARG GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct
WORKDIR /src
COPY go.mod go.sum ./
# 本仓库通过 replace 使用本地 norma；下载依赖前必须先提供它的模块声明。
COPY norma/go.mod norma/go.sum ./norma/
RUN go mod download
COPY . .
# 前端静态产物从 web 阶段拷入（.dockerignore 已排除宿主 dist，不会冲突）
COPY --from=web /web/out/ server/webui/dist/
RUN version="${ARTEX_BUILD_VERSION#v}" \
    && CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build \
       -tags embedui -trimpath -ldflags "-s -w -X main.version=${version}" \
       -o /out/artex ./cmd/artex

FROM scratch AS source
COPY --from=gobuild /out/artex /out/artex

########## Release 可选输入：不重新编译已验证的二进制 ##########
FROM scratch AS prebuilt
ARG TARGETARCH
COPY dist/${TARGETARCH}/artex /out/artex

FROM ${ARTEX_BINARY_SOURCE} AS binary

# Halmos 0.3.3 declares a mandatory yices-solver package. PyPI publishes that
# package only for linux/amd64, yet Halmos never imports it when invoked with
# --solver z3 (the adapter always passes --solver z3). Install Halmos without
# dependencies and list the runtime dependencies explicitly so arm64 does not
# fail on an unused package. Keep this list in sync with halmos 0.3.3's metadata.
FROM python:3.12-slim-bookworm AS python-tools-base
ARG HALMOS_VERSION=0.3.3
ARG FOUNDRY_VERSION=v1.7.1
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*
ENV PATH="/root/.foundry/bin:${PATH}"
RUN bash -o pipefail -c 'curl -fsSL https://foundry.paradigm.xyz | bash' \
    && foundryup --install "${FOUNDRY_VERSION}"
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m pip install --no-deps "halmos==${HALMOS_VERSION}" \
    && python3 -m pip install \
       "sortedcontainers>=2.4.0" "toml>=0.10.2" \
       "eth_hash[pysha3]>=0.7.0" "rich>=14.0.0,<14.1.0" \
       "xxhash>=3.5.0" "psutil>=6.1.0" "requests>=2.32.3" \
       "python-dotenv>=1.1.0"

# amd64: z3-solver has a prebuilt manylinux wheel.
FROM python-tools-base AS python-tools-amd64
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m pip install "z3-solver==4.12.6.0"

# arm64: z3-solver 4.12.6.0 has no linux/arm64 wheel, and solc is published only
# for x86_64. Build Z3 with a temporary C++ toolchain, then run the x86_64 solc
# through qemu-user (solc-select detects the qemu-x86_64 shim by name).
FROM python-tools-base AS python-tools-arm64
# The pip cache mount keeps the locally built Z3 wheel across image rebuilds;
# compiling it takes several minutes on arm64.
RUN --mount=type=cache,target=/root/.cache/pip \
    apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake qemu-user \
    && python3 -m pip install "z3-solver==4.12.6.0" \
    && apt-get purge -y --auto-remove build-essential cmake \
    && rm -rf /var/lib/apt/lists/*
RUN ln -sf /usr/bin/qemu-x86_64 /usr/local/bin/qemu-x86_64

FROM python-tools-${TARGETARCH} AS python-tools

########## 阶段 3：运行镜像（同原版：工具 + Playwright 预装）##########
FROM python:3.12-slim-bookworm AS runtime
ARG TARGETARCH
ARG NPM_REGISTRY=https://registry.npmmirror.com
ARG SLITHER_VERSION=0.11.5
ARG SOLC_VERSION=0.8.35
# 与下方 MCP/CLI 的精确依赖对齐，避免工具寻找另一版未安装的 Chromium。
ARG PLAYWRIGHT_VERSION=1.64.0-alpha-1790635538000
ARG PLAYWRIGHT_MCP_VERSION=0.0.83
ARG PLAYWRIGHT_CLI_VERSION=0.1.22
ARG PLAYWRIGHT_DOWNLOAD_HOST
# npm 源可覆盖；浏览器默认使用官方 CDN，也可通过 build arg 指定镜像站。
ENV npm_config_registry=$NPM_REGISTRY \
    PLAYWRIGHT_DOWNLOAD_HOST=$PLAYWRIGHT_DOWNLOAD_HOST \
    PATH="/root/.foundry/bin:${PATH}"
# 常用工具：ripgrep / curl / vim，加一批 recon 常备件（按需增删）。
# Node 与前端构建统一使用 22.x，避免继续使用已结束维护的 20.x。
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libseccomp2 ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap z3 \
    && if [ "$TARGETARCH" = "arm64" ]; then \
         apt-get install -y --no-install-recommends qemu-user; \
         ln -sf /usr/bin/qemu-x86_64 /usr/local/bin/qemu-x86_64; \
       fi \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# DeFi reviews need a compiler, project test runner, local EVM, static analyzer,
# and a symbolic checker (halmos, with the z3 solver). Pin the tools so the same
# source produces comparable evidence across runs.
# Bring in the per-architecture toolchain before the smoke checks below, so
# forge/solc/halmos are available in this stage rather than only at the end.
COPY --from=python-tools /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=python-tools /usr/local/bin/halmos /usr/local/bin/z3 /usr/local/bin/
COPY --from=python-tools /root/.foundry /root/.foundry
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m pip install \
       "slither-analyzer==${SLITHER_VERSION}" "solc-select==1.2.0" \
       "jsonschema==4.26.0" \
    && solc-select use "${SOLC_VERSION}" --always-install \
    && mkdir -p "/root/.svm/${SOLC_VERSION}" \
    && ln -sfn "/root/.solc-select/artifacts/solc-${SOLC_VERSION}/solc-${SOLC_VERSION}" \
       "/root/.svm/${SOLC_VERSION}/solc-${SOLC_VERSION}" \
    && forge --version && cast --version && anvil --version \
    && slither --version && solc --version \
    && halmos --version && z3 --version
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
RUN npm install -g "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}" \
      "@playwright/cli@${PLAYWRIGHT_CLI_VERSION}" "playwright@${PLAYWRIGHT_VERSION}" \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && node -e 'const fs = require("node:fs"), cp = require("node:child_process"); const root = cp.execFileSync("npm", ["root", "-g"], {encoding:"utf8"}).trim(); fs.symlinkSync(require(root + "/playwright").chromium.executablePath(), "/usr/local/bin/artex-chromium");' \
    && rm -rf /var/lib/apt/lists/*
# MCP/CLI 默认使用容器已安装的 Chromium，无需 Chrome、显示服务器或运行时下载。
# 容器以 root 运行，Chromium 的进程沙箱不可用；可在自定义非 root 部署中覆盖。
ENV PLAYWRIGHT_MCP_EXECUTABLE_PATH=/usr/local/bin/artex-chromium \
    PLAYWRIGHT_MCP_HEADLESS=true \
    PLAYWRIGHT_MCP_SANDBOX=false
WORKDIR /app
# 内置 browser MCP 使用 npx @playwright/mcp。npm exec 不保证解析全局包；
# 将预装依赖暴露到应用的本地依赖路径，子工作目录也可离线启动同一版本。
RUN ln -s "$(npm root -g)" /app/node_modules \
    && npx --offline --no-install @playwright/mcp --help > /dev/null
# 构建阶段产出的单二进制（内嵌前端）
COPY --from=binary /out/artex /app/artex
COPY LICENSE /usr/share/doc/artex/LICENSE
COPY web/LICENSE /usr/share/doc/artex/web/LICENSE
COPY norma/LICENSE /usr/share/doc/artex/norma/LICENSE
COPY norma/noa/LICENSE.acp-kernel /usr/share/doc/artex/norma/noa/LICENSE.acp-kernel
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 artex —— docker stop 只把信号发给 PID 1，
# 不转发的话 artex 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh
COPY skills/ /app/skills/
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
