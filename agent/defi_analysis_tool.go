package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/google/uuid"
)

// The fixed tool reads this launcher from the editable skills tree. Pin its
// reviewed contents and pass them to Python in memory so a changed on-disk file
// cannot turn the sandbox step into an unrestricted tool call. Update the hash
// deliberately when changing skills/defi-audit/scripts/sandbox_exec.py.
const defiSandboxSHA256 = "ad5e4a7a96ab79169f8545387b05230af6867a6c828ac8edd25d4f006fd218ea"

// defi_analysis is a fixed-action bridge to the shipped DeFi adapter. It never
// accepts a shell command, executable path, RPC URL or output directory from the
// model. Build hooks in reviewed repositories still require an external sandbox.
func newDeFiAnalysisTool(skillDir, dataDir, runDir string, taskID int64, as *db.AssetStore) actool.CoreTool {
	return writeTool("defi_analysis",
		"DeFi 专用分析工具：运行固定的本地分析（含 halmos 符号执行）、范围内合约的只读链上/源码获取和结构化证据动作，并通过 ledger-init/status/cover/show 维护任务级共享检测台账。静态告警、符号反例与通过的测试都只是候选线索，不是已确认漏洞。",
		obj(map[string]any{
			"action":                   map[string]any{"type": "string", "enum": []string{"repository-clone", "manifest", "forge-build", "forge-test", "forge-replay", "slither", "halmos", "inventory", "deployment-snapshot", "verified-source-fetch", "deployment-bind", "catalog-tags", "catalog-select", "evidence-from-run", "evidence-validate", "ledger", "ledger-init", "ledger-status", "ledger-cover", "ledger-show"}},
			"project":                  str("源码项目目录（manifest/build/test/slither/inventory 必填；须在当前任务工作目录内）"),
			"repository_url":           str("repository-clone 必填：任务范围中的 HTTPS Git 仓库 URL"),
			"revision":                 str("repository-clone 可选：任务范围允许的提交或 Git ref；返回固定 commit SHA"),
			"chain_id":                 map[string]any{"type": "integer", "minimum": 1, "description": "EIP-155 链 ID；链上只读动作必填，分析运行时记录目标上下文"},
			"block_number":             map[string]any{"type": "integer", "minimum": 0, "description": "固定区块号；deployment-snapshot 必填，其他动作可选；需要 chain_id"},
			"address":                  str("0x 合约地址；链上只读动作必填，其他动作可选；需要 chain_id"),
			"protocol":                 str("catalog-select 的协议类型，如 vault/lending/amm/bridge"),
			"features":                 map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "已观察到的协议功能标签；由 catalog.py tags 列出"},
			"track":                    str("catalog-select 的链/语言 track；默认 evm"),
			"match_test":               str("forge-test 的单个 Solidity 测试函数名；halmos 用作符号属性函数名（如 check_ 前缀）"),
			"match_contract":           str("forge-test/halmos 的测试合约名"),
			"record":                   str("evidence-validate 的结构化发现 JSON 文件（任务工作区内）"),
			"artifact_root":            str("evidence-validate 的工件根目录（任务工作区内）"),
			"primary_manifest":         str("forge-replay 必填：第一次测试的 manifest.json 路径"),
			"verifier":                 str("forge-replay 必填：独立复核者标识；仅为记录标签，不证明独立判断"),
			"result":                   str("evidence-from-run 必填：run_analysis.py 的 result.json 路径"),
			"snapshot":                 str("deployment-bind 必填：固定区块 deployment-snapshot JSON 路径"),
			"verified_source_response": str("deployment-bind 必填：Sourcify API v2 原始响应 JSON 路径"),
			"source_prefix":            str("deployment-bind 可选：Sourcify 源码路径在测试项目源快照中的前缀"),
			"details":                  str("evidence-from-run 申请 reproduced 时必填：人工/agent 编写的语义详情 JSON"),
			"evidence_status":          str("evidence-from-run 状态：hypothesis（默认）或 reproduced；不自动确认"),
			"ledger":                   str("ledger 动作的经济账本 JSON 路径"),
			"selection":                str("ledger-init 必填：catalog-select 输出的 selection JSON 路径"),
			"card_id":                  str("ledger-status/cover 必填：EVM-01 等检测卡 ID"),
			"review_status":            str("ledger-status 的证据状态；reproduced/confirmed 需要 record 和 artifact_root"),
			"reason":                   str("ledger-status 的原因；blocked/not_applicable/refuted 必填"),
			"actor":                    str("ledger-cover 的执行者角色"),
			"entrypoint":               str("ledger-cover 的合约入口"),
			"outcome":                  str("ledger-cover 的结果 success 或 revert"),
			"transition":               str("ledger-cover 的状态转换标签"),
			"boundaries":               map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "ledger-cover 覆盖到的边界状态"},
			"artifact":                 str("ledger-status/cover 的证据文件路径；工具会计算相对于 artifact_root 的 SHA-256 引用"),
		}, "action"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				Action                 string   `json:"action"`
				Project                string   `json:"project"`
				RepositoryURL          string   `json:"repository_url"`
				Revision               string   `json:"revision"`
				ChainID                *int64   `json:"chain_id"`
				BlockNumber            *int64   `json:"block_number"`
				Address                string   `json:"address"`
				Protocol               string   `json:"protocol"`
				Track                  string   `json:"track"`
				MatchTest              string   `json:"match_test"`
				MatchContract          string   `json:"match_contract"`
				Record                 string   `json:"record"`
				ArtifactRoot           string   `json:"artifact_root"`
				PrimaryManifest        string   `json:"primary_manifest"`
				Verifier               string   `json:"verifier"`
				Result                 string   `json:"result"`
				Snapshot               string   `json:"snapshot"`
				VerifiedSourceResponse string   `json:"verified_source_response"`
				SourcePrefix           string   `json:"source_prefix"`
				Details                string   `json:"details"`
				EvidenceStatus         string   `json:"evidence_status"`
				Ledger                 string   `json:"ledger"`
				Selection              string   `json:"selection"`
				CardID                 string   `json:"card_id"`
				ReviewStatus           string   `json:"review_status"`
				Reason                 string   `json:"reason"`
				Actor                  string   `json:"actor"`
				Entrypoint             string   `json:"entrypoint"`
				Outcome                string   `json:"outcome"`
				Transition             string   `json:"transition"`
				Boundaries             []string `json:"boundaries"`
				Artifact               string   `json:"artifact"`
				Features               []string `json:"features"`
			}
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			const maxInput = 4096
			for _, value := range []string{in.Action, in.Project, in.RepositoryURL, in.Revision, in.Address, in.Protocol, in.Track, in.MatchTest, in.MatchContract, in.Record, in.ArtifactRoot, in.PrimaryManifest, in.Verifier, in.Result, in.Snapshot, in.VerifiedSourceResponse, in.SourcePrefix, in.Details, in.EvidenceStatus, in.Ledger, in.Selection, in.CardID, in.ReviewStatus, in.Reason, in.Actor, in.Entrypoint, in.Outcome, in.Transition, in.Artifact} {
				if len(value) > maxInput {
					return actool.Errorf("DeFi 分析参数过长"), nil
				}
			}
			if len(in.Features) > 32 {
				return actool.Errorf("DeFi 功能标签过多"), nil
			}
			if len(in.Boundaries) > 32 {
				return actool.Errorf("DeFi 边界标签过多"), nil
			}
			for _, feature := range in.Features {
				if len(feature) > 128 {
					return actool.Errorf("DeFi 功能标签过长"), nil
				}
			}
			if (in.ChainID != nil && *in.ChainID <= 0) ||
				(in.BlockNumber != nil && (*in.BlockNumber < 0 || in.ChainID == nil)) {
				return actool.Errorf("DeFi 目标上下文需要正 chain_id，且 block_number 必须为非负数并附带 chain_id"), nil
			}
			if in.Address != "" && (in.ChainID == nil || !regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`).MatchString(in.Address)) {
				return actool.Errorf("DeFi address 必须为 0x 加 40 位十六进制且附带 chain_id"), nil
			}
			var script string
			var args []string
			var producedPath string
			taskRoot := filepath.Join(dataDir, "tasks", strconv.FormatInt(taskID, 10))
			sandboxProject := taskRoot
			verifiedRunDir, err := confinedPath(taskRoot, runDir, true)
			if err != nil {
				return actool.Errorf("DeFi 运行目录不属于当前任务: " + err.Error()), nil
			}
			ledgerDir := filepath.Join(taskRoot, "defi-review")
			if err := os.MkdirAll(ledgerDir, 0o700); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			ledgerDir, err = confinedPath(taskRoot, ledgerDir, true)
			if err != nil {
				return actool.Errorf("DeFi 台账目录不属于当前任务: " + err.Error()), nil
			}
			sharedLedger := filepath.Join(ledgerDir, "ledger.json")
			outDir := filepath.Join(verifiedRunDir, "defi-analysis")
			if err := os.MkdirAll(outDir, 0o700); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			outDir, err = confinedPath(verifiedRunDir, outDir, true)
			if err != nil {
				return actool.Errorf("DeFi 工件目录不属于当前运行: " + err.Error()), nil
			}
			switch in.Action {
			case "repository-clone":
				if in.RepositoryURL == "" {
					return actool.Errorf("repository-clone 需要 repository_url"), nil
				}
				project, commit, err := cloneDeFiRepository(ctx, as, taskID, taskRoot, in.RepositoryURL, in.Revision)
				if err != nil {
					return actool.Errorf("repository-clone: " + err.Error()), nil
				}
				return actool.Text(fmt.Sprintf("repository checkout: %s\ncommit: %s\nsubmodules: not fetched", project, commit)), nil
			case "verified-source-fetch":
				if in.ChainID == nil || in.Address == "" {
					return actool.Errorf("verified-source-fetch 需要 chain_id 和 address"), nil
				}
				if err := deFiScopedContract(as, taskID, *in.ChainID, in.Address); err != nil {
					return actool.Errorf("verified-source-fetch: " + err.Error()), nil
				}
				fetchCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
				defer cancel()
				responsePath, sum, err := fetchDeFiVerifiedSource(fetchCtx, *in.ChainID, in.Address, outDir, nil)
				if err != nil {
					return actool.Errorf("verified-source-fetch: " + err.Error()), nil
				}
				return actool.Text(fmt.Sprintf("verified source response: %s#sha256=%s\nsource files: %s", responsePath, sum, filepath.Join(filepath.Dir(responsePath), "sources"))), nil
			case "deployment-snapshot":
				if in.ChainID == nil || in.BlockNumber == nil || in.Address == "" {
					return actool.Errorf("deployment-snapshot 需要 chain_id、block_number 和 address"), nil
				}
				if err := deFiScopedContract(as, taskID, *in.ChainID, in.Address); err != nil {
					return actool.Errorf("deployment-snapshot: " + err.Error()), nil
				}
				if os.Getenv("RPC_URL") == "" {
					return actool.Errorf("deployment-snapshot 需要已配置的 RPC_URL"), nil
				}
				rpcCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
				defer cancel()
				snapshot, err := readDeFiDeploymentSnapshot(rpcCtx, os.Getenv("RPC_URL"), nil, *in.ChainID, *in.BlockNumber, in.Address)
				if err != nil {
					return actool.Errorf("deployment-snapshot: " + err.Error()), nil
				}
				output := filepath.Join(outDir, "deployment-"+uuid.NewString()+".json")
				sum, err := writeDeFiDeploymentSnapshot(output, snapshot)
				if err != nil {
					return actool.Errorf("deployment-snapshot 工件写入失败: " + err.Error()), nil
				}
				return actool.Text(fmt.Sprintf("read-only deployment snapshot: %s#sha256=%s", output, sum)), nil
			case "manifest", "forge-build", "forge-test", "forge-replay", "slither", "halmos", "inventory":
				project, err := confinedPath(taskRoot, in.Project, true)
				if err != nil {
					return actool.Errorf("project: " + err.Error()), nil
				}
				if rel, err := filepath.Rel(project, outDir); err == nil &&
					(rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
					return actool.Errorf("project 必须是独立源码目录，不能包含本次分析工件目录"), nil
				}
				sandboxProject = project
				if in.Action == "inventory" {
					script = "inventory.py"
					producedPath = filepath.Join(outDir, "inventory.json")
					args = []string{project, "--output", producedPath}
				} else {
					script = "run_analysis.py"
					verb := "run"
					if in.Action == "manifest" {
						verb = "manifest"
					}
					args = []string{verb, "--project", project, "--output-dir", outDir}
					if in.ChainID != nil {
						args = append(args, "--chain-id", strconv.FormatInt(*in.ChainID, 10))
					}
					if in.BlockNumber != nil {
						args = append(args, "--block-number", strconv.FormatInt(*in.BlockNumber, 10))
					}
					if in.Address != "" {
						args = append(args, "--address", in.Address)
					}
					if verb == "run" {
						requested := in.Action
						if requested == "forge-replay" {
							requested = "forge-test"
						}
						args = append(args, requested)
						args = append(args, "--timeout", "480")
					}
					if in.Action == "forge-test" || in.Action == "forge-replay" || in.Action == "halmos" {
						if in.MatchTest != "" {
							args = append(args, "--match-test", in.MatchTest)
						}
						if in.MatchContract != "" {
							args = append(args, "--match-contract", in.MatchContract)
						}
						if in.Action == "forge-replay" {
							taskRoot := filepath.Join(dataDir, "tasks", strconv.FormatInt(taskID, 10))
							manifest, err := confinedPath(taskRoot, in.PrimaryManifest, false)
							if err != nil || filepath.Base(manifest) != "manifest.json" {
								return actool.Errorf("forge-replay 需要本任务中的 primary_manifest"), nil
							}
							if !regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`).MatchString(in.Verifier) {
								return actool.Errorf("forge-replay 需要简短的 verifier 标识"), nil
							}
							args = append(args, "--reuse-manifest", manifest, "--independent-verifier", in.Verifier)
						}
					}
				}
			case "catalog-tags":
				script = "catalog.py"
				args = []string{"tags"}
			case "catalog-select":
				script = "catalog.py"
				track := in.Track
				if track == "" {
					track = "evm"
				}
				if in.Protocol == "" {
					return actool.Errorf("catalog-select 需要 protocol"), nil
				}
				producedPath = filepath.Join(outDir, "selection-"+time.Now().UTC().Format("20060102T150405.000000000")+".json")
				args = []string{"select", "--track", track, "--protocol", in.Protocol, "--format", "json", "--output", producedPath}
				for _, feature := range in.Features {
					args = append(args, "--feature", feature)
				}
			case "evidence-validate":
				script = "evidence.py"
				taskRoot := filepath.Join(dataDir, "tasks", strconv.FormatInt(taskID, 10))
				record, err := confinedPath(taskRoot, in.Record, false)
				if err != nil {
					return actool.Errorf("record: " + err.Error()), nil
				}
				root, err := confinedPath(taskRoot, in.ArtifactRoot, true)
				if err != nil {
					return actool.Errorf("artifact_root: " + err.Error()), nil
				}
				args = []string{"validate", record, "--artifact-root", root}
			case "evidence-from-run":
				script = "evidence.py"
				taskRoot := filepath.Join(dataDir, "tasks", strconv.FormatInt(taskID, 10))
				result, err := confinedPath(taskRoot, in.Result, false)
				if err != nil || filepath.Base(result) != "result.json" {
					return actool.Errorf("evidence-from-run 需要本任务中的 result.json"), nil
				}
				status := in.EvidenceStatus
				if status == "" {
					status = "hypothesis"
				}
				if status != "hypothesis" && status != "reproduced" {
					return actool.Errorf("evidence-from-run 只可创建 hypothesis 或 reproduced 草稿"), nil
				}
				producedPath = filepath.Join(outDir, "draft-"+time.Now().UTC().Format("20060102T150405.000000000")+".json")
				args = []string{"from-run", result, "--status", status, "--output", producedPath}
				if status == "reproduced" {
					details, err := confinedPath(taskRoot, in.Details, false)
					if err != nil {
						return actool.Errorf("reproduced 草稿需要本任务中的 details JSON"), nil
					}
					args = append(args, "--details", details)
				}
			case "deployment-bind":
				script = "deployment_bind.py"
				result, err := confinedPath(taskRoot, in.Result, false)
				if err != nil || filepath.Base(result) != "result.json" {
					return actool.Errorf("deployment-bind 需要本任务中的 result.json"), nil
				}
				snapshot, err := confinedPath(taskRoot, in.Snapshot, false)
				if err != nil {
					return actool.Errorf("deployment-bind 需要本任务中的 snapshot JSON"), nil
				}
				response, err := confinedPath(taskRoot, in.VerifiedSourceResponse, false)
				if err != nil {
					return actool.Errorf("deployment-bind 需要本任务中的 Sourcify 响应 JSON"), nil
				}
				producedPath = filepath.Join(filepath.Dir(result), "deployment_binding.json")
				args = []string{"--result", result, "--snapshot", snapshot, "--sourcify-response", response,
					"--output", producedPath, "--source-prefix", in.SourcePrefix}
			case "ledger":
				script = "evidence.py"
				taskRoot := filepath.Join(dataDir, "tasks", strconv.FormatInt(taskID, 10))
				ledger, err := confinedPath(taskRoot, in.Ledger, false)
				if err != nil {
					return actool.Errorf("ledger 需要本任务中的经济账本 JSON"), nil
				}
				root, err := confinedPath(taskRoot, in.ArtifactRoot, true)
				if err != nil {
					return actool.Errorf("ledger 需要本任务中的 artifact_root"), nil
				}
				args = []string{"ledger", ledger, "--artifact-root", root}
			case "ledger-init":
				script = "review_ledger.py"
				selection, err := confinedPath(taskRoot, in.Selection, false)
				if err != nil {
					return actool.Errorf("ledger-init 需要本任务中的 selection JSON"), nil
				}
				if err := os.MkdirAll(filepath.Dir(sharedLedger), 0o700); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				args = []string{"init", "--selection", selection, "--output", sharedLedger}
				producedPath = sharedLedger
			case "ledger-status":
				script = "review_ledger.py"
				if in.CardID == "" || in.ReviewStatus == "" {
					return actool.Errorf("ledger-status 需要 card_id 和 review_status"), nil
				}
				args = []string{"status", "--ledger", sharedLedger, "--id", in.CardID, "--status", in.ReviewStatus, "--reason", in.Reason}
				var root string
				if in.Artifact != "" || in.ReviewStatus == "reproduced" || in.ReviewStatus == "confirmed" {
					var err error
					root, err = confinedPath(taskRoot, in.ArtifactRoot, true)
					if err != nil {
						return actool.Errorf("ledger-status 需要本任务中的 artifact_root"), nil
					}
					args = append(args, "--artifact-root", root)
				}
				if in.Artifact != "" {
					artifact, err := hashedArtifactReference(root, in.Artifact)
					if err != nil {
						return actool.Errorf("artifact 必须属于 artifact_root 且可读取"), nil
					}
					args = append(args, "--artifact", artifact)
				}
				if in.ReviewStatus == "reproduced" || in.ReviewStatus == "confirmed" {
					record, err := confinedPath(taskRoot, in.Record, false)
					if err != nil {
						return actool.Errorf("升级状态需要本任务中的 record"), nil
					}
					args = append(args, "--record", record)
				}
				producedPath = sharedLedger
			case "ledger-cover":
				script = "review_ledger.py"
				if in.CardID == "" || in.Actor == "" || in.Entrypoint == "" || in.Outcome == "" {
					return actool.Errorf("ledger-cover 需要 card_id、actor、entrypoint 和 outcome"), nil
				}
				root, err := confinedPath(taskRoot, in.ArtifactRoot, true)
				if err != nil {
					return actool.Errorf("ledger-cover 需要本任务中的 artifact_root"), nil
				}
				artifact, err := hashedArtifactReference(root, in.Artifact)
				if err != nil {
					return actool.Errorf("ledger-cover 需要 artifact_root 内可读取的 artifact"), nil
				}
				args = []string{"cover", "--ledger", sharedLedger, "--id", in.CardID, "--actor", in.Actor, "--entrypoint", in.Entrypoint, "--outcome", in.Outcome, "--transition", in.Transition, "--artifact-root", root, "--artifact", artifact}
				for _, boundary := range in.Boundaries {
					args = append(args, "--boundary", boundary)
				}
				producedPath = sharedLedger
			case "ledger-show":
				script = "review_ledger.py"
				args = []string{"show", "--ledger", sharedLedger, "--format", "text"}
			default:
				return actool.Errorf("不支持的 DeFi 分析动作"), nil
			}
			path := filepath.Join(skillDir, "defi-audit", "scripts", script)
			if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
				return actool.Errorf("DeFi 分析脚本不可用: " + script), nil
			}
			commandArgs, err := deFiSandboxCommand(filepath.Dir(path), sandboxProject, outDir, path, args...)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			timeout := 10 * time.Minute
			if in.Action == "catalog-tags" || in.Action == "catalog-select" || in.Action == "evidence-from-run" || in.Action == "evidence-validate" || in.Action == "ledger" || strings.HasPrefix(in.Action, "ledger-") {
				timeout = time.Minute
			}
			if in.Action == "inventory" {
				timeout = 3 * time.Minute
			}
			callCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			cmd := exec.CommandContext(callCtx, "python3", commandArgs...)
			configureDeFiProcessGroup(cmd)
			cmd.Dir = verifiedRunDir
			cmd.Env = defiToolEnvironment()
			var stdout, stderr limitedToolBuffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err = cmd.Run()
			if callCtx.Err() != nil {
				killDeFiProcessGroup(cmd)
				return actool.Errorf("DeFi 分析超时或任务已取消；本次覆盖记为 blocked"), nil
			}
			if stdout.truncated || stderr.truncated {
				return actool.Errorf("DeFi 分析工具输出过大；本次覆盖记为 blocked，请检查工件"), nil
			}
			output := strings.TrimSpace(stdout.String())
			if err != nil {
				return actool.Errorf(fmt.Sprintf("DeFi 分析未完成: %v；输出: %s；错误: %s", err, output, stderr.String())), nil
			}
			if output == "" {
				output = "分析完成；请检查工作目录中的工件"
			}
			if producedPath != "" {
				output += "\n工件: " + producedPath
			}
			return actool.Text(output), nil
		})
}

func deFiSandboxCommand(scriptDir, project, output, script string, args ...string) ([]string, error) {
	sandboxPath := filepath.Join(scriptDir, "sandbox_exec.py")
	info, err := os.Stat(sandboxPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, fmt.Errorf("DeFi 分析沙箱不可用")
	}
	file, err := os.Open(sandboxPath)
	if err != nil {
		return nil, fmt.Errorf("DeFi 分析沙箱不可用: %w", err)
	}
	source, readErr := io.ReadAll(io.LimitReader(file, 64<<10+1))
	_ = file.Close()
	if readErr != nil || len(source) > 64<<10 || fmt.Sprintf("%x", sha256.Sum256(source)) != defiSandboxSHA256 {
		return nil, fmt.Errorf("DeFi 分析沙箱内容与内置版本不一致")
	}
	return append([]string{"-I", "-c", string(source), "--project", project,
		"--output-dir", output, "--script", script, "--trusted-scripts", scriptDir, "--"}, args...), nil
}

func hashedArtifactReference(root, candidate string) (string, error) {
	path, err := confinedPath(root, candidate, false)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("artifact escapes root")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s#sha256=%x", filepath.ToSlash(rel), h.Sum(nil)), nil
}

// confinedPath resolves existing paths and rejects symlink escapes from the
// allowed data root. Writes are always generated by the tool inside runDir.
func confinedPath(root, candidate string, directory bool) (string, error) {
	if strings.TrimSpace(candidate) == "" {
		return "", fmt.Errorf("路径不能为空")
	}
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	path, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("路径超出任务数据目录")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return "", fmt.Errorf("路径类型不正确")
	}
	return path, nil
}

func defiToolEnvironment() []string {
	allowed := map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "USER": true, "LANG": true, "LC_ALL": true, "PYENV_VERSION": true,
		"FOUNDRY_PROFILE": true, "FOUNDRY_SOLC": true, "SOLC_VERSION": true, "SOLC_BIN": true, "XDG_CACHE_HOME": true, "XDG_CONFIG_HOME": true}
	var out []string
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if allowed[key] {
			out = append(out, item)
		}
	}
	return out
}

type limitedToolBuffer struct {
	bytes.Buffer
	truncated bool
}

func (b *limitedToolBuffer) Write(p []byte) (int, error) {
	const limit = 64 << 10
	if b.Len() >= limit {
		b.truncated = true
		return len(p), nil
	}
	keep := len(p)
	if keep > limit-b.Len() {
		keep = limit - b.Len()
		b.truncated = true
	}
	_, _ = b.Buffer.Write(p[:keep])
	return len(p), nil
}
