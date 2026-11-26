package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The fixed DeFi actions fail closed unless the Linux Landlock launcher is
// available. Tests that exercise the real launcher are therefore Linux-only;
// keep the fail-closed assertion in TestDeFiAnalysisRequiresSandboxForAllActions
// running everywhere.
func requireDeFiLandlock(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("DeFi analyzer sandbox requires Linux Landlock")
	}
}

// The halmos action must be advertised and must build the expected run_analysis.py
// invocation (run ... halmos ... --match-test/--match-contract passed through). A
// stub runner echoes its argv so the Go-built command is asserted without needing
// a real halmos/solver.
func TestDeFiAnalysisHalmosActionBuildsRunnerInvocation(t *testing.T) {
	requireDeFiLandlock(t)
	skill := t.TempDir()
	scripts := filepath.Join(skill, "defi-audit", "scripts")
	if err := os.MkdirAll(scripts, 0o700); err != nil {
		t.Fatal(err)
	}
	stub := "import sys, json\nprint(json.dumps(sys.argv[1:]))\n"
	if err := os.WriteFile(filepath.Join(scripts, "run_analysis.py"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	sandbox, err := os.ReadFile(filepath.Join("..", "skills", "defi-audit", "scripts", "sandbox_exec.py"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scripts, "sandbox_exec.py"), sandbox, 0o700); err != nil {
		t.Fatal(err)
	}

	data := t.TempDir()
	run := filepath.Join(data, "tasks", "1", "i1")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(data, "tasks", "1", "proj"), 0o700); err != nil {
		t.Fatal(err)
	}

	tool := newDeFiAnalysisTool(skill, data, run, 1, nil)
	if raw, err := json.Marshal(tool.InputSchema()); err != nil || !strings.Contains(string(raw), "halmos") {
		t.Fatalf("halmos not advertised in schema (err=%v): %s", err, raw)
	}

	res, err := tool.Call(context.Background(),
		json.RawMessage(`{"action":"halmos","project":"proj","match_test":"check_bug","match_contract":"PropC","chain_id":1,"block_number":123,"address":"0x1111111111111111111111111111111111111111"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := res.Flatten()
	for _, want := range []string{"run", "halmos", "--match-test", "check_bug", "--match-contract", "PropC", "--timeout", "480", "--chain-id", "--block-number", "123", "--address", "0x1111111111111111111111111111111111111111"} {
		if !strings.Contains(out, want) {
			t.Errorf("runner invocation missing %q in: %s", want, out)
		}
	}
}

func TestDeFiAnalysisRejectsModifiedSandboxSource(t *testing.T) {
	skill := t.TempDir()
	scripts := filepath.Join(skill, "defi-audit", "scripts")
	if err := os.MkdirAll(scripts, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{"run_analysis.py", "sandbox_exec.py"} {
		if err := os.WriteFile(filepath.Join(scripts, script), []byte("print('modified')\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	data := t.TempDir()
	run := filepath.Join(data, "tasks", "1", "i1")
	project := filepath.Join(data, "tasks", "1", "proj")
	for _, dir := range []string{run, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tool := newDeFiAnalysisTool(skill, data, run, 1, nil)
	result, err := tool.Call(context.Background(), json.RawMessage(`{"action":"manifest","project":"proj"}`), nil)
	if err != nil || !strings.Contains(result.Flatten(), "内容与内置版本不一致") {
		t.Fatalf("modified sandbox source accepted: %v, %s", err, result.Flatten())
	}
}

func TestDeFiAnalysisRequiresSandboxForAllActions(t *testing.T) {
	skill := t.TempDir()
	scripts := filepath.Join(skill, "defi-audit", "scripts")
	if err := os.MkdirAll(scripts, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scripts, "run_analysis.py"), []byte("print('unsafe')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scripts, "catalog.py"), []byte("print('unsafe')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	run := filepath.Join(data, "tasks", "1", "i1")
	project := filepath.Join(data, "tasks", "1", "proj")
	for _, dir := range []string{run, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tool := newDeFiAnalysisTool(skill, data, run, 1, nil)
	for _, input := range []json.RawMessage{
		json.RawMessage(`{"action":"manifest","project":"proj"}`),
		json.RawMessage(`{"action":"catalog-tags"}`),
	} {
		result, err := tool.Call(context.Background(), input, nil)
		if err != nil || !strings.Contains(result.Flatten(), "沙箱不可用") {
			t.Fatalf("analysis executed without sandbox: %v, %s", err, result.Flatten())
		}
	}
}

func TestDeFiAnalysisRejectsIncompleteChainContext(t *testing.T) {
	data := t.TempDir()
	run := filepath.Join(data, "tasks", "1", "i1")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	tool := newDeFiAnalysisTool(t.TempDir(), data, run, 1, nil)
	for _, check := range []struct{ input, want string }{
		{`{"action":"manifest","block_number":1}`, "目标上下文"},
		{`{"action":"manifest","chain_id":0}`, "目标上下文"},
		{`{"action":"manifest","chain_id":1,"address":"0x123"}`, "address"},
	} {
		result, err := tool.Call(context.Background(), json.RawMessage(check.input), nil)
		if err != nil || !strings.Contains(result.Flatten(), check.want) {
			t.Errorf("invalid chain context accepted: %s, %v, %s", check.input, err, result.Flatten())
		}
	}
}

func TestDeFiAnalysisSnapshotRequiresTaskScopeBeforeRPC(t *testing.T) {
	data := t.TempDir()
	run := filepath.Join(data, "tasks", "1", "i1")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	tool := newDeFiAnalysisTool(t.TempDir(), data, run, 1, nil)
	result, err := tool.Call(context.Background(), json.RawMessage(`{"action":"deployment-snapshot","chain_id":1,"block_number":100,"address":"0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}`), nil)
	if err != nil || !strings.Contains(result.Flatten(), "scope is unavailable") {
		t.Fatalf("unscoped RPC snapshot was accepted: %v, %s", err, result.Flatten())
	}
	result, err = tool.Call(context.Background(), json.RawMessage(`{"action":"verified-source-fetch","chain_id":1,"address":"0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}`), nil)
	if err != nil || !strings.Contains(result.Flatten(), "scope is unavailable") {
		t.Fatalf("unscoped verified-source fetch was accepted: %v, %s", err, result.Flatten())
	}
}

func TestDeFiAnalysisDeploymentBindUsesTaskArtifacts(t *testing.T) {
	requireDeFiLandlock(t)
	skill := t.TempDir()
	scripts := filepath.Join(skill, "defi-audit", "scripts")
	if err := os.MkdirAll(scripts, 0o700); err != nil {
		t.Fatal(err)
	}
	sandbox, err := os.ReadFile(filepath.Join("..", "skills", "defi-audit", "scripts", "sandbox_exec.py"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scripts, "sandbox_exec.py"), sandbox, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scripts, "deployment_bind.py"), []byte("import sys, json\nprint(json.dumps(sys.argv[1:]))\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	run := filepath.Join(data, "tasks", "1", "i1")
	resultDir := filepath.Join(run, "defi-analysis", "run-1")
	if err := os.MkdirAll(resultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(resultDir, "result.json"), filepath.Join(run, "snapshot.json"), filepath.Join(run, "source.json")} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tool := newDeFiAnalysisTool(skill, data, run, 1, nil)
	input, err := json.Marshal(map[string]string{
		"action": "deployment-bind", "result": filepath.Join(resultDir, "result.json"),
		"snapshot":                 filepath.Join(run, "snapshot.json"),
		"verified_source_response": filepath.Join(run, "source.json"),
		"source_prefix":            "src",
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := tool.Call(context.Background(), input, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--result", "--snapshot", "--sourcify-response", "--source-prefix", "src", filepath.Join(resultDir, "deployment_binding.json")} {
		if !strings.Contains(response.Flatten(), want) {
			t.Errorf("deployment binding invocation missing %q: %s", want, response.Flatten())
		}
	}
}

func TestDeFiAnalysisRejectsProjectFromAnotherTask(t *testing.T) {
	data := t.TempDir()
	for _, task := range []string{"1", "2"} {
		if err := os.MkdirAll(filepath.Join(data, "tasks", task, "proj"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	run := filepath.Join(data, "tasks", "1", "i1")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	tool := newDeFiAnalysisTool(t.TempDir(), data, run, 1, nil)
	otherProject := filepath.Join(data, "tasks", "2", "proj")
	for _, project := range []string{otherProject, "../2/proj"} {
		input, err := json.Marshal(map[string]string{"action": "manifest", "project": project})
		if err != nil {
			t.Fatal(err)
		}
		result, err := tool.Call(context.Background(), input, nil)
		if err != nil || !strings.Contains(result.Flatten(), "project:") {
			t.Errorf("other task's project was accepted: %s, %v, %s", project, err, result.Flatten())
		}
	}
}

func TestDeFiAnalysisRejectsProjectContainingOutput(t *testing.T) {
	data := t.TempDir()
	taskRoot := filepath.Join(data, "tasks", "1")
	run := filepath.Join(taskRoot, "i1")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	tool := newDeFiAnalysisTool(t.TempDir(), data, run, 1, nil)
	for _, project := range []string{taskRoot, run} {
		input, err := json.Marshal(map[string]string{"action": "manifest", "project": project})
		if err != nil {
			t.Fatal(err)
		}
		result, err := tool.Call(context.Background(), input, nil)
		if err != nil || !strings.Contains(result.Flatten(), "独立源码目录") {
			t.Fatalf("project containing artifacts accepted: %s, %v, %s", project, err, result.Flatten())
		}
	}
}

func TestDeFiAnalysisRejectsRunDirectorySymlinkEscape(t *testing.T) {
	data := t.TempDir()
	other := filepath.Join(data, "tasks", "2", "i2")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	currentTask := filepath.Join(data, "tasks", "1")
	if err := os.MkdirAll(currentTask, 0o700); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(currentTask, "i1")
	if err := os.Symlink(other, run); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	tool := newDeFiAnalysisTool(t.TempDir(), data, run, 1, nil)
	result, err := tool.Call(context.Background(), json.RawMessage(`{"action":"catalog-tags"}`), nil)
	if err != nil || !strings.Contains(result.Flatten(), "运行目录不属于当前任务") {
		t.Fatalf("run directory symlink escape accepted: %v, %s", err, result.Flatten())
	}
}
