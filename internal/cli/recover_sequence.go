package cli

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/user"
	"github.com/xxvcc/linux-temp-admin/internal/validate"
)

type identitySequenceHighWaterFlag struct {
	set   bool
	text  string
	value int
}

func (f *identitySequenceHighWaterFlag) String() string { return f.text }

func (f *identitySequenceHighWaterFlag) Set(value string) error {
	if f.set {
		return fmt.Errorf("--highest may be specified only once")
	}
	f.set = true
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return fmt.Errorf("--highest must be a canonical decimal Linux ID")
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return fmt.Errorf("--highest must be a canonical decimal Linux ID")
		}
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || !validate.KernelID(parsed) {
		return fmt.Errorf("--highest is outside the usable Linux ID range")
	}
	f.text = value
	f.value = parsed
	return nil
}

type identitySequenceRecoveryPlan struct {
	recordsHash       [32]byte
	registryHighest   int
	allocation        user.IdentityAllocationSnapshot
	observedFloor     int
	earliestSafeAfter time.Time
}

func identitySequenceRecoverySafeAfter(now time.Time) time.Time {
	target := now.UTC().Add(time.Duration(config.IdentityQuarantineSeconds) * time.Second)
	if target.Nanosecond() == 0 {
		return target
	}
	return target.Truncate(time.Second).Add(time.Second)
}

func (p identitySequenceRecoveryPlan) sameState(other identitySequenceRecoveryPlan) bool {
	return p.recordsHash == other.recordsHash &&
		p.registryHighest == other.registryHighest &&
		p.allocation == other.allocation && p.observedFloor == other.observedFloor
}

func (a *App) planIdentitySequenceRecovery(highWater int) (identitySequenceRecoveryPlan, error) {
	if a.Registry == nil {
		return identitySequenceRecoveryPlan{}, fmt.Errorf("registry is not configured")
	}
	integrityErr := a.Registry.CheckIntegrity()
	if integrityErr == nil {
		return identitySequenceRecoveryPlan{}, fmt.Errorf("identity sequence is not missing; refusing recovery")
	}
	if !errors.Is(integrityErr, registry.ErrIdentitySequenceMissing) {
		return identitySequenceRecoveryPlan{}, fmt.Errorf("registry state is not eligible for missing-sequence recovery: %w", integrityErr)
	}
	recs, err := a.Registry.List()
	if err != nil {
		return identitySequenceRecoveryPlan{}, fmt.Errorf("read registry recovery state: %w", err)
	}
	allocation, err := a.inspectIdentityAllocation()
	if err != nil {
		return identitySequenceRecoveryPlan{}, fmt.Errorf("inspect local UID/GID allocation state: %w", err)
	}
	plan := identitySequenceRecoveryPlan{allocation: allocation}
	h := sha256.New()
	for _, rec := range recs {
		_, _ = h.Write([]byte(rec.TSV()))
		_, _ = h.Write([]byte{0})
		if rec.UID > plan.registryHighest {
			plan.registryHighest = rec.UID
		}
	}
	copy(plan.recordsHash[:], h.Sum(nil))
	plan.observedFloor = plan.registryHighest
	if allocation.CurrentHighest > plan.observedFloor {
		plan.observedFloor = allocation.CurrentHighest
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	plan.earliestSafeAfter = identitySequenceRecoverySafeAfter(now)
	if highWater < plan.observedFloor {
		return identitySequenceRecoveryPlan{}, fmt.Errorf(
			"requested high-water mark %d is below the observed minimum %d", highWater, plan.observedFloor)
	}
	return plan, nil
}

func identitySequenceRecoveryFields(plan identitySequenceRecoveryPlan, highest int, safeAfter time.Time) map[string]string {
	return map[string]string{
		"highest":            strconv.Itoa(highest),
		"observed_floor":     strconv.Itoa(plan.observedFloor),
		"registry_highest":   strconv.Itoa(plan.registryHighest),
		"local_highest":      strconv.Itoa(plan.allocation.CurrentHighest),
		"allocation_lower":   strconv.Itoa(plan.allocation.Lower),
		"allocation_maximum": strconv.Itoa(plan.allocation.Upper),
		"safe_after":         safeAfter.UTC().Format(time.RFC3339),
	}
}

func (a *App) recoverIdentitySequence(args []string) int {
	if !a.requireRoot() {
		return 1
	}
	fs := flag.NewFlagSet("recover-identity-sequence", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	var highest identitySequenceHighWaterFlag
	fs.Var(&highest, "highest", "")
	if !a.parseFlags(fs, args) {
		return 1
	}
	if !highest.set {
		a.errorf("%s", a.P.M("必须提供 --highest <历史最高 ID>",
			"--highest <historical-highest-ID> is required"))
		return 1
	}
	if a.StdinIsTTY == nil || !a.StdinIsTTY() {
		a.errorf("%s", a.P.M("身份序列恢复只能在真实交互终端中执行；管道输入和自动任务均被拒绝。",
			"identity-sequence recovery requires a real interactive terminal; piped input and automatic jobs are refused."))
		return 1
	}

	plan, err := a.planIdentitySequenceRecovery(highest.value)
	if err != nil {
		a.errorf("%s: %v", a.P.M("无法制定身份序列恢复计划", "cannot plan identity-sequence recovery"), err)
		return 1
	}
	a.warnf("%s", a.P.M(
		"现存登记和账号数据库无法证明已删除账号或失败创建曾预留的历史最高 UID/GID；只有从可信历史独立确认该值后才能继续。不要猜测，也不要手工创建 identity-sequence 文件。",
		"the surviving registry and account databases cannot prove the highest UID/GID reserved by deleted accounts or failed creations. Continue only with an independently established value from trusted history; do not guess or create identity-sequence by hand."))
	a.printf("  registry-highest=%d", plan.registryHighest)
	a.printf("  local-allocation=%d..%d local-highest=%d", plan.allocation.Lower, plan.allocation.Upper, plan.allocation.CurrentHighest)
	a.printf("  observed-floor=%d requested-highest=%d", plan.observedFloor, highest.value)
	a.printf("  safe-after-at-least=%s", plan.earliestSafeAfter.Format(time.RFC3339))
	if highest.value >= plan.allocation.Upper {
		a.warnf("%s", a.P.M(
			"给定高水位已达到或超过当前分配上限；恢复会保留安全历史，但后续邀请会因 UID/GID 范围耗尽而失败，直到管理员扩大策略范围。",
			"the supplied high-water mark reaches or exceeds the current allocation maximum. Recovery preserves the safety history, but later invites will fail as exhausted until an administrator expands the policy range."))
	}
	confirmation := "RECOVER IDENTITY-SEQUENCE HIGHEST=" + highest.text
	if a.prompt(fmt.Sprintf(a.P.M("请输入 %s 以确认恢复: ", "Type %s to confirm recovery: "), confirmation)) != confirmation {
		a.info(a.P.M("已取消；未修改身份序列。", "cancelled; the identity sequence was not changed."))
		return 0
	}

	return a.withLifecycleLock(func() int {
		current, err := a.planIdentitySequenceRecovery(highest.value)
		if err != nil {
			a.errorf("%s: %v", a.P.M("确认后恢复条件已失效", "recovery conditions changed after confirmation"), err)
			a.audit("registry.identity-sequence.recover", "", "fail", err.Error(), nil)
			return 1
		}
		if !plan.sameState(current) {
			err := fmt.Errorf("registry or local UID/GID allocation state changed; rerun and confirm the new plan")
			a.errorf("%s", a.P.M("确认后登记或本地 UID/GID 分配状态发生变化；请重新运行并确认新计划。", err.Error()))
			a.audit("registry.identity-sequence.recover", "", "fail", err.Error(),
				identitySequenceRecoveryFields(current, highest.value, current.earliestSafeAfter))
			return 1
		}
		info, err := a.Registry.RepairMissingIdentitySequence(highest.value)
		if err != nil {
			a.errorf("%s: %v", a.P.M("恢复身份序列失败", "identity-sequence recovery failed"), err)
			a.audit("registry.identity-sequence.recover", "", "fail", err.Error(),
				identitySequenceRecoveryFields(current, highest.value, current.earliestSafeAfter))
			return 1
		}
		fields := identitySequenceRecoveryFields(current, info.Highest, info.SafeAfter)
		a.audit("registry.identity-sequence.recover", "", "ok", "missing identity sequence recovered", fields)
		a.success(fmt.Sprintf(a.P.M(
			"身份序列已恢复：highest=%d，身份隔离安全期至 %s。",
			"identity sequence recovered: highest=%d; identity isolation remains active until %s."),
			info.Highest, info.SafeAfter.UTC().Format(time.RFC3339)))
		return 0
	})
}
