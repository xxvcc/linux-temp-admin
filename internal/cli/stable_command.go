package cli

import (
	"errors"
	"fmt"
	"github.com/xxvcc/linux-temp-admin/internal/buildinfo"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
	"github.com/xxvcc/linux-temp-admin/internal/version"
	"strings"
)

// ensureStableInstalled makes sure the binary at InstallPath can actually carry
// out the auto-revoke this invite is about to schedule.
//
// The scheduled task executes whatever sits at InstallPath — not this process.
// So a binary OLDER than this one is not merely stale, it is a binary that does
// not know about everything this invite created: an older revoke deletes the
// account and its registry row while leaving this version's sshd exception
// behind forever, with the row that would have named it now gone. That is the
// default upgrade path (a host still carrying the previous release, an operator
// running a freshly built binary from their home directory), so it is not an
// edge case.
//
// An older binary is therefore replaced by this one. A newer or equal one is
// left alone. An installed command that cannot be safely identified aborts the
// invite, because executing or overwriting an untrusted root path is unsafe.
func (a *App) ensureStableInstalled() error {
	if a.Selfmanage == nil {
		return fmt.Errorf("self-manager not configured")
	}
	force := false
	installed, versionErr := a.Selfmanage.InstalledVersion()
	// A readable version means a command is already at InstallPath; only then can
	// a write displace something.
	hadInstalledBinary := versionErr == nil
	if versionErr == nil {
		if strings.HasSuffix(buildinfo.Version, "-dev") {
			// A development build is not ordered against releases. Install these exact
			// bytes so its scheduled cleanup always runs the code creating the account.
			//
			// Say so. This replaces the signed release at a shared root path that every
			// other account's auto-revoke timer already points at, and it used to happen
			// with no line on screen and no audit record.
			a.warnf("%s", fmt.Sprintf(a.P.M(
				"当前运行的是开发构建 %s，将用它覆盖已安装的 %s（路径 %s）：该路径上的稳定命令由其他账号的自动撤销任务共用。",
				"this is development build %s and it will replace the installed %s at %s: that stable command is shared by every other account's auto-revoke task."),
				buildinfo.Version, installed, a.InstallPath))
			force = true
		} else if !version.Greater(buildinfo.Version, installed) {
			return nil
		} else {
			a.info(fmt.Sprintf(a.P.M("已安装的稳定命令较旧（%s → %s）；自动删除任务由它执行，故一并升级。",
				"the installed stable command is older (%s -> %s); the auto-delete task runs it, so it is upgraded too."),
				installed, buildinfo.Version))
			force = true
		}
	} else if !errors.Is(versionErr, selfmanage.ErrNotInstalled) {
		return versionErr
	}
	bin, err := a.readRunningBinary()
	if err != nil {
		return err
	}
	replaced, err := a.Selfmanage.Install(bin, force)
	if replaced && hadInstalledBinary {
		a.stableCommandReplaced = true
	}
	if err != nil {
		if replaced {
			action := "installed"
			if hadInstalledBinary {
				action = "replaced"
			}
			err = fmt.Errorf("stable command %s but durability unknown: %w", action, err)
			a.audit("install", "", "fail", err.Error(), nil)
		}
		return err
	}
	if replaced {
		// A prior command's inode has been replaced, including a metadata repair.
		// A first installation has no previous command to restore on rollback.
		if hadInstalledBinary {
			a.audit("install", "", "ok", fmt.Sprintf("stable command replaced with %s while preparing an account action", buildinfo.Version), nil)
		} else {
			a.audit("install", "", "ok", fmt.Sprintf("stable command installed at %s while preparing an account action", buildinfo.Version), nil)
		}
	}
	installed, err = a.Selfmanage.InstalledVersion()
	if err != nil {
		return fmt.Errorf("verify installed command version: %w", err)
	}
	if installed != buildinfo.Version {
		return fmt.Errorf("installed command reports %s, want %s", installed, buildinfo.Version)
	}
	return nil
}
