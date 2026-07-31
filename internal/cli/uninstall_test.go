package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

func TestUninstallMarkerOnlyPermanentAccountBlocksWithoutDeleteAuthority(t *testing.T) {
	const (
		name       = "lta-marker-only"
		generation = "0123456789abcdef0123456789abcdef"
	)
	a, out, errb := newTestApp(t, "")
	root := t.TempDir()
	a.StateDir = filepath.Join(root, "state")
	a.AuditLogDir = filepath.Join(root, "audit")
	registryDir := filepath.Join(a.StateDir, "v2")
	if err := os.MkdirAll(registryDir, 0o700); err != nil {
		t.Fatal(err)
	}
	a.Registry = &registry.Store{
		Dir:  registryDir,
		File: filepath.Join(registryDir, "registry.tsv"),
		Lock: filepath.Join(registryDir, "registry.lock"),
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	a.InstallPath = filepath.Join(binDir, "linux-temp-admin")
	if err := os.WriteFile(a.InstallPath, []byte("unchanged"), 0o755); err != nil {
		t.Fatal(err)
	}

	pw := user.Passwd{
		Name: name, UID: 2001, GID: 2001,
		GECOS: config.ManagedGenerationGECOSPrefix + generation,
		Home:  "/home/" + name, Shell: "/bin/sh",
	}
	a.ListMarkerAccounts = func() ([]string, error) { return []string{name}, nil }
	a.LookupUser = func(got string) (user.Passwd, bool, error) {
		if got != name {
			t.Fatalf("passwd lookup = %q, want %q", got, name)
		}
		return pw, true, nil
	}

	result := a.uninstallResult([]string{"--yes", "--remove-users", "--force"})
	if result.status != 1 || result.applied {
		t.Fatalf("uninstall result = %+v, want an unapplied marker-only refusal", result)
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Fatalf("installed command changed despite the block-only witness: %v", err)
	}
	if _, err := os.Stat(a.StateDir); err != nil {
		t.Fatalf("state changed despite the block-only witness: %v", err)
	}
	if found, err := a.Registry.Contains(name); err != nil || found {
		t.Fatalf("fixture unexpectedly gained deletion authority: found=%v err=%v", found, err)
	}
	if got := out.String(); !strings.Contains(got, string(witnessMarker)) {
		t.Fatalf("teardown plan did not identify the block-only marker: %q", got)
	}
	if got := errb.String(); !strings.Contains(got, "without a current generation-bound identity record") {
		t.Fatalf("refusal did not explain the missing strong identity: %q", got)
	}
}

func TestUninstallRefusesLiveUIDOnlyRecoveryBeforeAnyMutation(t *testing.T) {
	const name = "xxvcc-live-recovery"
	a, _, errb := newTestApp(t, "")
	root := t.TempDir()
	a.StateDir = filepath.Join(root, "state")
	a.AuditLogDir = filepath.Join(root, "audit")
	if err := os.MkdirAll(a.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	a.Registry = &registry.Store{
		Dir:  filepath.Join(a.StateDir, "v2"),
		File: filepath.Join(a.StateDir, "v2", "registry.tsv"),
		Lock: filepath.Join(a.StateDir, "v2", "registry.lock"),
	}
	if err := a.Registry.Init(); err != nil {
		t.Fatal(err)
	}
	if err := a.Registry.BeginDeletion(name, 2001, ""); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	a.InstallPath = filepath.Join(binDir, "linux-temp-admin")
	if err := os.WriteFile(a.InstallPath, []byte("unchanged"), 0o755); err != nil {
		t.Fatal(err)
	}
	pw := user.Passwd{
		Name: name, UID: 2001, GID: 2001,
		GECOS: config.ManagedGenerationGECOSPrefix + "0123456789abcdef0123456789abcdef",
		Home:  "/home/" + name, Shell: "/bin/sh",
	}
	a.LookupUser = func(string) (user.Passwd, bool, error) { return pw, true, nil }

	result := a.uninstallResult([]string{"--yes", "--remove-users", "--force"})
	if result.status != 1 || result.applied {
		t.Fatalf("uninstall result = %+v, want pre-mutation recovery refusal", result)
	}
	if _, err := os.Stat(a.InstallPath); err != nil {
		t.Fatalf("installed command changed despite UID-only recovery: %v", err)
	}
	if _, err := os.Stat(a.StateDir); err != nil {
		t.Fatalf("state changed despite UID-only recovery: %v", err)
	}
	if rec, found, err := a.Registry.Lookup(name); err != nil || !found || !rec.DeletionStarted {
		t.Fatalf("UID-only witness changed: found=%v rec=%+v err=%v", found, rec, err)
	}
	if got := errb.String(); !strings.Contains(got, "not bound to its current generation") {
		t.Fatalf("recovery refusal was not explained: %q", got)
	}
}

func TestAuthorizeUninstallRejectsLaterUnverifiedAccountBeforeTeardown(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	validName := "lta-a-valid"
	blockedName := "lta-z-marker-only"
	validRecord := registry.Record{
		User: validName, UID: 2001, Generation: generation, IdentityBound: true, Port: 22,
	}
	validPasswd := user.Passwd{
		Name: validName, UID: 2001, GID: 2001,
		GECOS: config.ManagedGenerationGECOSPrefix + generation,
		Home:  "/home/" + validName, Shell: "/bin/sh",
	}
	blockedPasswd := user.Passwd{
		Name: blockedName, UID: 2002, GID: 2002,
		GECOS: config.ManagedGenerationGECOSPrefix + generation,
		Home:  "/home/" + blockedName, Shell: "/bin/sh",
	}
	plan := teardownPlan{accounts: []teardownAccount{
		{
			name: validName, exists: true, witnesses: []witness{witnessRegistry},
			registryFound: true, registryRecord: validRecord, passwd: validPasswd,
		},
		{
			name: blockedName, exists: true, witnesses: []witness{witnessMarker},
			passwd: blockedPasswd,
		},
	}}

	a, _, errb := newTestApp(t, "")
	if a.authorizeUninstall(plan, true, true) {
		t.Fatal("mixed uninstall was authorized even though a later live account lacks deletion authority")
	}
	if got := errb.String(); !strings.Contains(got, blockedName) ||
		!strings.Contains(got, "before deleting any account") {
		t.Fatalf("whole-plan refusal did not identify the later blocker: %q", got)
	}
}

func TestUninstallRefusesWhenMarkerInventoryCannotBeRead(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	a.StateDir = t.TempDir()
	a.ListMarkerAccounts = func() ([]string, error) {
		return nil, os.ErrPermission
	}
	plan := a.teardownPlan(false, false)
	if plan.inventoryErr == nil {
		t.Fatal("marker scan failure was not included in the fail-closed inventory error")
	}
	if a.authorizeUninstall(plan, true, true) {
		t.Fatal("uninstall was authorized with an unreadable marker inventory")
	}
	if got := errb.String(); !strings.Contains(got, "scanning account lifecycle markers failed") {
		t.Fatalf("marker inventory refusal was not explained: %q", got)
	}
}

func TestSameTeardownPlanBindsRegistryAndPasswdIdentity(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	base := teardownPlan{accounts: []teardownAccount{{
		name: "xxvcc-plan1", exists: true, witnesses: []witness{witnessRegistry},
		registryFound: true,
		registryRecord: registry.Record{
			User: "xxvcc-plan1", UID: 1001, Generation: generation,
			IdentityBound: true, Port: 22,
		},
		passwd: user.Passwd{
			Name: "xxvcc-plan1", UID: 1001, GID: 1001,
			GECOS: config.ManagedGenerationGECOSPrefix + generation,
			Home:  "/home/xxvcc-plan1", Shell: "/bin/sh",
		},
	}}}
	if !sameTeardownPlan(base, base) {
		t.Fatal("an unchanged teardown identity did not compare equal")
	}

	for _, tc := range []struct {
		name   string
		mutate func(*teardownAccount)
	}{
		{
			name: "registry generation changed",
			mutate: func(acc *teardownAccount) {
				acc.registryRecord.Generation = "fedcba9876543210fedcba9876543210"
			},
		},
		{
			name: "passwd UID changed",
			mutate: func(acc *teardownAccount) {
				acc.passwd.UID = 2002
			},
		},
		{
			name: "registry disappeared",
			mutate: func(acc *teardownAccount) {
				acc.registryFound = false
				acc.registryRecord = registry.Record{}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			changed.accounts = append([]teardownAccount(nil), base.accounts...)
			tc.mutate(&changed.accounts[0])
			if sameTeardownPlan(base, changed) {
				t.Fatal("teardown plan ignored an account identity change")
			}
		})
	}
}

func TestV1RegistryUsersRejectsNonCanonicalRows(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "leading whitespace before username",
			content: " xxvcc-a1\t2026-07-31\n",
			wantErr: "invalid username",
		},
		{
			name:    "valid username without tab-separated fields",
			content: "xxvcc-a1\n",
			wantErr: "not tab-separated",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _ := newTestApp(t, "")
			a.StateDir = t.TempDir()
			path := filepath.Join(a.StateDir, filepath.Base(config.V1RegistryFile))
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if users, err := a.v1RegistryUsers(); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("v1RegistryUsers = %v, %v; want error containing %q", users, err, tc.wantErr)
			}
		})
	}
}

func TestV1RegistryUsersAcceptsHistoricalTabSeparatedRows(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	a.StateDir = t.TempDir()
	path := filepath.Join(a.StateDir, filepath.Base(config.V1RegistryFile))
	content := strings.Join([]string{
		"",
		"# retained operator note",
		"xxvcc-v1early\tcreated\texpires\tyes\tno\thost\t22\tfingerprint",
		"xxvcc-v1late\tcreated\texpires\tyes\tno\thost\t22\tfingerprint\tyes\tunit",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	users, err := a.v1RegistryUsers()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"xxvcc-v1early", "xxvcc-v1late"}
	if len(users) != len(want) || users[0] != want[0] || users[1] != want[1] {
		t.Fatalf("v1RegistryUsers = %v, want %v", users, want)
	}
}
