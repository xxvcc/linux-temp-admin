package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
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
	requireRootRegistryFixture(t)
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
	if a.authorizeUninstall(plan, uninstallOptions{yes: true, removeUsers: true}) {
		t.Fatal("mixed uninstall was authorized even though a later live account lacks deletion authority")
	}
	if got := errb.String(); !strings.Contains(got, blockedName) ||
		!strings.Contains(got, "before deleting any account") {
		t.Fatalf("whole-plan refusal did not identify the later blocker: %q", got)
	}
}

// foreignMarkerPlan builds the one shape --ignore-foreign-markers excuses: a
// live account named ONLY by a passwd GECOS marker. Any local user can produce it
// with `chfn -f 'linux-temp-admin temporary admin'` on their own account.
func foreignMarkerPlan(name string, extra ...witness) teardownPlan {
	return teardownPlan{accounts: []teardownAccount{{
		name:      name,
		exists:    true,
		witnesses: append([]witness{witnessMarker}, extra...),
		passwd: user.Passwd{
			Name: name, UID: 4242, GID: 4242, GECOS: config.ManagedGECOS,
			Home: "/home/" + name, Shell: "/bin/sh",
		},
	}}}
}

func TestAuthorizeUninstallRefusesForeignMarkerAndNamesTheRemedy(t *testing.T) {
	const name = "someone-else"
	a, _, errb := newTestApp(t, "")
	if a.authorizeUninstall(foreignMarkerPlan(name), uninstallOptions{yes: true, removeUsers: true}) {
		t.Fatal("a marker-only account was silently ignored without the explicit opt-in")
	}
	got := errb.String()
	for _, want := range []string{name, "usermod -c ''", "--ignore-foreign-markers", "chfn"} {
		if !strings.Contains(got, want) {
			t.Fatalf("refusal did not mention %q: %q", want, got)
		}
	}
}

func TestAuthorizeUninstallIgnoresForeignMarkerOnExplicitOptIn(t *testing.T) {
	const name = "someone-else"
	a, _, errb := newTestApp(t, "")
	// removeUsers is deliberately absent: nothing is going to be deleted, so
	// demanding the flag that authorizes deletion would name a lie.
	if !a.authorizeUninstall(foreignMarkerPlan(name), uninstallOptions{yes: true, ignoreForeignMarkers: true}) {
		t.Fatalf("explicit opt-in did not clear a marker-only block: %q", errb.String())
	}
	if got := errb.String(); !strings.Contains(got, name) || !strings.Contains(got, "--ignore-foreign-markers") {
		t.Fatalf("ignored accounts were not named back to the operator: %q", got)
	}
}

func TestAuthorizeUninstallStillBlocksMarkerAccountCarryingAnArtifact(t *testing.T) {
	const name = "someone-else"
	for _, extra := range []witness{witnessSudoers, witnessSSHD, witnessUnit} {
		t.Run(string(extra), func(t *testing.T) {
			a, _, errb := newTestApp(t, "")
			plan := foreignMarkerPlan(name, extra)
			if a.authorizeUninstall(plan, uninstallOptions{yes: true, removeUsers: true, ignoreForeignMarkers: true}) {
				t.Fatalf("the opt-in excused an account that still carries %s", extra)
			}
			if got := errb.String(); !strings.Contains(got, name) {
				t.Fatalf("refusal did not identify the account: %q", got)
			}
		})
	}
}

func TestAuthorizeUninstallStillBlocksRegisteredMarkerAccount(t *testing.T) {
	const name = "lta-registered"
	a, _, _ := newTestApp(t, "")
	plan := foreignMarkerPlan(name)
	// A registry row is exactly the evidence that says this account may be ours.
	plan.accounts[0].registryFound = true
	plan.accounts[0].registryRecord = registry.Record{User: name, UID: 4242, Port: 22}
	if a.authorizeUninstall(plan, uninstallOptions{yes: true, removeUsers: true, ignoreForeignMarkers: true}) {
		t.Fatal("the opt-in excused an account that has a registry row")
	}
}

func TestUninstallIgnoreForeignMarkersCompletesTeardown(t *testing.T) {
	const name = "someone-else"
	a, _, errb := newTestApp(t, "")
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
	if err := os.WriteFile(a.InstallPath, []byte("installed"), 0o755); err != nil {
		t.Fatal(err)
	}
	a.Selfmanage = selfmanage.New(a.InstallPath, 0)

	pw := user.Passwd{
		Name: name, UID: 4242, GID: 4242, GECOS: config.ManagedGECOS,
		Home: "/home/" + name, Shell: "/bin/sh",
	}
	a.ListMarkerAccounts = func() ([]string, error) { return []string{name}, nil }
	a.LookupUser = func(string) (user.Passwd, bool, error) { return pw, true, nil }
	// Users is nil on purpose: reaching any account mutation would panic, which is
	// the assertion that the ignored account is never revoked or deleted.

	result := a.uninstallResult([]string{"--yes", "--force", "--ignore-foreign-markers"})
	if result.status != 0 || !result.applied {
		t.Fatalf("uninstall result = %+v, want a completed teardown; stderr=%q", result, errb.String())
	}
	if _, err := os.Lstat(a.InstallPath); !os.IsNotExist(err) {
		t.Fatalf("installed command survived the teardown: %v", err)
	}
	if _, err := os.Lstat(a.StateDir); !os.IsNotExist(err) {
		t.Fatalf("state directory survived the teardown: %v", err)
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
	if a.authorizeUninstall(plan, uninstallOptions{yes: true, removeUsers: true}) {
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
			GECOS: ",,,," + config.ManagedGenerationGECOSWitnessPrefix + generation,
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

	mutable := base
	mutable.accounts = append([]teardownAccount(nil), base.accounts...)
	mutable.accounts[0].passwd.GECOS = "Changed Name,room,work,home," + config.ManagedGenerationGECOSWitnessPrefix + generation
	mutable.accounts[0].passwd.Shell = "/bin/bash"
	if !sameTeardownPlan(base, mutable) {
		t.Fatal("teardown plan treated current-format user-writable passwd changes as a new identity")
	}

	old := base
	old.accounts = append([]teardownAccount(nil), base.accounts...)
	old.accounts[0].passwd.GECOS = config.ManagedGenerationGECOSPrefix + generation
	oldChanged := old
	oldChanged.accounts = append([]teardownAccount(nil), old.accounts...)
	oldChanged.accounts[0].passwd.Shell = "/bin/bash"
	if sameTeardownPlan(old, oldChanged) {
		t.Fatal("teardown plan accepted a changed legacy first-field passwd snapshot")
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

func TestQuarantinedAccountRemainsAuthorizedForSynchronousUninstallCleanup(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	pw := user.Passwd{
		Name: "xxvcc-quarantine", UID: 1001, GID: 1001,
		GECOS: config.ManagedGenerationGECOSPrefix + generation,
		Home:  "/home/xxvcc-quarantine", Shell: "/bin/sh",
	}
	rec := registry.Record{
		User: pw.Name, UID: pw.UID, Port: 22, Generation: generation, IdentityBound: true,
		DeletionStarted: true, QuarantineUntil: "2026-08-01T12:02:00Z",
		QuarantineUnit: config.QuarantineUnitPrefix + pw.Name,
	}
	acc := teardownAccount{
		name: pw.Name, exists: true, registryFound: true, registryRecord: rec, passwd: pw,
		witnesses: []witness{witnessRegistry},
	}
	if !liveTeardownAccountAuthorized(acc) {
		t.Fatal("a valid quarantined account could not be synchronously finalized by uninstall")
	}
}
