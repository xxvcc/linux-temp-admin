package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/schedule"
	"github.com/xxvcc/linux-temp-admin/internal/sysinfo"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

func TestDoctorReportsUnsafeLiveAccountGID(t *testing.T) {
	requireRootRegistryFixture(t)
	const (
		name       = "xxvcc-a1"
		generation = "0123456789abcdef0123456789abcdef"
	)
	a, _, errb := newTestApp(t, "")
	if err := a.Registry.Init(); err != nil {
		t.Fatal(err)
	}
	reserveTestIdentity(t, a, 1001)
	if err := a.Registry.Record(registry.Record{
		User: name, UID: 1001, Generation: generation, IdentityBound: true, Port: 22,
	}); err != nil {
		t.Fatal(err)
	}
	a.LookupUser = func(string) (user.Passwd, bool, error) {
		return user.Passwd{
			Name: name, UID: 1001, GID: 0,
			GECOS: config.ManagedGenerationGECOSPrefix + generation,
			Home:  "/home/" + name, Shell: "/bin/sh",
		}, true, nil
	}
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"), nil
	}
	if rc := a.doctor(nil); rc != 1 {
		t.Fatalf("doctor rc = %d, want unsafe-identity failure", rc)
	}
	if got := errb.String(); !strings.Contains(got, "no safe non-root UID/GID") || !strings.Contains(got, name) {
		t.Fatalf("doctor hid unsafe live-account GID: %q", got)
	}
}

func TestCompletedAccountIdentityRejectsUnsafeLiveAccountGID(t *testing.T) {
	requireRootRegistryFixture(t)
	const (
		name       = "xxvcc-a1"
		generation = "0123456789abcdef0123456789abcdef"
	)
	a, _, _ := newTestApp(t, "")
	if err := a.Registry.Init(); err != nil {
		t.Fatal(err)
	}
	reserveTestIdentity(t, a, 1001)
	if err := a.Registry.Record(registry.Record{
		User: name, UID: 1001, Generation: generation, IdentityBound: true, Port: 22,
	}); err != nil {
		t.Fatal(err)
	}
	a.LookupUser = func(string) (user.Passwd, bool, error) {
		return user.Passwd{
			Name: name, UID: 1001, GID: 0,
			GECOS: config.ManagedGenerationGECOSPrefix + generation,
			Home:  "/home/" + name, Shell: "/bin/sh",
		}, true, nil
	}

	ours, live, err := a.completedAccountIdentity(name)
	if err != nil {
		t.Fatal(err)
	}
	if ours || !live {
		t.Fatalf("completedAccountIdentity = ours %v, live %v; want false, true", ours, live)
	}
}

func TestDoctorDistinguishesIdentitySequenceIntegrityFailures(t *testing.T) {
	requireRootRegistryFixture(t)
	const (
		name       = "xxvcc-sequence-doctor"
		generation = "0123456789abcdef0123456789abcdef"
	)
	for _, tc := range []struct {
		name       string
		mutate     func(*testing.T, string) []byte
		want       []string
		doNotWant  []string
		wantAbsent bool
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, path string) []byte {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				return nil
			},
			want: []string{
				"v5 registry is missing identity-sequence",
				"linux-temp-admin recover-identity-sequence --highest <N>",
			},
			doNotWant:  []string{"identity sequence is corrupt or unsafe", "will not overwrite an existing object"},
			wantAbsent: true,
		},
		{
			name: "corrupt",
			mutate: func(t *testing.T, path string) []byte {
				t.Helper()
				content := []byte("not an identity sequence\n")
				if err := os.WriteFile(path, content, 0o600); err != nil {
					t.Fatal(err)
				}
				return content
			},
			want: []string{
				"identity sequence is corrupt or unsafe",
				"will not overwrite an existing object",
			},
			doNotWant: []string{"recover-identity-sequence --highest"},
		},
		{
			name: "too low",
			mutate: func(t *testing.T, path string) []byte {
				t.Helper()
				content := []byte("# linux-temp-admin identity sequence v1\nhighest\t1000\nsafe-after\tnone\n")
				if err := os.WriteFile(path, content, 0o600); err != nil {
					t.Fatal(err)
				}
				return content
			},
			want: []string{
				"identity sequence is corrupt or unsafe",
				"will not overwrite an existing object",
				"high-water mark 1000 is below recorded UID 1001",
			},
			doNotWant: []string{"recover-identity-sequence --highest"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, errb := newTestApp(t, "")
			setTestRegistryRecord(t, a, registry.Record{
				User: name, UID: 1001, Generation: generation, IdentityBound: true, Port: 22,
			})
			sequencePath := filepath.Join(a.Registry.Dir, "identity-sequence")
			wantSequence := tc.mutate(t, sequencePath)
			a.LookupUser = func(string) (user.Passwd, bool, error) {
				return user.Passwd{
					Name: name, UID: 1001, GID: 1001,
					GECOS: ",,,," + config.ManagedGenerationGECOSWitnessPrefix + generation,
					Home:  "/home/" + name, Shell: "/bin/sh",
				}, true, nil
			}
			a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
				return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"), nil
			}

			if rc := a.doctor(nil); rc != 1 {
				t.Fatalf("doctor rc = %d, want integrity failure", rc)
			}
			got := errb.String()
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("doctor output missing %q: %q", want, got)
				}
			}
			for _, unwanted := range tc.doNotWant {
				if strings.Contains(got, unwanted) {
					t.Fatalf("doctor output unexpectedly contains %q: %q", unwanted, got)
				}
			}
			if tc.wantAbsent {
				if _, err := os.Lstat(sequencePath); !os.IsNotExist(err) {
					t.Fatalf("read-only doctor recreated missing sequence: %v", err)
				}
			} else if current, err := os.ReadFile(sequencePath); err != nil || string(current) != string(wantSequence) {
				t.Fatalf("read-only doctor changed sequence: bytes=%q err=%v", current, err)
			}
		})
	}
}

func TestNineFieldLegacyStatusAndDoctorNameTheManualRecoveryCommand(t *testing.T) {
	requireRootRegistryFixture(t)
	const name = "xxvcc-ninelegacy"
	a, _, errb := newTestApp(t, "")
	rec := setLegacyV2RevokeRegistry(t, a, name, 9, 1001, "")
	a.LookupUser = func(string) (user.Passwd, bool, error) {
		return user.Passwd{
			Name: name, UID: 1001, GID: 1001, GECOS: config.ManagedGECOS,
			Home: "/home/" + name, Shell: "/bin/sh",
		}, true, nil
	}
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"), nil
	}

	if got := a.userCells(rec)[1]; got != "legacy identity unverified" {
		t.Fatalf("nine-field legacy state = %q, want legacy identity warning", got)
	}
	if rc := a.doctor(nil); rc != 1 {
		t.Fatalf("doctor rc = %d, want legacy identity warning", rc)
	}
	wantCommand := "linux-temp-admin revoke --user " + name + " --force"
	if got := errb.String(); !strings.Contains(got, "legacy fixed identity marker") || !strings.Contains(got, wantCommand) {
		t.Fatalf("doctor did not name nine-field recovery command %q: %q", wantCommand, got)
	}
}

func TestDoctorDistinguishesDeletionRecoveryStates(t *testing.T) {
	const generation = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name    string
		rec     registry.Record
		pw      user.Passwd
		exists  bool
		wantMsg string
	}{
		{
			name: "absent recovery",
			rec: registry.Record{
				User: "xxvcc-recovery-a", UID: 1001, DeletionStarted: true, Port: 22,
			},
			wantMsg: "account is absent; the witness authorizes only an owner-checked UID-bound mail cleanup retry",
		},
		{
			name: "live bound retry",
			rec: registry.Record{
				User: "xxvcc-recovery-b", UID: 1002, Generation: generation,
				IdentityBound: true, DeletionStarted: true, Port: 22,
			},
			pw: user.Passwd{
				Name: "xxvcc-recovery-b", UID: 1002, GID: 1002,
				GECOS: config.ManagedGenerationGECOSPrefix + generation,
				Home:  "/home/xxvcc-recovery-b", Shell: "/bin/sh",
			},
			exists: true, wantMsg: "exactly matches a durably started deletion generation",
		},
		{
			name: "live UID-only manual recovery",
			rec: registry.Record{
				User: "xxvcc-recovery-c", UID: 1003, DeletionStarted: true, Port: 22,
			},
			pw: user.Passwd{
				Name: "xxvcc-recovery-c", UID: 1003, GID: 1003,
				GECOS: config.ManagedGenerationGECOSPrefix + generation,
				Home:  "/home/xxvcc-recovery-c", Shell: "/bin/sh",
			},
			exists: true, wantMsg: "unbound to the current generation",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, errb := newTestApp(t, "")
			setTestRegistryRecord(t, a, tc.rec)
			a.LookupUser = func(string) (user.Passwd, bool, error) { return tc.pw, tc.exists, nil }
			a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
				return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"), nil
			}
			if rc := a.doctor(nil); rc != 1 {
				t.Fatalf("doctor rc = %d, want recovery warning", rc)
			}
			if got := errb.String(); !strings.Contains(got, tc.wantMsg) || !strings.Contains(got, tc.rec.User) {
				t.Fatalf("doctor recovery output missing %q: %q", tc.wantMsg, got)
			}
		})
	}
}

func TestStatusReportsAbsentDeletionRecovery(t *testing.T) {
	rec := registry.Record{User: "xxvcc-recovery-status", UID: 1001, DeletionStarted: true, Port: 22}
	a, out, _ := newTestApp(t, "")
	setTestRegistryRecord(t, a, rec)
	a.LookupUser = func(string) (user.Passwd, bool, error) { return user.Passwd{}, false, nil }
	if rc := a.status([]string{"--user", rec.User}); rc != 0 {
		t.Fatalf("status rc = %d, want recovery status", rc)
	}
	if got := out.String(); !strings.Contains(got, "identity=deletion-recovery-absent") || !strings.Contains(got, "uid=1001") {
		t.Fatalf("status hid absent recovery: %q", got)
	}
}

func TestStatusAndDoctorReportDeployedFirstFieldGenerationWitness(t *testing.T) {
	const (
		name       = "xxvcc-first-field"
		generation = "0123456789abcdef0123456789abcdef"
	)
	rec := registry.Record{User: name, UID: 1001, Generation: generation, IdentityBound: true, Port: 22}
	pw := user.Passwd{
		Name: name, UID: 1001, GID: 1001,
		GECOS: config.ManagedGenerationGECOSPrefix + generation,
		Home:  "/home/" + name, Shell: "/bin/sh",
	}
	a, out, errb := newTestApp(t, "")
	setTestRegistryRecord(t, a, rec)
	a.LookupUser = func(string) (user.Passwd, bool, error) { return pw, true, nil }
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"), nil
	}

	if rc := a.status([]string{"--user", name}); rc != 0 {
		t.Fatalf("status rc=%d", rc)
	}
	if got := out.String(); !strings.Contains(got, "identity=generation-bound-first-field-compat") {
		t.Fatalf("status hid first-field compatibility identity: %q", got)
	}
	if rc := a.doctor(nil); rc != 1 {
		t.Fatalf("doctor rc=%d, want compatibility warning", rc)
	}
	if got := errb.String(); !strings.Contains(got, "v2.9.3-and-earlier generation witness") ||
		!strings.Contains(got, "linux-temp-admin revoke --user "+name) {
		t.Fatalf("doctor hid first-field migration risk: %q", got)
	}
}

func TestStatusReportsQuarantineFieldsAfterExternalAccountRemoval(t *testing.T) {
	deadline := time.Now().UTC().Add(2 * time.Minute).Truncate(time.Minute)
	rec := registry.Record{
		User: "xxvcc-quarantine-status", UID: 1001, Port: 22,
		Generation: "0123456789abcdef0123456789abcdef", IdentityBound: true,
		DeletionStarted: true, QuarantineUntil: deadline.Format(time.RFC3339),
		QuarantineUnit: config.QuarantineUnitPrefix + "xxvcc-quarantine-status",
	}
	a, out, _ := newTestApp(t, "")
	setTestRegistryRecord(t, a, rec)
	a.LookupUser = func(string) (user.Passwd, bool, error) { return user.Passwd{}, false, nil }
	if rc := a.status([]string{"--user", rec.User}); rc != 0 {
		t.Fatalf("status rc = %d, want recovery status", rc)
	}
	got := out.String()
	if !strings.Contains(got, "identity=deletion-recovery-absent") ||
		!strings.Contains(got, "quarantine-until="+rec.QuarantineUntil+" unit="+rec.QuarantineUnit) {
		t.Fatalf("status hid absent quarantine recovery: %q", got)
	}
}

func TestDoctorDistinguishesMissingQuarantineFinalizer(t *testing.T) {
	const (
		name       = "xxvcc-quarantine-doctor"
		generation = "0123456789abcdef0123456789abcdef"
	)
	a, _, errb := newTestApp(t, "")
	deadline := a.Now().UTC().Add(2 * time.Minute).Truncate(time.Minute)
	rec := registry.Record{
		User: name, UID: 1001, Port: 22, Generation: generation, IdentityBound: true,
		DeletionStarted: true, SequentialID: true,
		QuarantineUntil: deadline.Format(time.RFC3339), QuarantineUnit: config.QuarantineUnitPrefix + name,
	}
	setTestRegistryRecord(t, a, rec)
	a.Scheduler = &schedule.Scheduler{
		SystemdDir: t.TempDir(), InstallPath: a.InstallPath,
		UnitPrefix: config.AutoRevokeUnitPrefix, Now: a.Now,
		Sys: revokeTestScheduleSystem{},
	}
	a.LookupUser = func(string) (user.Passwd, bool, error) {
		return user.Passwd{
			Name: name, UID: 1001, GID: 1001,
			GECOS: config.ManagedGenerationGECOSPrefix + generation,
			Home:  "/home/" + name, Shell: "/bin/sh",
		}, true, nil
	}
	a.SSHDConfig = func(string) (*sysinfo.SSHDConfig, error) {
		return sysinfo.ParseSSHD("pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n"), nil
	}
	if rc := a.doctor(nil); rc != 1 {
		t.Fatalf("doctor rc = %d, want missing-finalizer failure", rc)
	}
	got := errb.String()
	if !strings.Contains(got, "identity remains quarantined, but no valid background finalizer remains") ||
		!strings.Contains(got, name) || strings.Contains(got, "account set to auto-delete but has no valid task left") {
		t.Fatalf("doctor did not distinguish quarantine finalizer loss: %q", got)
	}
}

func TestDoctorReportsLifecycleMarkerWithoutRegistryRow(t *testing.T) {
	requireRootRegistryFixture(t)
	const (
		registered = "xxvcc-registered"
		markerOnly = "xxvcc-marker-only"
		generation = "0123456789abcdef0123456789abcdef"
	)
	a, _, errb := newTestApp(t, "")
	if err := a.Registry.Init(); err != nil {
		t.Fatal(err)
	}
	reserveTestIdentity(t, a, 1001)
	if err := a.Registry.Record(registry.Record{
		User: registered, UID: 1001, Generation: generation, IdentityBound: true, Port: 22,
	}); err != nil {
		t.Fatal(err)
	}
	a.LookupUser = func(name string) (user.Passwd, bool, error) {
		if name != registered {
			t.Fatalf("unexpected passwd lookup for %q", name)
		}
		return user.Passwd{
			Name: name, UID: 1001, GID: 1001,
			GECOS: config.ManagedGenerationGECOSPrefix + generation,
			Home:  "/home/" + name, Shell: "/bin/sh",
		}, true, nil
	}
	a.ListMarkerAccounts = func() ([]string, error) {
		return []string{registered, markerOnly}, nil
	}

	if rc := a.doctor(nil); rc != 1 {
		t.Fatalf("doctor rc = %d, want marker-only anomaly failure", rc)
	}
	got := errb.String()
	if !strings.Contains(got, "lifecycle marker but has no registry row") || !strings.Contains(got, markerOnly) {
		t.Fatalf("doctor did not report the marker-only account: %q", got)
	}
	if strings.Contains(got, "deletion: "+registered) {
		t.Fatalf("doctor reported a marker backed by a registry row: %q", got)
	}
}

func TestDoctorFailsWhenLifecycleMarkerScanFails(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	wantErr := errors.New("passwd fixture unreadable")
	a.ListMarkerAccounts = func() ([]string, error) { return nil, wantErr }

	if rc := a.doctor(nil); rc != 1 {
		t.Fatalf("doctor rc = %d, want marker-scan failure", rc)
	}
	got := errb.String()
	if !strings.Contains(got, "cannot scan account lifecycle markers") || !strings.Contains(got, wantErr.Error()) {
		t.Fatalf("doctor hid the marker-scan failure: %q", got)
	}
}

func TestDoctorDoesNotCompareMarkersAgainstUnreadableRegistry(t *testing.T) {
	a, _, errb := newTestApp(t, "")
	if err := os.Mkdir(a.Registry.File, 0o700); err != nil {
		t.Fatal(err)
	}
	scans := 0
	a.ListMarkerAccounts = func() ([]string, error) {
		scans++
		return []string{"xxvcc-marker-only"}, nil
	}

	if rc := a.doctor(nil); rc != 1 {
		t.Fatalf("doctor rc = %d, want unreadable-registry failure", rc)
	}
	if scans != 0 {
		t.Fatalf("marker scan calls = %d, want none without a readable registry", scans)
	}
	got := errb.String()
	if !strings.Contains(got, "cannot read registry") {
		t.Fatalf("doctor hid the registry failure: %q", got)
	}
	if strings.Contains(got, "lifecycle marker but has no registry row") {
		t.Fatalf("doctor made a missing-row claim without a readable registry: %q", got)
	}
}
