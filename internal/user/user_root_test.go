//go:build integration

package user

import (
	"os/exec"
	"testing"
)

// TestUserLifecycle exercises real useradd/usermod/chage/userdel end to end.
// It creates a disposable test account and always cleans it up.
func TestUserLifecycle(t *testing.T) {
	if err := exec.Command("id").Run(); err != nil {
		t.Skip("no id")
	}
	passwdPath = "/etc/passwd" // use the real database
	const name = "ltatestacct"
	// Best-effort pre-clean and guaranteed post-clean.
	forceDelete := func() { _ = exec.Command("userdel", "-r", "--", name).Run() }
	forceDelete()
	t.Cleanup(forceDelete)

	m := New()
	if err := m.Create(name, "/bin/sh"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !Exists(name) {
		t.Fatal("account should exist after Create")
	}
	pw, ok := Lookup(name)
	if !ok || pw.UID < 1 {
		t.Fatalf("Lookup after create: %+v ok=%v", pw, ok)
	}
	if !IsManaged(name) {
		t.Error("created account should carry the managed GECOS tag")
	}
	if err := m.LockPassword(name); err != nil {
		t.Errorf("LockPassword: %v", err)
	}
	if err := m.SetExpiry(name, "2999-01-01"); err != nil {
		t.Errorf("SetExpiry: %v", err)
	}
	if err := m.Delete(name); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if Exists(name) {
		t.Error("account should be gone after Delete")
	}
}
