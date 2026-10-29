//go:build integration

package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/registry"
	"github.com/xxvcc/linux-temp-admin/internal/user"
)

func TestInviteRefusesSubordinateIDsBeforeActivation(t *testing.T) {
	for _, permanent := range []bool{false, true} {
		t.Run(map[bool]string{false: "temporary", true: "permanent"}[permanent], func(t *testing.T) {
			const name = "xxvcc-subidgate"
			const generation = "0123456789abcdef0123456789abcdef"
			gecos, err := user.ManagedGECOSForGeneration(generation)
			if err != nil {
				t.Fatal(err)
			}
			expected := user.Passwd{Name: name, UID: 2345, GID: 2345, Home: "/home/" + name, Shell: "/bin/sh", GECOS: gecos}
			a, out, errb := newTestApp(t, "")
			dir := filepath.Join(rootOwnedDir(t), "registry")
			a.Registry = &registry.Store{Dir: dir, File: filepath.Join(dir, "registry.tsv"), Lock: filepath.Join(dir, "registry.lock")}
			if err := a.Registry.Init(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := a.Registry.ReserveIdentity(expected.UID, expected.UID); err != nil {
				t.Fatal(err)
			}
			checked := false
			a.Users = &user.Manager{
				// A nil Runner also makes any attempted expiry activation fail the
				// test: no system helper should run after this validation refuses.
				LookupUser: func(string) (user.Passwd, bool, error) { return expected, true, nil },
				CheckSubordinateIDsAbsent: func(gotName string, gotUID int) error {
					if gotName != name || gotUID != expected.UID {
						t.Fatalf("subordinate validation identity = %s:%d", gotName, gotUID)
					}
					checked = true
					return errors.New("subuid assignment appeared before activation")
				},
			}
			tx := newInviteTransaction(a, invitePlan{username: name})
			tx.pw, tx.generation, tx.permanent = expected, generation, permanent
			tx.rec = registry.Record{User: name, UID: expected.UID, Generation: generation, IdentityBound: true, Port: 22}
			if rc := tx.scheduleActivateAndReport(); rc != 1 || !checked || tx.loginActivationStarted {
				t.Fatalf("activation rc=%d checked=%v started=%v: %s", rc, checked, tx.loginActivationStarted, errb.String())
			}
			if !strings.Contains(errb.String(), "subuid assignment appeared") || strings.Contains(out.String(), "BEGIN LINUX TEMP ADMIN INVITE") {
				t.Fatalf("activation output out=%q err=%q", out.String(), errb.String())
			}
			if found, err := a.Registry.Contains(name); err != nil || !found {
				t.Fatalf("recovery record found=%v err=%v", found, err)
			}
		})
	}
}
