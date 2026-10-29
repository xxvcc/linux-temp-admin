package user

import (
	"errors"
	"strings"
	"testing"
)

func TestCreateRejectsUnexpectedSubordinateAllocation(t *testing.T) {
	setProcRoot(t, nil)
	setPasswd(t, "xxvcc-a1:x:2345:2345:"+testPendingGenerationGECOS(t)+":/home/xxvcc-a1:/bin/sh\n")
	created := false
	runner := &fakeRunner{available: map[string]bool{"useradd": true, "groupdel": true}, onRun: func(name string) {
		if name == "useradd" {
			created = true
		}
	}}
	m := managerWithStubbedHomeChecks(runner)
	m.CheckSubordinateIDsAbsent = func(name string, uid int) error {
		if name != "xxvcc-a1" || uid != 2345 {
			t.Fatalf("subordinate check identity = %s:%d", name, uid)
		}
		if created {
			return errors.New("unexpected subordinate-ID assignment")
		}
		return nil
	}
	m.RemoveManagedMail = func(Passwd) error {
		t.Fatal("continued preparing an account with subordinate identities")
		return nil
	}
	pw, err := m.CreatePendingIdentityWithID("xxvcc-a1", "/bin/sh", testGeneration, 2345)
	if err == nil || !strings.Contains(err.Error(), "unexpected subordinate-ID assignment") || pw.UID != 2345 {
		t.Fatalf("create = %+v, %v; want inactive identity and allocation refusal", pw, err)
	}
	if len(runner.calls) != 1 || runner.calls[0][0] != "useradd" {
		t.Fatalf("unexpected account helper calls %v", runner.calls)
	}
}

func TestSubordinateValidationDetectsIdentityReplacement(t *testing.T) {
	pw := Passwd{Name: "xxvcc-a1", UID: 2345, GID: 2345, Home: "/home/xxvcc-a1", Shell: "/bin/sh", GECOS: testPendingGenerationGECOS(t)}
	current := pw
	m := &Manager{
		LookupUser: func(string) (Passwd, bool, error) { return current, true, nil },
		CheckSubordinateIDsAbsent: func(string, int) error {
			current.UID++
			return nil
		},
	}
	if err := m.CheckNoSubordinateIDsExpected(pw.Name, pw); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("validation error = %v, want identity replacement refusal", err)
	}
}
