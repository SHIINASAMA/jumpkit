package config

import (
	"os"
	"reflect"
	"testing"

	"jumpkit/pkg/core"
)

func TestSaveLoad_roundtrip(t *testing.T) {
	hops := []core.HopConfig{
		{Host: "bastion.example.com", Port: 22, User: "alice", AuthType: core.AuthTypePrivateKey},
		{Host: "internal.db", Port: 3306, User: "root", AuthType: core.AuthTypePassword, UseInternalDns: true},
	}

	f, err := os.CreateTemp("", "jumpkit-test-*.json")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)

	if err := Save(path, hops); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !reflect.DeepEqual(loaded, hops) {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", loaded, hops)
	}
}

func TestSavePath_name(t *testing.T) {
	path, err := SavePath("myconfig")
	if err != nil {
		t.Fatal(err)
	}
	if path != "myconfig.json" {
		t.Errorf("got %q, want myconfig.json", path)
	}
}

func TestSavePath_absolute(t *testing.T) {
	path, err := SavePath("/tmp/foo")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/tmp/foo.json" {
		t.Errorf("got %q, want /tmp/foo.json", path)
	}
}

func TestSavePath_invalid(t *testing.T) {
	cases := []string{"", "../escape", "sub/dir", "bad\\path"}
	for _, c := range cases {
		if _, err := SavePath(c); err == nil {
			t.Errorf("SavePath(%q) should error", c)
		}
	}
}

func TestLoad_nonexistent(t *testing.T) {
	_, err := Load("/tmp/jumpkit-nosuch.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
