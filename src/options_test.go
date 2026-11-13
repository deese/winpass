package main

import (
	"reflect"
	"testing"
)

func TestParseOptions(t *testing.T) {
	specs := []flagSpec{
		{short: 'c', long: "clip", optValue: true},
		{short: 'r', long: "recursive"},
		{short: 'f', long: "force"},
	}
	tests := []struct {
		name       string
		args       []string
		flags      []string
		clipLine   int
		positional []string
		wantErr    bool
	}{
		{"plain", []string{"a/b"}, nil, 0, []string{"a/b"}, false},
		{"clip default", []string{"-c", "a"}, []string{"clip"}, 0, []string{"a"}, false},
		{"clip line short", []string{"-c2", "a"}, []string{"clip"}, 2, []string{"a"}, false},
		{"clip line long", []string{"--clip=3", "a"}, []string{"clip"}, 3, []string{"a"}, false},
		{"combined", []string{"-rf", "dir"}, []string{"recursive", "force"}, 0, []string{"dir"}, false},
		{"flag after name", []string{"a", "-f"}, []string{"force"}, 0, []string{"a"}, false},
		{"double dash", []string{"--", "-weird"}, nil, 0, []string{"-weird"}, false},
		{"unknown short", []string{"-x", "a"}, nil, 0, nil, true},
		{"unknown long", []string{"--nope"}, nil, 0, nil, true},
		{"bad clip value", []string{"-c0", "a"}, nil, 0, nil, true},
		{"value on plain flag", []string{"--force=1"}, nil, 0, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseOptions(tc.args, specs)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			for _, f := range tc.flags {
				if !got.flags[f] {
					t.Errorf("flag %q not set", f)
				}
			}
			if len(got.flags) != len(tc.flags) {
				t.Errorf("flags = %v, want %v", got.flags, tc.flags)
			}
			if got.values["clip"] != tc.clipLine {
				t.Errorf("clip line = %d, want %d", got.values["clip"], tc.clipLine)
			}
			if !reflect.DeepEqual(got.positional, tc.positional) {
				t.Errorf("positional = %v, want %v", got.positional, tc.positional)
			}
		})
	}
}

func TestNthLine(t *testing.T) {
	s := "pw\r\nuser: me\r\nurl"
	for n, want := range map[int]string{1: "pw", 2: "user: me", 3: "url"} {
		if got, ok := nthLine(s, n); !ok || got != want {
			t.Errorf("nthLine(%d) = %q, %v; want %q", n, got, ok, want)
		}
	}
	if _, ok := nthLine(s, 4); ok {
		t.Error("nthLine(4) should fail")
	}
}
