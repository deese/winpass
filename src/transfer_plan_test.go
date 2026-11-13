package main

import (
	"errors"
	"reflect"
	"testing"
)

func TestPlanTransfer(t *testing.T) {
	names := []string{"a/x", "a/y/z", "b/one", "file", "dual", "dual/child"}
	tests := []struct {
		name     string
		old, new string
		want     []transferPair
		wantErr  bool
	}{
		{"rename entry", "file", "other", []transferPair{{"file", "other"}}, false},
		{"entry into dir with slash", "file", "c/", []transferPair{{"file", "c/file"}}, false},
		{"entry into existing dir", "file", "b", []transferPair{{"file", "b/file"}}, false},
		{"rename dir", "a", "c", []transferPair{{"a/x", "c/x"}, {"a/y/z", "c/y/z"}}, false},
		{"dir into existing dir", "a", "b", []transferPair{{"a/x", "b/a/x"}, {"a/y/z", "b/a/y/z"}}, false},
		{"dir into dir with slash", "a/", "c/", []transferPair{{"a/x", "c/a/x"}, {"a/y/z", "c/a/y/z"}}, false},
		{"entry that is also a dir wins", "dual", "other", []transferPair{{"dual", "other"}}, false},
		{"dir into itself", "a", "a/sub", nil, true},
		{"same entry", "file", "file", nil, true},
		{"same dir", "a", "a", nil, true},
		{"missing source", "nope", "x", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := planTransfer(tc.old, tc.new, names)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}

	if _, err := planTransfer("nope", "x", names); !errors.Is(err, errEntryNotFound) {
		t.Errorf("missing source should wrap errEntryNotFound, got %v", err)
	}
}
