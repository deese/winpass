package main

import (
	"reflect"
	"testing"
)

func TestDiffEntriesIdentical(t *testing.T) {
	m := map[string]string{"a": "1", "b": "2"}
	d := diffEntries(m, map[string]string{"a": "1", "b": "2"})
	if d.matching != 2 || len(d.differing)+len(d.missingInStore)+len(d.notInBackup) != 0 {
		t.Fatalf("unexpected diff: %+v", d)
	}
}

func TestDiffEntriesCategories(t *testing.T) {
	backup := map[string]string{"same": "1", "changed": "old", "gone": "x"}
	store := map[string]string{"same": "1", "changed": "new", "fresh": "y"}
	d := diffEntries(backup, store)

	if d.matching != 1 {
		t.Fatalf("matching = %d, want 1", d.matching)
	}
	if !reflect.DeepEqual(d.differing, []string{"changed"}) {
		t.Fatalf("differing = %v", d.differing)
	}
	if !reflect.DeepEqual(d.missingInStore, []string{"gone"}) {
		t.Fatalf("missingInStore = %v", d.missingInStore)
	}
	if !reflect.DeepEqual(d.notInBackup, []string{"fresh"}) {
		t.Fatalf("notInBackup = %v", d.notInBackup)
	}
}

func TestDiffEntriesSortedOutput(t *testing.T) {
	d := diffEntries(map[string]string{}, map[string]string{"c": "1", "a": "1", "b": "1"})
	if !reflect.DeepEqual(d.notInBackup, []string{"a", "b", "c"}) {
		t.Fatalf("notInBackup not sorted: %v", d.notInBackup)
	}
}

func TestDiffEntriesEmptyValuesCompare(t *testing.T) {
	d := diffEntries(map[string]string{"e": ""}, map[string]string{"e": ""})
	if d.matching != 1 {
		t.Fatalf("empty values should match: %+v", d)
	}
}
