package cache

import (
	"bytes"
	"encoding/json"
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

func TestRawReportCache(t *testing.T) {
	cache := NewRawReportCache(1 << 20)
	report := trivyTypes.Report{
		SchemaVersion: 2,
		ArtifactName:  "alpine:3.19",
		Results: []trivyTypes.Result{
			{Target: "alpine:3.19 (alpine 3.19.0)", Class: "os-pkgs", Type: "alpine"},
			{Target: "usr/local/bin/app", Class: "lang-pkgs", Type: "gobinary"},
		},
	}

	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	cache.Add("sha256:manifest", reportJSON)

	got, ok := cache.Get("sha256:manifest")
	if !ok {
		t.Fatal("expected report to be in cache")
	}

	if !bytes.Equal(got, reportJSON) {
		t.Fatalf("cached report lost native report data: got %s", got)
	}

	var decoded trivyTypes.Report
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("cached report is not valid JSON: %v", err)
	}

	if decoded.SchemaVersion != report.SchemaVersion || decoded.ArtifactName != report.ArtifactName ||
		len(decoded.Results) != len(report.Results) || decoded.Results[0].Target != report.Results[0].Target ||
		decoded.Results[1].Target != report.Results[1].Target {
		t.Fatalf("cached report lost native report data: got %#v", decoded)
	}

	if _, ok := cache.Get("sha256:missing"); ok {
		t.Fatal("expected cache miss for unknown digest")
	}

	cache.Purge()

	if _, ok := cache.Get("sha256:manifest"); ok {
		t.Fatal("expected report cache to be empty after purge")
	}

	if used := cache.UsedBytes(); used != 0 {
		t.Fatalf("expected no bytes accounted after purge, got %d", used)
	}
}

// The budget, not the entry count, is what bounds this cache.
func TestRawReportCacheEvictsOnByteBudget(t *testing.T) {
	entry := bytes.Repeat([]byte("a"), 100)
	cache := NewRawReportCache(int64(len(entry) * 3))

	for _, key := range []string{"one", "two", "three"} {
		cache.Add(key, entry)
	}

	if used := cache.UsedBytes(); used != int64(len(entry)*3) {
		t.Fatalf("expected budget to be full, got %d", used)
	}

	// "one" becomes least recently used once "two" and "three" are touched.
	cache.Get("two")
	cache.Get("three")
	cache.Add("four", entry)

	if _, ok := cache.Get("one"); ok {
		t.Fatal("expected least-recently-used entry to be evicted")
	}

	for _, key := range []string{"two", "three", "four"} {
		if _, ok := cache.Get(key); !ok {
			t.Fatalf("expected %q to still be cached", key)
		}
	}

	if used := cache.UsedBytes(); used > int64(len(entry)*3) {
		t.Fatalf("cache exceeded its byte budget: %d", used)
	}
}

func TestRawReportCacheRejectsOversizedEntry(t *testing.T) {
	cache := NewRawReportCache(10)

	cache.Add("huge", bytes.Repeat([]byte("a"), 11))

	if _, ok := cache.Get("huge"); ok {
		t.Fatal("expected an entry larger than the whole budget to be rejected")
	}

	if used := cache.UsedBytes(); used != 0 {
		t.Fatalf("expected no bytes accounted, got %d", used)
	}
}

// A non-positive budget is the supported way to disable caching entirely.
func TestRawReportCacheNonPositiveBudgetDisablesCaching(t *testing.T) {
	for _, maxBytes := range []int64{0, -1} {
		cache := NewRawReportCache(maxBytes)

		cache.Add("key", []byte("{}"))

		if _, ok := cache.Get("key"); ok {
			t.Fatalf("expected budget %d to disable caching", maxBytes)
		}

		if used := cache.UsedBytes(); used != 0 {
			t.Fatalf("expected no bytes accounted for budget %d, got %d", maxBytes, used)
		}
	}
}

// Replacing a key must not leak its previous size, since replacement does not evict.
func TestRawReportCacheAccountsForReplacement(t *testing.T) {
	cache := NewRawReportCache(1000)

	cache.Add("key", bytes.Repeat([]byte("a"), 100))
	cache.Add("key", bytes.Repeat([]byte("b"), 40))

	if used := cache.UsedBytes(); used != 40 {
		t.Fatalf("expected replacement to discount the previous value, got %d", used)
	}
}
