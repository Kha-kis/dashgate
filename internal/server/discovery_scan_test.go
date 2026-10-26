package server

import (
	"testing"

	"dashgate/internal/models"
)

func TestDiscoveryScanLifecycle(t *testing.T) {
	dm := NewDiscoveryManager()
	if got := dm.GetScanSnapshot().State; got != ScanDisabled {
		t.Fatalf("initial state = %q", got)
	}
	dm.EnableScan()
	if got := dm.GetScanSnapshot().State; got != ScanWaiting {
		t.Fatalf("enabled state = %q", got)
	}
	if !dm.RunScan(func() (DiscoveryScanResult, string) {
		if got := dm.GetScanSnapshot().State; got != ScanScanning {
			t.Errorf("in-flight state = %q", got)
		}
		return DiscoveryScanResult{Apps: []models.App{{Name: "Found"}}}, ""
	}) {
		t.Fatal("first scan was rejected")
	}
	success := dm.GetScanSnapshot()
	if success.State != ScanCompleted || success.LastSuccessCount != 1 || success.LastSuccessAt.IsZero() || success.CompletedAt.IsZero() {
		t.Fatalf("successful snapshot = %+v", success)
	}
	if !dm.RunScan(func() (DiscoveryScanResult, string) { return DiscoveryScanResult{}, "unreachable" }) {
		t.Fatal("failure scan was rejected")
	}
	failure := dm.GetScanSnapshot()
	if failure.State != ScanFailed || failure.IssueCode != "unreachable" || failure.LastSuccessCount != 1 || !failure.LastSuccessAt.Equal(success.LastSuccessAt) || len(dm.GetApps()) != 1 {
		t.Fatalf("failure lost last success: %+v, apps=%v", failure, dm.GetApps())
	}
	dm.RunScan(func() (DiscoveryScanResult, string) {
		return DiscoveryScanResult{WarningCount: 2, IssueCode: "partial_read"}, ""
	})
	warning := dm.GetScanSnapshot()
	if warning.State != ScanWarning || warning.WarningCount != 2 || warning.LastSuccessCount != 0 || len(dm.GetApps()) != 0 {
		t.Fatalf("warning snapshot = %+v", warning)
	}
	dm.DisableScan()
	if got := dm.GetScanSnapshot(); got.State != ScanDisabled || !got.LastSuccessAt.IsZero() || got.LastSuccessCount != 0 || len(dm.GetApps()) != 0 {
		t.Fatalf("disabled snapshot = %+v", got)
	}
	dm.EnableScan()
	if got := dm.GetScanSnapshot(); got.State != ScanWaiting || !got.StartedAt.IsZero() {
		t.Fatalf("re-enabled snapshot = %+v", got)
	}
	dm.RunScan(func() (DiscoveryScanResult, string) { return DiscoveryScanResult{}, "" })
	if got := dm.GetScanSnapshot(); got.State != ScanCompleted || got.LastSuccessCount != 0 {
		t.Fatalf("zero-route success = %+v", got)
	}
}

func TestDiscoveryScanCoalescesAndInvalidates(t *testing.T) {
	dm := NewDiscoveryManager()
	dm.EnableScan()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		dm.RunScan(func() (DiscoveryScanResult, string) {
			close(entered)
			<-release
			return DiscoveryScanResult{Apps: []models.App{{Name: "Old"}}}, ""
		})
	}()
	<-entered
	if dm.RunScan(func() (DiscoveryScanResult, string) {
		t.Error("overlapping callback ran")
		return DiscoveryScanResult{}, ""
	}) {
		t.Fatal("overlapping scan accepted")
	}
	dm.DisableScan()
	dm.EnableScan()
	close(release)
	<-done
	if got := dm.GetScanSnapshot(); got.State != ScanWaiting || len(dm.GetApps()) != 0 {
		t.Fatalf("stale scan republished: %+v, apps=%v", got, dm.GetApps())
	}
}

func TestDiscoveryScanPanic(t *testing.T) {
	dm := NewDiscoveryManager()
	dm.EnableScan()
	if !dm.RunScan(func() (DiscoveryScanResult, string) { panic("password=secret") }) {
		t.Fatal("panic scan rejected")
	}
	got := dm.GetScanSnapshot()
	if got.State != ScanFailed || got.IssueCode != "internal_error" {
		t.Fatalf("panic snapshot = %+v", got)
	}
	if !dm.RunScan(func() (DiscoveryScanResult, string) { return DiscoveryScanResult{}, "" }) {
		t.Fatal("panic left scan locked")
	}
}
