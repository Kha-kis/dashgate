package server

import (
	"time"

	"dashgate/internal/models"
)

type DiscoveryScanState string

const (
	ScanDisabled  DiscoveryScanState = "disabled"
	ScanWaiting   DiscoveryScanState = "waiting"
	ScanScanning  DiscoveryScanState = "scanning"
	ScanCompleted DiscoveryScanState = "completed"
	ScanWarning   DiscoveryScanState = "warning"
	ScanFailed    DiscoveryScanState = "failed"
)

type DiscoveryScanResult struct {
	Apps         []models.App
	WarningCount int
	IssueCode    string
}

type DiscoveryScanSnapshot struct {
	State            DiscoveryScanState
	StartedAt        time.Time
	CompletedAt      time.Time
	LastSuccessAt    time.Time
	LastSuccessCount int
	WarningCount     int
	IssueCode        string
}

func safeScanIssue(code string) string {
	switch code {
	case "missing_config", "invalid_config", "unreachable", "upstream_auth", "bad_response", "decode_failed", "partial_read", "internal_error":
		return code
	default:
		return "internal_error"
	}
}

func (dm *DiscoveryManager) EnableScan() {
	dm.AppsMu.Lock()
	defer dm.AppsMu.Unlock()
	dm.scanEpoch++
	dm.scanRunning = false
	dm.Apps = nil
	dm.scan = DiscoveryScanSnapshot{State: ScanWaiting}
}

func (dm *DiscoveryManager) DisableScan() {
	dm.AppsMu.Lock()
	defer dm.AppsMu.Unlock()
	dm.scanEpoch++
	dm.scanRunning = false
	dm.Apps = nil
	dm.scan = DiscoveryScanSnapshot{State: ScanDisabled}
}

func (dm *DiscoveryManager) GetScanSnapshot() DiscoveryScanSnapshot {
	dm.AppsMu.RLock()
	defer dm.AppsMu.RUnlock()
	return dm.scan
}

// RunScan serializes attempts within one source and discards a result if the
// source was disabled or re-enabled while the callback was running.
func (dm *DiscoveryManager) RunScan(scan func() (DiscoveryScanResult, string)) bool {
	dm.AppsMu.Lock()
	if dm.scan.State == ScanDisabled || dm.scanRunning {
		dm.AppsMu.Unlock()
		return false
	}
	dm.scanRunning = true
	epoch := dm.scanEpoch
	dm.scan.State = ScanScanning
	dm.scan.StartedAt = time.Now().UTC()
	dm.scan.CompletedAt = time.Time{}
	dm.scan.WarningCount = 0
	dm.scan.IssueCode = ""
	dm.AppsMu.Unlock()

	result, failure := func() (result DiscoveryScanResult, failure string) {
		defer func() {
			if recover() != nil {
				failure = "internal_error"
			}
		}()
		return scan()
	}()

	dm.AppsMu.Lock()
	defer dm.AppsMu.Unlock()
	if epoch != dm.scanEpoch {
		return true
	}
	dm.scanRunning = false
	dm.scan.CompletedAt = time.Now().UTC()
	if failure != "" {
		dm.scan.State = ScanFailed
		dm.scan.IssueCode = safeScanIssue(failure)
		return true
	}
	dm.Apps = append([]models.App(nil), result.Apps...)
	dm.scan.LastSuccessAt = dm.scan.CompletedAt
	dm.scan.LastSuccessCount = len(result.Apps)
	if result.WarningCount > 0 {
		dm.scan.State = ScanWarning
		dm.scan.WarningCount = result.WarningCount
		dm.scan.IssueCode = safeScanIssue(result.IssueCode)
	} else {
		dm.scan.State = ScanCompleted
	}
	return true
}
