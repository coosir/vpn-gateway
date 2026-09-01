package agent

import (
	"log/slog"
	"testing"
)

func TestCaptureAndRestoreBaseNetwork(t *testing.T) {
	bn := CaptureBaseNetwork()
	if bn == nil {
		t.Fatal("CaptureBaseNetwork returned nil")
	}

	// Restore should not panic or error even with nil logger
	bn.Restore(nil)
	bn.Restore(slog.Default())

	// Nil BaseNetwork should be safe
	var nilBN *BaseNetwork
	nilBN.Restore(nil)
}

func TestGetDefaultGateway(t *testing.T) {
	// Should return without crashing on any OS
	gw, iface := getDefaultGateway()
	_ = gw
	_ = iface
}
