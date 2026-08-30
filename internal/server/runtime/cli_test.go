package runtime

import (
	"errors"
	"testing"
)

// TestIsNotFoundRecognisesAbsence covers the wordings the engines use.
// Absence is a normal state here -- it is how the manager decides to create a
// container or fetch an image -- so treating one of these as a failure hides
// the explanation the manager would otherwise give.
func TestIsNotFoundRecognisesAbsence(t *testing.T) {
	absent := []string{
		"Error response from daemon: No such container: vpngw-office",
		"Error response from daemon: No such image: coosir/vg-mock:latest",
		"Error: no such object: vpngw-net-office",
		"Error response from daemon: network vpngw-net-lab not found",
		"Error: image not known",
	}
	for _, msg := range absent {
		if !isNotFound(errors.New(msg)) {
			t.Errorf("not recognised as absence: %q", msg)
		}
	}

	present := []string{
		"Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
		"permission denied while trying to connect to the Docker daemon socket",
		"failed to fetch: no route to host",
	}
	for _, msg := range present {
		if isNotFound(errors.New(msg)) {
			t.Errorf("a real failure was mistaken for absence: %q", msg)
		}
	}
}
