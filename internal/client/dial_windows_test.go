//go:build windows

package client

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestPipeName(t *testing.T) {
	sid, err := CurrentUserSID()
	if err != nil || !strings.HasPrefix(sid, "S-1-") {
		t.Fatalf("sid = %q %v", sid, err)
	}
	name, err := PipeName()
	if err != nil || name != PipePrefix+sid {
		t.Fatalf("name = %q %v", name, err)
	}
}

func TestDialMissingPipe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := DialPipe(ctx, PipePrefix+"does-not-exist-"+time.Now().Format("150405.000000")); err == nil {
		t.Fatal("dial of a missing pipe succeeded")
	}
}
