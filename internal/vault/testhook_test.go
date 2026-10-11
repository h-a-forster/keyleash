package vault

import "testing"

func TestSetTestKDFParamsRestores(t *testing.T) {
	before, beforeTarget := kdfDefaults, kdfTarget
	restore := SetTestKDFParams()
	if kdfDefaults != (kdfParams{Time: 1, MemoryKiB: 64, Threads: 1}) || kdfTarget != 0 {
		t.Fatalf("params not lowered: %+v %v", kdfDefaults, kdfTarget)
	}
	restore()
	if kdfDefaults != before || kdfTarget != beforeTarget {
		t.Fatalf("params not restored: %+v %v", kdfDefaults, kdfTarget)
	}
}
