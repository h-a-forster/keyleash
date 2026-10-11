package money

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		in   string
		want Micros
		err  bool
	}{
		{"$2", 2 * Dollar, false},
		{"2", 2 * Dollar, false},
		{"2.50", 2*Dollar + 50*Cent, false},
		{"$0.000125", 125, false},
		{".5", 500_000, false},
		{"150c", 150 * Cent, false},
		{" $3 ", 3 * Dollar, false},
		{"", 0, true},
		{"$", 0, true},
		{"-1", 0, true},
		{"$-1", 0, true},
		{"1.0000001", 0, true},
		{"abc", 0, true},
		{"1.2.3", 0, true},
		{"-5c", 0, true},
		{"99999999999999999999", 0, true},
		{"922337203685478c", 0, true},
		{"1.-5", 0, true},
		{"+1", 0, true},
		{"1.+5", 0, true},
		{"1.", 1 * Dollar, false},
	}
	for _, tt := range tests {
		got, err := Parse(tt.in)
		if (err != nil) != tt.err {
			t.Errorf("Parse(%q) err = %v, want err %v", tt.in, err, tt.err)
			continue
		}
		if got != tt.want {
			t.Errorf("Parse(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		in   Micros
		want string
	}{
		{0, "$0.00"},
		{Dollar, "$1.00"},
		{2*Dollar + 50*Cent, "$2.50"},
		{125, "$0.000125"},
		{-Cent, "-$0.01"},
	}
	for _, tt := range tests {
		if got := tt.in.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCostRoundsUp(t *testing.T) {
	// $3 / MTok: one token costs 3 micros exactly.
	if got := PerMTok(3_000_000).Cost(1); got != 3 {
		t.Errorf("got %d, want 3", got)
	}
	// $0.10 / MTok: one token is 0.1 micro, rounds up to 1.
	if got := PerMTok(100_000).Cost(1); got != 1 {
		t.Errorf("got %d, want 1", got)
	}
	if got := PerMTok(15_000_000).Cost(1_000_000); got != 15*Dollar {
		t.Errorf("got %d, want %d", got, 15*Dollar)
	}
	if got := PerMTok(5).Cost(0); got != 0 {
		t.Errorf("zero tokens cost %d", got)
	}
	if got := PerMTok(-5).Cost(10); got != 0 {
		t.Errorf("negative price cost %d", got)
	}
}
