// Package money is integer accounting in micro-USD. No floats touch balances.
package money

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Micros is an amount of US dollars in millionths (1 USD = 1_000_000).
type Micros int64

const (
	Cent   Micros = 10_000
	Dollar Micros = 1_000_000
)

// Parse reads "$2", "2", "2.50", "$0.000125" or "150c" into Micros.
// More than six decimal places is an error rather than a silent rounding.
func Parse(s string) (Micros, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("money: empty amount")
	}
	if strings.HasSuffix(s, "c") {
		n, err := strconv.ParseInt(strings.TrimSuffix(s, "c"), 10, 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("money: bad cents amount %q", s)
		}
		return Micros(n) * Cent, nil
	}
	s = strings.TrimPrefix(s, "$")
	neg := strings.HasPrefix(s, "-")
	if neg {
		return 0, fmt.Errorf("money: negative amount %q", s)
	}
	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" {
		whole = "0"
	}
	w, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("money: bad amount %q", s)
	}
	if len(frac) > 6 {
		return 0, fmt.Errorf("money: %q has more than 6 decimal places", s)
	}
	var f int64
	if frac != "" {
		f, err = strconv.ParseInt(frac+strings.Repeat("0", 6-len(frac)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("money: bad amount %q", s)
		}
	}
	if w > (1<<62)/int64(Dollar) {
		return 0, fmt.Errorf("money: amount %q too large", s)
	}
	return Micros(w)*Dollar + Micros(f), nil
}

// String renders as "$1.234567" trimmed to at least two decimals.
func (m Micros) String() string {
	sign := ""
	if m < 0 {
		sign = "-"
		m = -m
	}
	s := fmt.Sprintf("%s$%d.%06d", sign, m/Dollar, m%Dollar)
	s = strings.TrimRight(s, "0")
	if i := strings.IndexByte(s, '.'); len(s)-i-1 < 2 {
		s += strings.Repeat("0", 2-(len(s)-i-1))
	}
	return s
}

// PerMTok is a price in micro-USD per million tokens. Using micros per MTok
// keeps typical prices ($0.10 – $75 / MTok) exact as integers.
type PerMTok int64

// Cost returns the cost of n tokens at rate p, rounded up to the next micro so
// rounding never favours spending.
func (p PerMTok) Cost(n int64) Micros {
	if n <= 0 || p <= 0 {
		return 0
	}
	num := int64(p) * n
	return Micros((num + 999_999) / 1_000_000)
}
