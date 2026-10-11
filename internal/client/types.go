package client

import (
	"time"

	"github.com/h-a-forster/keyleash/internal/money"
)

// Daemon states (docs/DAEMON.md "State machine").
const (
	StateLocked   = "locked"
	StateUnlocked = "unlocked"
	StateAway     = "away"
	StateTripped  = "tripped"
)

// Unlock methods accepted by POST /v1/unlock.
const (
	MethodHello      = "hello"
	MethodPassphrase = "passphrase"
	MethodRecovery   = "recovery"
	MethodDPAPI      = "dpapi"
)

// Error codes carried in ErrorBody.Code.
const (
	CodeBadRequest    = "bad_request"
	CodeNotFound      = "not_found"
	CodeLocked        = "locked"
	CodeWrongSecret   = "wrong_secret"
	CodeRollback      = "rollback"
	CodeConflict      = "conflict"
	CodeStepUpDenied  = "step_up_denied"
	CodeStepUpTimeout = "step_up_timeout"
	CodeForbidden     = "forbidden"
	CodeUnsupported   = "unsupported"
	CodeInternal      = "internal"
)

// ErrorBody is the JSON body of every non-2xx admin response.
type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Status is the response of GET /v1/status and of state-changing calls.
type Status struct {
	State string `json:"state"`
	// TripReason says why the daemon is Tripped ("velocity", "integrity",
	// "audit", ...); empty otherwise.
	TripReason string    `json:"trip_reason,omitempty"`
	Session    string    `json:"session,omitempty"`
	LeaseUntil time.Time `json:"lease_until,omitzero"`
	AwaySince  time.Time `json:"away_since,omitzero"`
	AwayUntil  time.Time `json:"away_until,omitzero"`
	Grant      *Grant    `json:"grant,omitempty"`

	ProxyAddr string        `json:"proxy_addr,omitempty"`
	Limits    []LimitStatus `json:"limits"`
	InFlight  []InFlight    `json:"in_flight"`

	PresenceDegraded       bool   `json:"presence_degraded,omitempty"`
	PresenceDegradedReason string `json:"presence_degraded_reason,omitempty"`

	Vault VaultInfo `json:"vault"`

	PendingApprovals int `json:"pending_approvals"`
	// AuditHealthy is false after a sticky audit write failure (the daemon
	// is then Tripped until the log can be reopened).
	AuditHealthy bool `json:"audit_healthy"`
	// Integrity reports the last ledger/state verification ("ok",
	// "failed: ...", or "" before the first unlock).
	Integrity string `json:"integrity,omitempty"`
	// Warnings are human-readable notices (recovered vault, stale .prev, ...).
	Warnings []string `json:"warnings,omitempty"`
}

// VaultInfo is vault metadata for status. It never contains secrets.
type VaultInfo struct {
	ID                string `json:"id"`
	Seq               uint64 `json:"seq"`
	Unlocked          bool   `json:"unlocked"`
	RecoveredFromPrev bool   `json:"recovered_from_prev,omitempty"`
	PrevNotScrubbed   bool   `json:"prev_not_scrubbed,omitempty"`
	RollbackDetected  bool   `json:"rollback_detected,omitempty"`
	Slots             []Slot `json:"slots"`
}

// Slot is public key-slot metadata.
type Slot struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Label       string    `json:"label,omitempty"`
	Created     time.Time `json:"created,omitzero"`
	Convenience bool      `json:"convenience,omitempty"`
}

// LimitStatus is one budget limit's state.
type LimitStatus struct {
	Scope     string       `json:"scope"`
	Window    string       `json:"window"`
	Limit     money.Micros `json:"limit_micros"`
	Settled   money.Micros `json:"settled_micros"`
	Reserved  money.Micros `json:"reserved_micros"`
	Remaining money.Micros `json:"remaining_micros"`
}

// InFlight is one in-flight reservation.
type InFlight struct {
	ID       string        `json:"id"`
	Pass     string        `json:"pass,omitempty"`
	Provider string        `json:"provider,omitempty"`
	Model    string        `json:"model,omitempty"`
	Client   string        `json:"client,omitempty"`
	Amount   money.Micros  `json:"amount_micros"`
	Age      time.Duration `json:"age_ns"`
}

// UnlockRequest is the body of POST /v1/unlock. Secret holds the passphrase
// or recovery code (JSON base64); it is wiped by both sides after use.
type UnlockRequest struct {
	Method string `json:"method"`
	Secret []byte `json:"secret,omitempty"`
}

// PanicRequest is the body of POST /v1/panic.
type PanicRequest struct {
	RevokeUpstream bool `json:"revoke_upstream,omitempty"`
}

// PanicSummary is the response of POST /v1/panic.
type PanicSummary struct {
	Locked          bool   `json:"locked"`
	PassesRevoked   int    `json:"passes_revoked"`
	UpstreamRevoked bool   `json:"upstream_revoked"`
	Note            string `json:"note,omitempty"`
	Status          Status `json:"status"`
}

// AwayRequest is the body of POST /v1/away (unattended grant, step-up).
type AwayRequest struct {
	Budget money.Micros  `json:"budget_micros"`
	For    time.Duration `json:"for_ns"`
	Pass   string        `json:"pass,omitempty"`
}

// Grant is an active unattended grant.
type Grant struct {
	ID     string       `json:"id"`
	Amount money.Micros `json:"amount_micros"`
	Until  time.Time    `json:"until"`
	Pass   string       `json:"pass,omitempty"`
}

// PassLimit is a per-pass spend limit (window: request|minute|hour|day|month|session).
type PassLimit struct {
	Window string       `json:"window"`
	Amount money.Micros `json:"amount_micros"`
}

// PassCreateRequest is the body of POST /v1/passes.
type PassCreateRequest struct {
	Name string `json:"name"`
	// Kind is "named" (default) or "run".
	Kind      string   `json:"kind,omitempty"`
	Providers []string `json:"providers"`
	// Models / DenyModels are model globs (allow / deny lists).
	Models     []string    `json:"models,omitempty"`
	DenyModels []string    `json:"deny_models,omitempty"`
	Limits     []PassLimit `json:"limits,omitempty"`
	// Concurrency caps in-flight requests for this pass (0: config default).
	Concurrency int `json:"concurrency,omitempty"`
	// TTL is the lifetime (0: config default for the kind).
	TTL time.Duration `json:"ttl_ns,omitempty"`
	// BindPID binds the pass to a running process and its descendants.
	// Required for kind "run".
	BindPID int `json:"bind_pid,omitempty"`
}

// PassInfo is pass metadata. It never contains the secret.
type PassInfo struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Kind        string      `json:"kind"`
	Created     time.Time   `json:"created"`
	Expires     time.Time   `json:"expires"`
	Providers   []string    `json:"providers"`
	Models      []string    `json:"models,omitempty"`
	DenyModels  []string    `json:"deny_models,omitempty"`
	Limits      []PassLimit `json:"limits,omitempty"`
	Concurrency int         `json:"concurrency,omitempty"`
	BindPID     int         `json:"bind_pid,omitempty"`
	BindImage   string      `json:"bind_image,omitempty"`
	Revoked     bool        `json:"revoked,omitempty"`
	RevokedAt   time.Time   `json:"revoked_at,omitzero"`
	LastUsed    time.Time   `json:"last_used,omitzero"`
	Expired     bool        `json:"expired,omitempty"`
}

// PassCreateResponse is the response of POST /v1/passes. Token is the only
// copy of the pass secret; it is returned exactly once.
type PassCreateResponse struct {
	Pass  PassInfo `json:"pass"`
	Token string   `json:"token"`
}

// PassRevokeRequest is the body of DELETE /v1/passes.
type PassRevokeRequest struct {
	ID string `json:"id"`
}

// KeyInfo is masked vault entry metadata (never the secret).
type KeyInfo struct {
	ID          string    `json:"id"`
	Provider    string    `json:"provider"`
	Kind        string    `json:"kind"`
	Label       string    `json:"label"`
	Created     time.Time `json:"created"`
	Rotated     time.Time `json:"rotated"`
	Fingerprint string    `json:"fingerprint"`
	// Authenticated is false while the vault is locked: the metadata has
	// not been verified yet.
	Authenticated bool `json:"authenticated"`
}

// AddKeyRequest is the body of POST /v1/keys. Secret is wiped after use.
type AddKeyRequest struct {
	Provider string `json:"provider"`
	Label    string `json:"label"`
	// Kind is "api_key" (default) or "admin_key".
	Kind   string `json:"kind,omitempty"`
	Secret []byte `json:"secret"`
}

// UsageRow is one aggregate of GET /v1/usage.
type UsageRow struct {
	Key       string       `json:"key"`
	Requests  int          `json:"requests"`
	Amount    money.Micros `json:"amount_micros"`
	Estimated int          `json:"estimated"`
}

// Usage is the response of GET /v1/usage.
type Usage struct {
	By    string       `json:"by"`
	Since time.Time    `json:"since"`
	Rows  []UsageRow   `json:"rows"`
	Total money.Micros `json:"total_micros"`
}

// Approval is a pending step-up request.
type Approval struct {
	ID       string       `json:"id"`
	Kind     string       `json:"kind"`
	Prompt   string       `json:"prompt"`
	Pass     string       `json:"pass,omitempty"`
	Model    string       `json:"model,omitempty"`
	Amount   money.Micros `json:"amount_micros,omitempty"`
	Created  time.Time    `json:"created"`
	Deadline time.Time    `json:"deadline"`
	Waiters  int          `json:"waiters"`
}

// ApprovalGrant is an allowance attached to an approval.
type ApprovalGrant struct {
	Amount money.Micros  `json:"amount_micros"`
	For    time.Duration `json:"for_ns"`
}

// DecideRequest is the body of POST /v1/approvals/{id}.
type DecideRequest struct {
	Approved bool           `json:"approved"`
	Grant    *ApprovalGrant `json:"grant,omitempty"`
}

// AuditRecord is one audit log record.
type AuditRecord struct {
	Seq    uint64         `json:"seq"`
	TS     time.Time      `json:"ts"`
	Type   string         `json:"type"`
	Fields map[string]any `json:"fields,omitempty"`
	Hash   string         `json:"hash"`
}

// AuditVerify is the response of GET /v1/audit/verify.
type AuditVerify struct {
	OK              bool   `json:"ok"`
	Records         int    `json:"records"`
	Files           int    `json:"files"`
	Anchors         int    `json:"anchors"`
	AnchorsVerified int    `json:"anchors_verified"`
	KeyUsed         bool   `json:"key_used"`
	Problem         string `json:"problem,omitempty"`
}

// RotateRecoveryResponse is the response of POST /v1/vault/recovery. Code
// is the new recovery code, shown once.
type RotateRecoveryResponse struct {
	Code    string `json:"code"`
	Warning string `json:"warning,omitempty"`
}
