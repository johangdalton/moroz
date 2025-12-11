// Package santa defines types for a Santa sync server.
package santa

import (
	"github.com/pkg/errors"
)

// Config represents the combination of the Preflight configuration and Rules
// for a given MachineID.
type Config struct {
	MachineID string `toml:"machine_id,omitempty"`
	Preflight
	Rules []Rule `toml:"rules"`
}

// Rule is a Santa rule.
// https://github.com/google/santa/blob/ff0efe952b2456b52fad2a40e6eedb0931e6bdf7/docs/development/sync-protocol.md#rules-objects
type Rule struct {
	RuleType              RuleType `json:"rule_type" toml:"rule_type"`
	Policy                Policy   `json:"policy" toml:"policy"`
	Identifier            string   `json:"identifier" toml:"identifier"`
	CustomMessage         string   `json:"custom_msg,omitempty" toml:"custom_msg,omitempty"`
	CustomUrl             string   `json:"custom_url,omitempty" toml:"custom_url,omitempty"`
	FileBundleBinaryCount *int     `json:"file_bundle_binary_count,omitempty" toml:"file_bundle_binary_count,omitempty"`
	FileBundleHash        *string  `json:"file_bundle_hash,omitempty" toml:"file_bundle_hash,omitempty"`
	DeprecatedSHA256      *string  `json:"deprecated_sha256,omitempty" toml:"deprecated_sha256,omitempty"`
}

// Preflight represents sync response sent to a Santa client by the sync server.
// https://github.com/google/santa/blob/344a35aaf63c24a56f7a021ce18ecab090584da3/docs/development/sync-protocol.md#preflight-response
type Preflight struct {
	ClientMode ClientMode `json:"client_mode" toml:"client_mode"`

	// Sync configuration
	SyncType                                      SyncType `json:"sync_type,omitempty" toml:"sync_type,omitempty"`
	BatchSize                                     int      `json:"batch_size" toml:"batch_size"`
	FullSyncIntervalSeconds                       int      `json:"full_sync_interval" toml:"full_sync_interval_seconds"`
	PushNotificationFullSyncIntervalSeconds       int      `json:"push_notification_full_sync_interval" toml:"push_notification_full_sync_interval_seconds,omitempty"`
	PushNotificationGlobalRuleSyncDeadlineSeconds int      `json:"push_notification_global_rule_sync_deadline" toml:"push_notification_global_rule_sync_deadline_seconds,omitempty"`

	// File-system policy
	BlockedPathRegex         string               `json:"blocked_path_regex,omitempty" toml:"blocked_path_regex,omitempty"`
	AllowedPathRegex         string               `json:"allowed_path_regex,omitempty" toml:"allowed_path_regex,omitempty"`
	BlockUSBMount            bool                 `json:"block_usb_mount" toml:"block_usb_mount,omitempty"`
	RemountUSBMode           []string             `json:"remount_usb_mode,omitempty" toml:"remount_usb_mode,omitempty"`
	OverrideFileAccessAction FileAccessAction     `json:"override_file_access_action,omitempty" toml:"override_file_access_action,omitempty"`
	EventDetailURL           string               `json:"event_detail_url,omitempty" toml:"event_detail_url,omitempty"`
	EventDetailText          string               `json:"event_detail_text,omitempty" toml:"event_detail_text,omitempty"`
	ExportConfiguration      *ExportConfiguration `json:"export_configuration,omitempty" toml:"export_configuration,omitempty"`

	// Event upload controls
	EnableAllEventUpload      bool `json:"enable_all_event_upload" toml:"enable_all_event_upload"`
	DisableUnknownEventUpload bool `json:"disable_unknown_event_upload" toml:"disable_unknown_event_upload,omitempty"`

	// Rules / bundles
	EnableBundles         bool `json:"enable_bundles" toml:"enable_bundles"`
	EnableTransitiveRules bool `json:"enable_transitive_rules" toml:"enable_transitive_rules"`

	// Deprecated compatibility fields
	CleanSync                                  bool   `json:"clean_sync,omitempty" toml:"clean_sync,omitempty"`
	DeprecatedBundlesEnabled                   bool   `json:"bundles_enabled,omitempty" toml:"deprecated_bundles_enabled,omitempty"`
	DeprecatedWhitelistRegex                   string `json:"whitelist_regex,omitempty" toml:"deprecated_whitelist_regex,omitempty"`
	DeprecatedBlacklistRegex                   string `json:"blacklist_regex,omitempty" toml:"deprecated_blacklist_regex,omitempty"`
	DeprecatedEnabledTransitiveWhitelisting    bool   `json:"enabled_transitive_whitelisting,omitempty" toml:"deprecated_enabled_transitive_whitelisting,omitempty"`
	DeprecatedTransitiveWhitelistingEnabled    bool   `json:"transitive_whitelisting_enabled,omitempty" toml:"deprecated_transitive_whitelisting_enabled,omitempty"`
	DeprecatedFcmFullSyncIntervalSeconds       int    `json:"fcm_full_sync_interval,omitempty" toml:"deprecated_fcm_full_sync_interval_seconds,omitempty"`
	DeprecatedFcmGlobalRuleSyncDeadlineSeconds int    `json:"fcm_global_rule_sync_deadline,omitempty" toml:"deprecated_fcm_global_rule_sync_deadline_seconds,omitempty"`
}

// A PreflightPayload represents the request sent by a santa client to the sync server.
// https://github.com/google/santa/blob/344a35aaf63c24a56f7a021ce18ecab090584da3/docs/development/sync-protocol.md#preflight-request
type PreflightPayload struct {
	SerialNumber          string     `json:"serial_num"`
	Hostname              string     `json:"hostname"`
	OSVersion             string     `json:"os_version"`
	OSBuild               string     `json:"os_build"`
	ModelIdentifier       string     `json:"model_identifier"`
	SantaVersion          string     `json:"santa_version"`
	PrimaryUser           string     `json:"primary_user"`
	PushNotificationToken string     `json:"push_notification_token,omitempty"`
	BinaryRuleCount       int        `json:"binary_rule_count"`
	CertificateRuleCount  int        `json:"certificate_rule_count"`
	CompilerRuleCount     int        `json:"compiler_rule_count"`
	TransitiveRuleCount   int        `json:"transitive_rule_count"`
	TeamIDRuleCount       int        `json:"teamid_rule_count"`
	SigningIDRuleCount    int        `json:"signingid_rule_count"`
	CdHashRuleCount       int        `json:"cdhash_rule_count"`
	ClientMode            ClientMode `json:"client_mode"`
	RequestCleanSync      bool       `json:"request_clean_sync"`
	// Optional self-reported policy hints (pass-through)
	BlockedPathRegex          string           `json:"blocked_path_regex,omitempty"`
	AllowedPathRegex          string           `json:"allowed_path_regex,omitempty"`
	BlockUSBMount             bool             `json:"block_usb_mount,omitempty"`
	RemountUSBMode            []string         `json:"remount_usb_mode,omitempty"`
	OverrideFileAccessAction  FileAccessAction `json:"override_file_access_action,omitempty"`
	DisableUnknownEventUpload bool             `json:"disable_unknown_event_upload,omitempty"`
	MachineID                 string           `json:"machine_id,omitempty"`
}

// Postflight represents sync response sent to a Santa client by the sync server.
// Currently, this is a no-op.
type Postflight struct {
	NoOp struct{}
}

// A PostflightPayload represents the request sent by a santa client to the sync server.
// https://github.com/google/santa/blob/344a35aaf63c24a56f7a021ce18ecab090584da3/docs/development/sync-protocol.md#postflight-request
type PostflightPayload struct {
	MachineID      string   `json:"machine_id,omitempty"`
	SyncType       SyncType `json:"sync_type,omitempty"`
	RulesReceived  int      `json:"rules_received"`
	RulesProcessed int      `json:"rules_processed"`
}

// ExportConfiguration encapsulates export destinations Santa can push data to.
type ExportConfiguration struct {
	SignedPost *SignedPost `json:"signed_post,omitempty" toml:"signed_post,omitempty"`
}

// SignedPost describes a pre-signed POST destination for uploads.
type SignedPost struct {
	URL        string            `json:"url" toml:"url"`
	FormValues map[string]string `json:"form_values" toml:"form_values"`
}

// EventPayload represents derived metadata for events uploaded with the UploadEvent endpoint.
type EventPayload struct {
	FileSHA   string  `json:"file_sha256"`
	UnixTime  float64 `json:"execution_time"`
	EventInfo EventUploadEvent
}

// EventUploadRequest encapsulation of an /eventupload POST body sent by a Santa client
type EventUploadRequest struct {
	MachineID string             `json:"machine_id,omitempty"`
	Events    []EventUploadEvent `json:"events"`
}

// EventUploadResponse mirrors santa.sync.v1.EventUploadResponse.
type EventUploadResponse struct {
	EventUploadBundleBinaries []string `json:"event_upload_bundle_binaries,omitempty"`
}

// EventUploadEvent is a single event entry
// https://github.com/google/santa/blob/344a35aaf63c24a56f7a021ce18ecab090584da3/docs/development/sync-protocol.md#event-objects
type EventUploadEvent struct {
	CurrentSessions              []string       `json:"current_sessions"`
	Decision                     string         `json:"decision"`
	ExecutingUser                string         `json:"executing_user"`
	ExecutionTime                float64        `json:"execution_time"`
	FileBundleBinaryCount        int64          `json:"file_bundle_binary_count"`
	FileBundleExecutableRelPath  string         `json:"file_bundle_executable_rel_path"`
	FileBundleHash               string         `json:"file_bundle_hash"`
	FileBundleHashMilliseconds   float64        `json:"file_bundle_hash_millis"`
	FileBundleID                 string         `json:"file_bundle_id"`
	FileBundleName               string         `json:"file_bundle_name"`
	FileBundlePath               string         `json:"file_bundle_path"`
	FileBundleShortVersionString string         `json:"file_bundle_version_string"`
	FileBundleVersion            string         `json:"file_bundle_version"`
	FileName                     string         `json:"file_name"`
	FilePath                     string         `json:"file_path"`
	FileSHA256                   string         `json:"file_sha256"`
	LoggedInUsers                []string       `json:"logged_in_users"`
	ParentName                   string         `json:"parent_name"`
	ParentProcessID              int            `json:"ppid"`
	ProcessID                    int            `json:"pid"`
	QuarantineAgentBundleID      string         `json:"quarantine_agent_bundle_id"`
	QuarantineDataUrl            string         `json:"quarantine_data_url"`
	QuarantineRefererUrl         string         `json:"quarantine_referer_url"`
	QuarantineTimestamp          float64        `json:"quarantine_timestamp"`
	SigningChain                 []SigningEntry `json:"signing_chain"`
	SigningID                    string         `json:"signing_id"`
	TeamID                       string         `json:"team_id"`
	CdHash                       string         `json:"cdhash"`
}

// SigningEntry is optionally present when an event includes a binary that is signed
type SigningEntry struct {
	CertificateName    string `json:"cn"`
	Organization       string `json:"org"`
	OrganizationalUnit string `json:"ou"`
	SHA256             string `json:"sha256"`
	ValidFrom          int    `json:"valid_from"`
	ValidUntil         int    `json:"valid_until"`
}

// RuleType represents a Santa rule type.
type RuleType int

const (
	RuleTypeUnknown RuleType = iota

	// Binary rules use the SHA-256 hash of the entire binary as an identifier.
	Binary

	// Certificate rules are formed from the SHA-256 fingerprint of an X.509 leaf signing certificate.
	// This is a powerful rule type that has a much broader reach than an individual binary rule .
	// A signing certificate can sign any number of binaries.
	Certificate

	// TeamID rules are the 10-character identifier issued by Apple and tied to developer accounts/organizations.
	// This is an even more powerful rule with broader reach than individual certificate rules.
	// ie. EQHXZ8M8AV for Google
	TeamID

	// Signing IDs are arbitrary identifiers under developer control that are given to a binary at signing time.
	// Because the signing IDs are arbitrary, the Santa rule identifier must be prefixed with the Team ID associated
	// with the Apple developer certificate used to sign the application.
	// ie. EQHXZ8M8AV:com.google.Chrome
	SigningID

	// CDHash rules use a binary's code directory hash as an identifier. This is the most specific rule in Santa.
	// The code directory hash identifies a specific version of a program, similar to a file hash.
	// Note that the operating system evaluates the cdhash lazily, only verifying pages of code when they're mapped in.
	// This means that it is possible for a file hash to change, but a binary could still execute as long as modified
	// pages are not mapped in. Santa only considers CDHash rules for processes that have CS_KILL or CS_HARD
	// codesigning flags set to ensure that a process will be killed if the CDHash was tampered with
	// (assuming the system has SIP enabled).
	CdHash
)

func (r *RuleType) UnmarshalText(text []byte) error {
	switch t := string(text); t {
	case "RULETYPE_UNKNOWN":
		*r = RuleTypeUnknown
	case "BINARY":
		*r = Binary
	case "CERTIFICATE":
		*r = Certificate
	case "TEAMID":
		*r = TeamID
	case "SIGNINGID":
		*r = SigningID
	case "CDHASH":
		*r = CdHash
	default:
		return errors.Errorf("unknown rule_type value %q", t)
	}
	return nil
}

func (r RuleType) MarshalText() ([]byte, error) {
	switch r {
	case RuleTypeUnknown:
		return []byte("RULETYPE_UNKNOWN"), nil
	case Binary:
		return []byte("BINARY"), nil
	case Certificate:
		return []byte("CERTIFICATE"), nil
	case TeamID:
		return []byte("TEAMID"), nil
	case SigningID:
		return []byte("SIGNINGID"), nil
	case CdHash:
		return []byte("CDHASH"), nil
	default:
		return nil, errors.Errorf("unknown rule_type %d", r)
	}
}

// Policy represents the Santa Rule Policy.
type Policy int

const (
	PolicyUnknown Policy = iota
	Allowlist
	AllowlistCompiler
	Blocklist
	SilentBlocklist
	Remove
	Cel
)

func (p *Policy) UnmarshalText(text []byte) error {
	switch t := string(text); t {
	case "ALLOWLIST":
		*p = Allowlist
	case "ALLOWLIST_COMPILER":
		*p = AllowlistCompiler
	case "BLOCKLIST":
		*p = Blocklist
	case "SILENT_BLOCKLIST":
		*p = SilentBlocklist
	case "REMOVE":
		*p = Remove
	case "CEL":
		*p = Cel
	case "POLICY_UNKNOWN":
		*p = PolicyUnknown
	// Backward-compat aliases
	case "WHITELIST":
		*p = Allowlist
	case "WHITELIST_COMPILER":
		*p = AllowlistCompiler
	case "BLACKLIST":
		*p = Blocklist
	case "SILENT_BLACKLIST":
		*p = SilentBlocklist
	default:
		return errors.Errorf("unknown policy value %q", t)
	}
	return nil
}

func (p Policy) MarshalText() ([]byte, error) {
	switch p {
	case PolicyUnknown:
		return []byte("POLICY_UNKNOWN"), nil
	case Allowlist:
		return []byte("ALLOWLIST"), nil
	case AllowlistCompiler:
		return []byte("ALLOWLIST_COMPILER"), nil
	case Blocklist:
		return []byte("BLOCKLIST"), nil
	case SilentBlocklist:
		return []byte("SILENT_BLOCKLIST"), nil
	case Remove:
		return []byte("REMOVE"), nil
	case Cel:
		return []byte("CEL"), nil
	default:
		return nil, errors.Errorf("unknown policy %d", p)
	}
}

// ClientMode specifies which mode the Santa client will evaluate rules in.
type ClientMode int

const (
	Monitor ClientMode = iota
	Lockdown
)

func (c *ClientMode) UnmarshalText(text []byte) error {
	switch mode := string(text); mode {
	case "MONITOR":
		*c = Monitor
	case "LOCKDOWN":
		*c = Lockdown
	default:
		return errors.Errorf("unknown client_mode value %q", mode)
	}
	return nil
}

func (c ClientMode) MarshalText() ([]byte, error) {
	switch c {
	case Monitor:
		return []byte("MONITOR"), nil
	case Lockdown:
		return []byte("LOCKDOWN"), nil
	default:
		return nil, errors.Errorf("unknown client_mode %d", c)
	}
}

// SyncType mirrors the Santa sync_type values (deprecated in upstream but retained for compatibility).
type SyncType int

const (
	SyncTypeUnspecified SyncType = iota
	SyncTypeNormal
	SyncTypeClean
	SyncTypeCleanAll
)

func (s *SyncType) UnmarshalText(text []byte) error {
	switch t := string(text); t {
	case "", "SYNC_TYPE_UNSPECIFIED":
		*s = SyncTypeUnspecified
	case "NORMAL":
		*s = SyncTypeNormal
	case "CLEAN":
		*s = SyncTypeClean
	case "CLEAN_ALL":
		*s = SyncTypeCleanAll
	default:
		return errors.Errorf("unknown sync_type value %q", t)
	}
	return nil
}

func (s SyncType) MarshalText() ([]byte, error) {
	switch s {
	case SyncTypeUnspecified:
		return []byte("SYNC_TYPE_UNSPECIFIED"), nil
	case SyncTypeNormal:
		return []byte("NORMAL"), nil
	case SyncTypeClean:
		return []byte("CLEAN"), nil
	case SyncTypeCleanAll:
		return []byte("CLEAN_ALL"), nil
	default:
		return nil, errors.Errorf("unknown sync_type %d", s)
	}
}

// FileAccessAction controls Santa's temporary file access remount behaviour.
type FileAccessAction int

const (
	FileAccessActionUnspecified FileAccessAction = iota
	FileAccessActionNone
	FileAccessActionAuditOnly
	FileAccessActionDisable
)

func (a *FileAccessAction) UnmarshalText(text []byte) error {
	switch t := string(text); t {
	case "", "FILE_ACCESS_ACTION_UNSPECIFIED":
		*a = FileAccessActionUnspecified
	case "NONE", "none":
		*a = FileAccessActionNone
	case "AUDIT_ONLY", "auditonly":
		*a = FileAccessActionAuditOnly
	case "DISABLE", "disable":
		*a = FileAccessActionDisable
	default:
		return errors.Errorf("unknown override_file_access_action value %q", t)
	}
	return nil
}

func (a FileAccessAction) MarshalText() ([]byte, error) {
	switch a {
	case FileAccessActionUnspecified:
		return []byte("FILE_ACCESS_ACTION_UNSPECIFIED"), nil
	case FileAccessActionNone:
		return []byte("none"), nil
	case FileAccessActionAuditOnly:
		return []byte("auditonly"), nil
	case FileAccessActionDisable:
		return []byte("disable"), nil
	default:
		return nil, errors.Errorf("unknown override_file_access_action %d", a)
	}
}
