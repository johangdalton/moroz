package santa

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestConfigMarshalUnmarshal(t *testing.T) {
	conf := testConfig(t, "testdata/config_a_toml.golden", (os.Getenv("REPLACE_GOLDEN") == "TRUE"))

	if have, want := conf.ClientMode, Lockdown; have != want {
		t.Errorf("have client_mode %d, want %d\n", have, want)
	}

	if have, want := conf.FullSyncIntervalSeconds, 600; have != want {
		t.Errorf("have full_sync_interval_seconds %d, want %d\n", have, want)
	}

	if have, want := conf.SyncType, SyncTypeClean; have != want {
		t.Errorf("have sync_type %d, want %d\n", have, want)
	}

	if have, want := conf.DisableUnknownEventUpload, true; have != want {
		t.Errorf("have disable_unknown_event_upload %t, want %t\n", have, want)
	}

	if have, want := conf.PushNotificationFullSyncIntervalSeconds, 14400; have != want {
		t.Errorf("have push_notification_full_sync_interval_seconds %d, want %d\n", have, want)
	}

	if have, want := conf.PushNotificationGlobalRuleSyncDeadlineSeconds, 600; have != want {
		t.Errorf("have push_notification_global_rule_sync_deadline_seconds %d, want %d\n", have, want)
	}

	if have, want := conf.BlockUSBMount, true; have != want {
		t.Errorf("have block_usb_mount %t, want %t\n", have, want)
	}

	if have, want := len(conf.RemountUSBMode), 2; have != want {
		t.Errorf("have remount_usb_mode len %d, want %d\n", have, want)
	}

	if have, want := conf.OverrideFileAccessAction, FileAccessActionAuditOnly; have != want {
		t.Errorf("have override_file_access_action %d, want %d\n", have, want)
	}

	if have, want := conf.EventDetailURL, "https://example.com/block?path=%{path}"; have != want {
		t.Errorf("have event_detail_url %s, want %s\n", have, want)
	}

	if have, want := conf.EventDetailText, "More details"; have != want {
		t.Errorf("have event_detail_text %s, want %s\n", have, want)
	}

	if conf.ExportConfiguration == nil || conf.ExportConfiguration.SignedPost == nil {
		t.Fatalf("export_configuration.signed_post missing\n")
	}
	if have, want := conf.ExportConfiguration.SignedPost.URL, "https://storage.example.com/upload"; have != want {
		t.Errorf("have signed_post.url %s, want %s\n", have, want)
	}
	if have, want := conf.ExportConfiguration.SignedPost.FormValues["key"], "uploads/${filename}"; have != want {
		t.Errorf("have signed_post.form_values[key] %s, want %s\n", have, want)
	}

	if have, want := conf.Rules[0].Identifier, "2dc104631939b4bdf5d6bccab76e166e37fe5e1605340cf68dab919df58b8eda"; have != want {
		t.Errorf("have identifier %s, want %s\n", have, want)
	}

	if have, want := conf.Rules[0].RuleType, Binary; have != want {
		t.Errorf("have rule_type %d, want %d\n", have, want)
	}

	if have, want := conf.Rules[1].RuleType, Certificate; have != want {
		t.Errorf("have rule_type %d, want %d\n", have, want)
	}

	if have, want := conf.Rules[2].RuleType, TeamID; have != want {
		t.Errorf("have rule_tpe %d, want %d\n", have, want)
	}

	if have, want := conf.Rules[3].RuleType, SigningID; have != want {
		t.Errorf("have rule_type %d, want %d\n", have, want)
	}

	if have, want := conf.Rules[4].RuleType, CdHash; have != want {
		t.Errorf("have rule_type %d, want %d\n", have, want)
	}

	if have, want := conf.Rules[0].Policy, Blocklist; have != want {
		t.Errorf("have policy %d, want %d\n", have, want)
	}

	if have, want := conf.Rules[1].Policy, Allowlist; have != want {
		t.Errorf("have policy %d, want %d\n", have, want)
	}

	if have, want := conf.Rules[5].Policy, AllowlistCompiler; have != want {
		t.Errorf("have policy %d, want %d\n", have, want)
	}

	if have, want := conf.Rules[6].Policy, Remove; have != want {
		t.Errorf("have policy %d, want %d\n", have, want)
	}

	if have, want := conf.Rules[10].CustomUrl, "https://go.dev"; have != want {
		t.Errorf("have custom_url %s, want %s\n", have, want)
	}

	// Full v1 vocabulary added on 2026-09-16.
	if conf.RemovableMediaPolicy == nil || conf.RemovableMediaPolicy.Action != RemovableMediaRemount || len(conf.RemovableMediaPolicy.Flags) != 2 {
		t.Errorf("removable_media_policy %+v", conf.RemovableMediaPolicy)
	}
	if conf.EncryptedRemovableMediaPolicy == nil || conf.EncryptedRemovableMediaPolicy.Action != RemovableMediaAllow {
		t.Errorf("encrypted_removable_media_policy %+v", conf.EncryptedRemovableMediaPolicy)
	}
	if have, want := conf.Rules[11].Policy, SilentGuiBlocklist; have != want {
		t.Errorf("have policy %d, want %d\n", have, want)
	}
	if have, want := conf.Rules[11].EventDetailButtonLabel, "Request access"; have != want {
		t.Errorf("have event_detail_button_label %s, want %s\n", have, want)
	}
	if have, want := conf.Rules[12].Policy, SilentTtyBlocklist; have != want {
		t.Errorf("have policy %d, want %d\n", have, want)
	}
	if have, want := conf.Rules[13].Policy, Cel; have != want {
		t.Errorf("have policy %d, want %d\n", have, want)
	}
	if !strings.HasPrefix(conf.Rules[13].CelExpr, "target.signing_time") {
		t.Errorf("have cel_expr %q", conf.Rules[13].CelExpr)
	}
	if have, want := conf.Rules[14].NotificationAppName, "Zoom"; have != want {
		t.Errorf("have notification_app_name %s, want %s\n", have, want)
	}
	for i, r := range conf.Rules {
		if err := ValidateRule(r); err != nil {
			t.Errorf("rule %d: %v", i, err)
		}
	}
	if err := conf.Preflight.Validate(); err != nil {
		t.Error(err)
	}
}

// The JSON Santa receives must use the protobuf names and the oneof shape of
// RemovableMediaPolicy from v1.proto; every new enum value must round-trip.
func TestV1VocabularyJSON(t *testing.T) {
	conf := testConfig(t, "testdata/config_a_toml.golden", false)
	data, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatal(err)
	}
	if want := map[string]interface{}{"remount": map[string]interface{}{"flags": []interface{}{"rdonly", "noexec"}}}; !reflect.DeepEqual(generic["removable_media_policy"], want) {
		t.Fatalf("removable_media_policy JSON %v", generic["removable_media_policy"])
	}
	if want := map[string]interface{}{"allow": true}; !reflect.DeepEqual(generic["encrypted_removable_media_policy"], want) {
		t.Fatalf("encrypted_removable_media_policy JSON %v", generic["encrypted_removable_media_policy"])
	}
	if block, _ := json.Marshal(RemovableMediaPolicy{Action: RemovableMediaBlock}); string(block) != `{"block":true}` {
		t.Fatalf("block JSON %s", block)
	}
	ruleData, _ := json.Marshal(conf.Rules)
	var rules []interface{}
	json.Unmarshal(ruleData, &rules)
	cel := rules[13].(map[string]interface{})
	if cel["policy"] != "CEL" || cel["cel_expr"] == nil || rules[11].(map[string]interface{})["policy"] != "SILENT_GUI_BLOCKLIST" || rules[12].(map[string]interface{})["policy"] != "SILENT_TTY_BLOCKLIST" {
		t.Fatalf("rule JSON %v %v %v", rules[11], rules[12], rules[13])
	}
	if rules[11].(map[string]interface{})["event_detail_button_label"] != "Request access" || rules[14].(map[string]interface{})["notification_app_name"] != "Zoom" {
		t.Fatalf("rule JSON %v %v", rules[11], rules[14])
	}
	var back Config
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ruleData, &back.Rules); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Rules, conf.Rules) || !reflect.DeepEqual(back.RemovableMediaPolicy, conf.RemovableMediaPolicy) || !reflect.DeepEqual(back.EncryptedRemovableMediaPolicy, conf.EncryptedRemovableMediaPolicy) {
		t.Fatalf("JSON round trip changed the config:\n%+v\n%+v", back.Rules, conf.Rules)
	}
	var bad RemovableMediaPolicy
	if err := json.Unmarshal([]byte(`{"allow":true,"block":true}`), &bad); err == nil {
		t.Fatal("two oneof arms accepted")
	}
	// Values Santa may report in requests must decode.
	for text, want := range map[string]ClientMode{"MONITOR": Monitor, "LOCKDOWN": Lockdown, "STANDALONE": Standalone} {
		var mode ClientMode
		if err := mode.UnmarshalText([]byte(text)); err != nil || mode != want {
			t.Fatalf("client_mode %s: %v %d", text, err, mode)
		}
	}
	var zero ClientMode
	if text, _ := zero.MarshalText(); string(text) != "MONITOR" {
		t.Fatalf("zero client_mode is %s", text)
	}
	for _, text := range []string{"NORMAL", "CLEAN", "CLEAN_ALL", "CLEAN_STANDALONE", "CLEAN_RULES", "CLEAN_FILE_ACCESS_RULES", "clean", "normal"} {
		var st SyncType
		if err := st.UnmarshalText([]byte(text)); err != nil {
			t.Fatalf("sync_type %s: %v", text, err)
		}
	}
	if !SyncTypeClean.IsClean() || !SyncTypeCleanAll.IsClean() || SyncTypeNormal.IsClean() || SyncTypeCleanStandalone.IsClean() {
		t.Fatal("IsClean")
	}
	for _, policy := range []Policy{Allowlist, AllowlistCompiler, Blocklist, SilentBlocklist, Remove, Cel, SilentGuiBlocklist, SilentTtyBlocklist} {
		text, err := policy.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var back Policy
		if err := back.UnmarshalText(text); err != nil || back != policy {
			t.Fatalf("policy %s does not round-trip", text)
		}
	}
}

func TestRuleAndPreflightValidation(t *testing.T) {
	if err := ValidateRule(Rule{Policy: Cel}); err == nil {
		t.Fatal("CEL without cel_expr accepted")
	}
	if err := ValidateRule(Rule{Policy: Blocklist, EventDetailButtonLabel: strings.Repeat("x", MaxEventDetailButtonLabel+1)}); err == nil {
		t.Fatal("49-character button label accepted")
	}
	if err := ValidateRule(Rule{Policy: Blocklist, EventDetailButtonLabel: strings.Repeat("x", MaxEventDetailButtonLabel)}); err != nil {
		t.Fatal(err)
	}
	if err := (Preflight{RemovableMediaPolicy: &RemovableMediaPolicy{}}).Validate(); err == nil {
		t.Fatal("removable media policy without action accepted")
	}
	if err := (Preflight{EncryptedRemovableMediaPolicy: &RemovableMediaPolicy{Action: RemovableMediaBlock, Flags: []string{"rdonly"}}}).Validate(); err == nil {
		t.Fatal("flags with BLOCK accepted")
	}
	if err := (Preflight{}).Validate(); err != nil {
		t.Fatal(err)
	}
}

// Every field of v1.proto Event decodes from Santa's JSON and re-encodes under
// the same name for the telemetry envelope.
func TestEventUploadEventForwardsIdentityFields(t *testing.T) {
	input := `{"file_sha256":"` + strings.Repeat("a", 64) + `","file_name":"CptHost","file_path":"/Applications/zoom.us.app/Contents/Frameworks/cpthost.app/Contents/MacOS",
		"file_bundle_id":"us.zoom.CptHost","file_bundle_name":"zoom.us","file_bundle_path":"/Applications/zoom.us.app","file_bundle_version":"12345","file_bundle_version_string":"6.1.0",
		"file_bundle_executable_rel_path":"Contents/MacOS/CptHost","file_bundle_hash":"` + strings.Repeat("b", 64) + `","file_bundle_binary_count":7,
		"signing_chain":[{"sha256":"` + strings.Repeat("c", 64) + `","cn":"Developer ID Application: Zoom","org":"Zoom Video Communications, Inc.","ou":"BJ4HAAB9B3","valid_from":1600000000,"valid_until":1900000000}],
		"signing_status":"SIGNING_STATUS_PRODUCTION","cs_flags":570503953,"signing_time":1700000000,"secure_signing_time":1700000001,"static_rule":true,
		"entitlement_info":{"entitlements_filtered":false,"entitlements":[{"key":"com.apple.security.cs.allow-jit","value":"true"}]},
		"decision":"BLOCK_UNKNOWN","parent_name":"launchd","logged_in_users":["student"],"current_sessions":["student@console"],"execution_time":1758000000.5,"pid":4242,"ppid":1,
		"team_id":"BJ4HAAB9B3","signing_id":"BJ4HAAB9B3:us.zoom.CptHost","cdhash":"` + strings.Repeat("d", 40) + `"}`
	var ev EventUploadEvent
	if err := json.Unmarshal([]byte(input), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.FileBundleName != "zoom.us" || ev.FileBundleBinaryCount != 7 || ev.SigningStatus != "SIGNING_STATUS_PRODUCTION" || ev.CsFlags != 570503953 ||
		ev.SigningTime != 1700000000 || ev.SecureSigningTime != 1700000001 || !ev.StaticRule || len(ev.SigningChain) != 1 || ev.SigningChain[0].Organization != "Zoom Video Communications, Inc." {
		t.Fatalf("%+v", ev)
	}
	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var want, got map[string]interface{}
	json.Unmarshal([]byte(input), &want)
	json.Unmarshal(out, &got)
	for key, value := range want {
		if !reflect.DeepEqual(got[key], value) {
			t.Errorf("%s: sent %v, forwarded %v", key, value, got[key])
		}
	}
	// Deprecated quarantine fields decode too, and an absent entitlement_info stays absent.
	var plain EventUploadEvent
	json.Unmarshal([]byte(`{"file_sha256":"x","quarantine_timestamp":1,"quarantine_data_url":"https://example.com"}`), &plain)
	out, _ = json.Marshal(plain)
	if strings.Contains(string(out), "entitlement_info") || strings.Contains(string(out), "static_rule") {
		t.Fatalf("zero identity fields emitted: %s", out)
	}
}

func testConfig(t *testing.T, path string, replace bool) Config {
	t.Helper()

	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("loading config from path %q, err = %q\n", path, err)
	}

	var conf Config
	if err := toml.Unmarshal(file, &conf); err != nil {
		t.Fatalf("unmarshal config from path %q, err = %q\n", path, err)
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(&conf); err != nil {
		t.Fatalf("encode config from path %q, err = %q\n", path, err)
	}

	if replace {
		if err := os.WriteFile(path, buf.Bytes(), os.ModePerm); err != nil {
			t.Fatalf("replace config at path %q, err = %q\n", path, err)
		}
		return testConfig(t, path, false)
	}

	if !bytes.Equal(file, buf.Bytes()) {
		t.Errorf("marshaling config to %q failed\nEXPECTED:\n%s\nGOT:\n%s\n", path, string(file), buf.Bytes())

	}

	return conf
}
