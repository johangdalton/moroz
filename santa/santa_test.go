package santa

import (
	"bytes"
	"os"
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
