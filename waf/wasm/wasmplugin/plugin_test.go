package wasmplugin

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/tidwall/gjson"
)

func TestBuildDirectives(t *testing.T) {
	cases := []struct {
		name    string
		config  string
		want    string
		notWant string
	}{
		{"custom only", `{"useCRS":false,"engineMode":"DetectionOnly","customRules":[{"id":1000000,"rule":"SecRule REQUEST_URI \"@streq /probe\" \"id:1000000,phase:1,deny\"","enabled":true}]}`, "SecRule REQUEST_URI", "Include @owasp_crs/"},
		{"missing enabled stays off", `{"customRules":[{"id":1000000,"rule":"SecRule REQUEST_URI \"@streq /probe\" \"id:1000000,phase:1,deny\""}]}`, "SecRuleEngine On", "SecRule REQUEST_URI"},
		{"category off", `{"useCRS":true,"paranoiaLevel":2,"categories":{"REQUEST-941-APPLICATION-ATTACK-XSS":false}}`, "Include @owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "Include @owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf"},
		{"all conf", `{"useCRS":true}`, "Include @owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf", ""},
		{"one rule disabled", `{"useCRS":true,"ruleStates":{"942100":false}}`, "SecRuleRemoveById 942100", ""},
		{"category disabled", `{"useCRS":true,"categories":{"REQUEST-941-APPLICATION-ATTACK-XSS":false}}`, "Include @owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "Include @owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf"},
		{"policy directives", `{"useCRS":true,"ruleStates":{"942100":false},"customRules":[{"id":1000000,"rule":"SecRule REQUEST_URI \"@streq /probe\" \"id:1000000,phase:1,deny\"","enabled":true}]}`, "SecRuleRemoveById 942100", ""},
		{"disabled category and rule", `{"useCRS":true,"categories":{"REQUEST-942-APPLICATION-ATTACK-SQLI":false},"ruleStates":{"942100":false}}`, "Include @owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf", "SecRuleRemoveById 942100"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			directives, err := buildDirectives(gjson.Parse(tc.config))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(directives, tc.want) || (tc.notWant != "" && strings.Contains(directives, tc.notWant)) {
				t.Fatalf("unexpected directives: %s", directives)
			}
			if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(root).WithDirectives(directives)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEachCRSFileCompiles(t *testing.T) {
	entries, err := fs.ReadDir(root, "@owasp_crs")
	if err != nil {
		t.Fatal(err)
	}
	categories := map[string]bool{}
	for _, entry := range entries {
		if isDetectionFile(entry.Name()) && strings.HasSuffix(entry.Name(), ".conf") {
			categories[strings.TrimSuffix(entry.Name(), ".conf")] = false
		}
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".conf") || !isDetectionFile(name) {
			continue
		}
		t.Run(name, func(t *testing.T) {
			categories[strings.TrimSuffix(name, ".conf")] = true
			config, err := json.Marshal(map[string]any{"useCRS": true, "categories": categories})
			if err != nil {
				t.Fatal(err)
			}
			directives, err := buildDirectives(gjson.ParseBytes(config))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(root).WithDirectives(directives)); err != nil {
				t.Fatal(err)
			}
			categories[strings.TrimSuffix(name, ".conf")] = false
		})
	}
}

func TestRejectInvalidConfig(t *testing.T) {
	for _, value := range []string{
		`{"useCRS":true,"categories":{"../REQUEST-942":true}}`,
		`{"useCRS":true,"categories":{"REQUEST-942-APPLICATION-ATTACK-SQLI.conf":true}}`,
		`{"useCRS":true,"paranoiaLevel":5}`,
		`{"engineMode":"Disabled"}`,
		`{"useCRS":true,"categories":{"../bad":true}}`,
		`{"useCRS":true,"ruleStates":{"999999":false}}`,
	} {
		if _, err := buildDirectives(gjson.Parse(value)); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
}

func TestSelectedSQLiRuleBlocks(t *testing.T) {
	directives, err := buildDirectives(gjson.Parse(`{"useCRS":true,"categories":{"REQUEST-941-APPLICATION-ATTACK-XSS":false}}`))
	if err != nil {
		t.Fatal(err)
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(root).WithDirectives(directives))
	if err != nil {
		t.Fatal(err)
	}
	for _, uri := range []string{"/?x=1%20UNION%20SELECT%201,2,3", "/?id=1%27%20OR%20%271%27%3D%271"} {
		tx := waf.NewTransaction()
		tx.ProcessURI(uri, "GET", "HTTP/1.1")
		tx.AddRequestHeader("Host", "example.com")
		interruption := tx.ProcessRequestHeaders()
		if interruption == nil {
			interruption, err = tx.ProcessRequestBody()
			if err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("%s: %+v", uri, interruption)
		tx.Close()
	}
}
