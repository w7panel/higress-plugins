package wasmplugin

import (
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
		{"custom only", `{"useCRS":false,"engineMode":"DetectionOnly","secRules":["SecRule REQUEST_URI \"@streq /probe\" \"id:1000000,phase:1,deny\""]}`, "SecRuleEngine DetectionOnly", "Include @owasp_crs/"},
		{"one conf", `{"useCRS":true,"paranoiaLevel":2,"ruleFiles":["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]}`, "Include @owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "Include @owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf"},
		{"all conf", `{"useCRS":true}`, "Include @owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf", ""},
		{"one rule disabled", `{"useCRS":true,"ruleFiles":["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"],"secRules":["SecRuleRemoveById 942100"]}`, "SecRuleRemoveById 942100", ""},
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
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".conf") || !isDetectionFile(name) {
			continue
		}
		t.Run(name, func(t *testing.T) {
			config := `{"useCRS":true,"ruleFiles":["` + name + `"]}`
			directives, err := buildDirectives(gjson.Parse(config))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(root).WithDirectives(directives)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRejectInvalidConfig(t *testing.T) {
	for _, value := range []string{
		`{"useCRS":true,"ruleFiles":["../REQUEST-942.conf"]}`,
		`{"useCRS":true,"ruleFiles":[42]}`,
		`{"useCRS":true,"paranoiaLevel":5}`,
		`{"engineMode":"Disabled"}`,
	} {
		if _, err := buildDirectives(gjson.Parse(value)); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
}

func TestSelectedSQLiRuleBlocks(t *testing.T) {
	directives, err := buildDirectives(gjson.Parse(`{"useCRS":true,"ruleFiles":["REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]}`))
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
