package wasmplugin

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
)

func PluginStart() {
	wrapper.SetCtx(
		"waf-plugin-go",
		wrapper.ParseConfigWithContext(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
		wrapper.ProcessRequestBodyBy(onHttpRequestBody),
		wrapper.ProcessResponseBodyBy(onHttpResponseBody),
		wrapper.ProcessResponseHeadersBy(onHttpResponseHeaders),
		wrapper.ProcessStreamDoneBy(onHttpStreamDone),
	)
}

type WafConfig struct {
	waf coraza.WAF
	// tx  ctypes.Transaction
}

type compiledWAF struct {
	directives string
	waf        coraza.WAF
}

func parseConfig(ctx wrapper.PluginContext, json gjson.Result, config *WafConfig) error {
	// Reclaim previous rules and parser temporaries before another config is parsed.
	runtime.GC()
	directives, err := buildDirectives(json)
	if err != nil {
		return err
	}
	if cached, ok := ctx.GetContext("compiledWAF").(compiledWAF); ok && cached.directives == directives {
		config.waf = cached.waf
		return nil
	}
	conf := coraza.NewWAFConfig().
		WithErrorCallback(logError).
		WithDebugLogger(debuglog.DefaultWithPrinterFactory(logPrinterFactory)).
		WithRootFS(root)
	waf, err := coraza.NewWAF(conf.WithDirectives(directives))
	if err != nil {
		proxywasm.LogErrorf("Failed to create waf conf: %v", err)
		return errors.New("failed to create waf conf")
	}
	ctx.SetContext("compiledWAF", compiledWAF{directives: directives, waf: waf})
	config.waf = waf
	// Drop parser temporaries before the next configuration update.
	runtime.GC()
	return nil
}

func buildDirectives(json gjson.Result) (string, error) {
	var secRules []string
	mode := json.Get("engineMode").String()
	if mode == "" {
		mode = "On"
	}
	if mode != "On" && mode != "Off" && mode != "DetectionOnly" {
		return "", fmt.Errorf("invalid engine mode %q", mode)
	}
	level := json.Get("paranoiaLevel").Int()
	if level == 0 {
		level = 1
	}
	if level < 1 || level > 4 {
		return "", fmt.Errorf("invalid paranoia level %d", level)
	}
	if json.Get("useCRS").Bool() {
		categories := json.Get("categories")
		entries, err := fs.ReadDir(root, "@owasp_crs")
		if err != nil {
			return "", err
		}
		var available []string
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".conf") {
				continue
			}
			if isDetectionFile(name) {
				available = append(available, name)
			} else if isRequiredFile(name) {
				available = append(available, name)
			}
		}
		if categories.Exists() {
			if !categories.IsObject() {
				return "", errors.New("categories must be an object")
			}
			for name, enabled := range categories.Map() {
				file := name + ".conf"
				if !isDetectionFile(file) || !contains(available, file) || enabled.Type != gjson.True && enabled.Type != gjson.False {
					return "", fmt.Errorf("invalid CRS category %q", name)
				}
			}
		}
		sort.Strings(available)
		activeIDs := make(map[string]bool)
		knownIDs := make(map[string]bool)
		for _, name := range available {
			if !isDetectionFile(name) {
				continue
			}
			content, err := fs.ReadFile(root, "@owasp_crs/"+name)
			if err != nil {
				return "", err
			}
			for _, line := range strings.Split(string(content), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue
				}
				if match := crsRuleID.FindStringSubmatch(line); len(match) == 2 {
					knownIDs[match[1]] = true
					if categoryActive(name, categories) {
						activeIDs[match[1]] = true
					}
				}
			}
		}
		secRules = append(secRules, "Include @demo-conf", "Include @crs-setup-conf")
		secRules = append(secRules,
			fmt.Sprintf(`SecAction "id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d"`, level),
			fmt.Sprintf(`SecAction "id:900001,phase:1,pass,nolog,setvar:tx.detection_paranoia_level=%d"`, level))
		for _, name := range available {
			if strings.HasPrefix(name, "REQUEST-999-") {
				content, err := fs.ReadFile(root, "@owasp_crs/"+name)
				if err != nil {
					return "", err
				}
				for _, line := range strings.Split(string(content), "\n") {
					fields := strings.Fields(line)
					if len(fields) >= 3 && fields[0] == "SecRuleUpdateTargetById" && activeIDs[fields[1]] {
						secRules = append(secRules, line)
					}
				}
				continue
			}
			if isRequiredFile(name) || categoryActive(name, categories) {
				secRules = append(secRules, "Include @owasp_crs/"+name)
			}
		}
		states := json.Get("ruleStates")
		if states.Exists() {
			if !states.IsObject() {
				return "", errors.New("ruleStates must be an object")
			}
			for id, enabled := range states.Map() {
				if !enabled.Bool() {
					if _, err := strconv.Atoi(id); err != nil || !knownIDs[id] {
						return "", fmt.Errorf("invalid CRS rule ID %q", id)
					}
					if activeIDs[id] {
						secRules = append(secRules, "SecRuleRemoveById "+id)
					}
				}
			}
		}
	}
	if json.Get("requestBodyAccess").Bool() {
		secRules = append(secRules, "SecRequestBodyAccess On")
	}
	custom := json.Get("customRules")
	if custom.Exists() {
		if !custom.IsArray() {
			return "", errors.New("customRules must be an array")
		}
		for _, item := range custom.Array() {
			rule := item.Get("rule")
			if rule.Type != gjson.String {
				return "", errors.New("customRules must contain rules")
			}
			if !item.Get("enabled").Bool() {
				continue
			}
			secRules = append(secRules, rule.String())
		}
	}
	secRules = append(secRules, "SecRuleEngine "+mode)
	return strings.Join(secRules, "\n"), nil
}

var crsRuleID = regexp.MustCompile(`(?i)\bid\s*:\s*(\d+)`)

func categoryActive(name string, categories gjson.Result) bool {
	if category := categories.Get(strings.TrimSuffix(name, ".conf")); category.Exists() {
		return category.Bool()
	}
	return true
}

func contains(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

func isDetectionFile(name string) bool {
	return (strings.HasPrefix(name, "REQUEST-9") || strings.HasPrefix(name, "RESPONSE-9")) && !isRequiredFile(name)
}

func isRequiredFile(name string) bool {
	for _, prefix := range []string{"REQUEST-901-", "REQUEST-905-", "REQUEST-949-", "REQUEST-999-", "RESPONSE-959-", "RESPONSE-980-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config WafConfig, log log.Log) types.Action {
	ctx.SetContext("skipwaf", false)

	if ignoreBody() {
		ctx.DontReadRequestBody()
		ctx.DontReadResponseBody()
		ctx.SetContext("skipwaf", true)
		return types.ActionContinue
	}

	ctx.SetContext("interruptionHandled", false)
	ctx.SetContext("processedRequestBody", false)
	ctx.SetContext("processedResponseBody", false)
	ctx.SetContext("tx", config.waf.NewTransaction())

	tx := ctx.GetContext("tx").(ctypes.Transaction)

	protocol, err := proxywasm.GetProperty([]string{"request", "protocol"})
	if err != nil {
		// TODO(anuraaga): HTTP protocol is commonly required in WAF rules, we should probably
		// fail fast here, but proxytest does not support properties yet.
		protocol = []byte("HTTP/2.0")
	}

	ctx.SetContext("httpProtocol", string(protocol))

	// Note the pseudo-header :path includes the query.
	// See https://httpwg.org/specs/rfc9113.html#rfc.section.8.3.1
	uri, err := proxywasm.GetHttpRequestHeader(":path")
	if err != nil {
		log.Error("Failed to get :path")
		return types.ActionContinue
	}

	// This currently relies on Envoy's behavior of mapping all requests to HTTP/2 semantics
	// and its request properties, but they may not be true of other proxies implementing
	// proxy-wasm.

	if tx.IsRuleEngineOff() {
		return types.ActionContinue
	}
	// OnHttpRequestHeaders does not terminate if IP/Port retrieve goes wrong
	srcIP, srcPort := retrieveAddressInfo(log, "source")
	dstIP, dstPort := retrieveAddressInfo(log, "destination")

	tx.ProcessConnection(srcIP, srcPort, dstIP, dstPort)

	method, err := proxywasm.GetHttpRequestHeader(":method")
	if err != nil {
		log.Error("Failed to get :method")
		return types.ActionContinue
	}

	tx.ProcessURI(uri, method, string(protocol))

	hs, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		log.Error("Failed to get request headers")
		return types.ActionContinue
	}

	for _, h := range hs {
		tx.AddRequestHeader(h[0], h[1])
	}

	// CRS rules tend to expect Host even with HTTP/2
	authority, err := proxywasm.GetHttpRequestHeader(":authority")
	if err == nil {
		tx.AddRequestHeader("Host", authority)
		tx.SetServerName(parseServerName(log, authority))
	}

	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		return handleInterruption(ctx, "http_request_headers", interruption, log)
	}

	return types.ActionContinue
}

func onHttpRequestBody(ctx wrapper.HttpContext, config WafConfig, body []byte, log log.Log) types.Action {
	if ctx.GetBoolContext("interruptionHandled", false) {
		return types.ActionContinue
	}

	tx, ok := ctx.GetContext("tx").(ctypes.Transaction)
	if !ok {
		return types.ActionContinue
	}

	if tx.IsRuleEngineOff() {
		return types.ActionContinue
	}

	// Do not perform any action related to request body data if SecRequestBodyAccess is set to false
	if !tx.IsRequestBodyAccessible() {
		log.Info("Skipping request body inspection, SecRequestBodyAccess is off.")
		// ProcessRequestBody is still performed for phase 2 rules, checking already populated variables
		ctx.SetContext("processedRequestBody", true)
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			log.Error("Failed to process request body")
			return types.ActionContinue
		}

		if interruption != nil {
			return handleInterruption(ctx, "http_request_body", interruption, log)
		}

		return types.ActionContinue
	}

	interruption, _, err := tx.WriteRequestBody(body)
	if err != nil {
		log.Error("Failed to write request body")
		return types.ActionContinue
	}

	if interruption != nil {
		return handleInterruption(ctx, "http_request_body", interruption, log)
	}

	ctx.SetContext("processedRequestBody", true)
	interruption, err = tx.ProcessRequestBody()
	if err != nil {
		log.Error("Failed to process request body")
		return types.ActionContinue
	}
	if interruption != nil {
		return handleInterruption(ctx, "http_request_body", interruption, log)
	}

	return types.ActionContinue
}

func onHttpResponseHeaders(ctx wrapper.HttpContext, config WafConfig, log log.Log) types.Action {
	if ctx.GetBoolContext("skipwaf", false) {
		return types.ActionContinue
	}

	if ctx.GetBoolContext("interruptionHandled", false) {
		return types.ActionContinue
	}

	tx, ok := ctx.GetContext("tx").(ctypes.Transaction)
	if !ok {
		return types.ActionContinue
	}

	if tx.IsRuleEngineOff() {
		return types.ActionContinue
	}

	// Requests without body won't call OnHttpRequestBody, but there are rules in the request body
	// phase that still need to be executed. If they haven't been executed yet, now is the time.
	if !ctx.GetBoolContext("processedRequestBody", false) {
		ctx.SetContext("processedRequestBody", true)
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			log.Error("Failed to process request body")
			return types.ActionContinue
		}
		if interruption != nil {
			return handleInterruption(ctx, "http_response_headers", interruption, log)
		}
	}

	status, err := proxywasm.GetHttpResponseHeader(":status")
	if err != nil {
		log.Error("Failed to get :status")
		return types.ActionContinue
	}
	code, err := strconv.Atoi(status)
	if err != nil {
		code = 0
	}

	hs, err := proxywasm.GetHttpResponseHeaders()
	if err != nil {
		log.Error("Failed to get response headers")
		return types.ActionContinue
	}

	for _, h := range hs {
		tx.AddResponseHeader(h[0], h[1])
	}

	httpProtocol, _ := ctx.GetContext("httpProtocol").(string)
	interruption := tx.ProcessResponseHeaders(code, httpProtocol)
	if interruption != nil {
		return handleInterruption(ctx, "http_response_headers", interruption, log)
	}

	return types.ActionContinue
}

func onHttpResponseBody(ctx wrapper.HttpContext, config WafConfig, body []byte, log log.Log) types.Action {
	if ctx.GetBoolContext("interruptionHandled", false) {
		// At response body phase, proxy-wasm currently relies on emptying the response body as a way of
		// interruption the response. See https://github.com/corazawaf/coraza-proxy-wasm/issues/26.
		// If OnHttpResponseBody is called again and an interruption has already been raised, it means that
		// we have to keep going with the sanitization of the response, emptying it.
		// Sending the crafted HttpResponse with empty body, we don't expect to trigger OnHttpResponseBody
		// log.Warn("Response body interruption already handled, keeping replacing the body")
		// Interruption happened, we don't want to send response body data
		return replaceResponseBodyWhenInterrupted(log, replaceResponseBody)
	}

	tx, ok := ctx.GetContext("tx").(ctypes.Transaction)
	if !ok {
		return types.ActionContinue
	}

	if tx.IsRuleEngineOff() {
		return types.ActionContinue
	}

	// Do not perform any action related to response body data if SecResponseBodyAccess is set to false
	if !tx.IsResponseBodyAccessible() {
		log.Debug("Skipping response body inspection, SecResponseBodyAccess is off.")
		// ProcessResponseBody is performed for phase 4 rules, checking already populated variables
		ctx.SetContext("processedResponseBody", true)
		interruption, err := tx.ProcessResponseBody()
		if err != nil {
			log.Error("Failed to process response body")
			return types.ActionContinue
		}

		if interruption != nil {
			// Proxy-wasm can not anymore deny the response. The best interruption is emptying the body
			// Coraza Multiphase evaluation will help here avoiding late interruptions
			return handleInterruption(ctx, "http_response_body", interruption, log)
		}
		return types.ActionContinue
	}

	interruption, _, err := tx.WriteResponseBody(body)
	if err != nil {
		log.Error("Failed to write response body")
		return types.ActionContinue
	}
	if interruption != nil {
		return handleInterruption(ctx, "http_response_body", interruption, log)
	}

	// We have already sent response headers, an unauthorized response can not be sent anymore,
	// but we can still drop the response to prevent leaking sensitive content.
	// The error will also be logged by Coraza.
	ctx.SetContext("processedResponseBody", true)
	interruption, err = tx.ProcessResponseBody()
	if err != nil {
		log.Error("Failed to process response body")
		return types.ActionContinue
	}
	if interruption != nil {
		return handleInterruption(ctx, "http_response_body", interruption, log)
	}
	return types.ActionContinue
}

func onHttpStreamDone(ctx wrapper.HttpContext, config WafConfig, log log.Log) {
	if ctx.GetBoolContext("skipwaf", false) {
		return
	}

	tx, ok := ctx.GetContext("tx").(ctypes.Transaction)
	if !ok {
		return
	}

	if !tx.IsRuleEngineOff() && !ctx.GetBoolContext("interruptionHandled", false) {
		// Responses without body won't call OnHttpResponseBody, but there are rules in the response body
		// phase that still need to be executed. If they haven't been executed yet, now is the time.
		if !ctx.GetBoolContext("processedResponseBody", false) {
			ctx.SetContext("processedResponseBody", true)
			_, err := tx.ProcessResponseBody()
			if err != nil {
				log.Error("Failed to process response body")
			}
		}
	}

	tx.ProcessLogging()

	_ = tx.Close()
}
