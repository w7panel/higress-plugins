package main

import (
	"strings"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
	wrapper.SetCtx(
		"w7-domain",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config W7DomainSetting, log wrapper.Log) types.Action {
	if len(config.setting.whiteDomainSetting) == 0 {
		return types.ActionContinue
	}

	reqDomain := ctx.Host()
	for domain, _ := range config.setting.whiteDomainSetting {
		domain = strings.TrimLeft(domain, "*")
		if strings.HasSuffix(reqDomain, domain) {
			return types.ActionContinue
		}
	}

	err := proxywasm.SendHttpResponse(uint32(config.setting.responseCode), nil, []byte(config.setting.responseBody), -1)
	if err != nil {
		log.Errorf("SendHttpResponse err: %v", err)
		return 0
	}

	return types.ActionPause
}
