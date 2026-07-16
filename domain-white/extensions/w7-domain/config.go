package main

import (
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"
)

type domainSetting struct {
	Domain string `json:"domain"`
	Enable bool   `json:"enable"`
}

type W7DomainSetting struct {
	setting struct {
		whiteDomainSetting map[string]domainSetting
		blackDomainSetting map[string]domainSetting
		responseCode       int
		responseBody       string
	}
}

func parseConfig(data gjson.Result, config *W7DomainSetting, log wrapper.Log) error {
	log.Errorf("parseConfig, %s", data.String())

	if data.Get("response_code").Exists() {
		value := data.Get("response_code").Int()
		config.setting.responseCode = int(value)
	}
	if data.Get("response_content").Exists() {
		value := data.Get("response_content").String()
		config.setting.responseBody = value
	}

	config.setting.whiteDomainSetting = make(map[string]domainSetting)
	if data.Get("white_domains").Exists() {
		domainData := data.Get("white_domains").Array()
		for _, item := range domainData {
			domain := item.Get("domain").String()
			config.setting.whiteDomainSetting[domain] = domainSetting{
				Domain: domain,
				Enable: item.Get("enable").Bool(),
			}
		}
		log.Errorf("whiteDomainSetting: %v", config.setting.whiteDomainSetting)
	}
	config.setting.blackDomainSetting = make(map[string]domainSetting)
	if data.Get("black_domains").Exists() {
		domainData := data.Get("white_domains").Array()
		for _, item := range domainData {
			domain := item.Get("domain").String()
			config.setting.blackDomainSetting[domain] = domainSetting{
				Domain: domain,
				Enable: item.Get("enable").Bool(),
			}
		}
		log.Errorf("blackDomainSetting: %v", config.setting.blackDomainSetting)
	}

	return nil
}
