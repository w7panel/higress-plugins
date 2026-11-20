package main

import (
	"github.com/w7panel/waf-wasm/wasmplugin"
	wasilibs "github.com/corazawaf/coraza-wasilibs"
)

func main() {}

func init() {
	wasilibs.RegisterRX()
	wasilibs.RegisterPM()
	wasilibs.RegisterSQLi()
	wasilibs.RegisterXSS()
	wasmplugin.PluginStart()
}
