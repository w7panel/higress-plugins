const { defineConfig } = require('@vue/cli-service')

module.exports = defineConfig({
  transpileDependencies: true,
  productionSourceMap: false,
  publicPath: process.env.NODE_ENV === 'production' ? '' : '/',
  devServer: {
    host: '0.0.0.0',
    port: 8082,
    proxy: {
      '/panel-api/v1/waf': {
        target: process.env.WAF_PANEL_ORIGIN || 'http://218.23.2.48:9090',
        changeOrigin: true,
      },
    },
    headers: {
      'Access-Control-Allow-Origin': '*',
    },
  },
})
