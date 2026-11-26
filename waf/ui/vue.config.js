const { defineConfig } = require('@vue/cli-service')

module.exports = defineConfig({
  transpileDependencies: true,
  productionSourceMap: false,
  publicPath: process.env.NODE_ENV === 'production' ? '' : '/',
  devServer: {
    host: '0.0.0.0',
    port: 8082,
    proxy: {
      '/panel-api/v1': {
        target: process.env.WAF_PANEL_ORIGIN || 'http://127.0.0.1:9090',
        changeOrigin: true,
      },
      '/k8s-proxy': {
        target: process.env.WAF_PANEL_ORIGIN || 'http://127.0.0.1:9090',
        changeOrigin: true,
      },
    },
    headers: {
      'Access-Control-Allow-Origin': '*',
    },
  },
})
