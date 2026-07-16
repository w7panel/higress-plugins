const { defineConfig } = require('@vue/cli-service')

module.exports = defineConfig({
  transpileDependencies: true,
  productionSourceMap: false,
  publicPath: process.env.NODE_ENV === 'production' ? '' : '/',
  devServer: {
    host: '0.0.0.0',
    port: 8081,
    headers: {
      'Access-Control-Allow-Origin': '*',
    },
  },
})
