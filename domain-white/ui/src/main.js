import { createApp } from 'vue'
import ArcoVue from '@arco-design/web-vue'
import '@arco-design/web-vue/dist/arco.css'
import App from './App.vue'

if (window.__POWERED_BY_WUJIE__) {
  // eslint-disable-next-line no-undef, camelcase
  __webpack_public_path__ = window.__WUJIE_PUBLIC_PATH__
}

let app

function mount() {
  if (app) {
    return
  }

  app = createApp(App)
  app.use(ArcoVue)
  app.mount('#app')
}

function unmount() {
  app?.unmount()
  app = undefined
}

if (window.__POWERED_BY_WUJIE__) {
  window.__WUJIE_MOUNT = mount
  window.__WUJIE_UNMOUNT = unmount
} else {
  mount()
}
