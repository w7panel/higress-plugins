<template>
  <main class="plugin-page">
    <header class="page-header">
      <div>
        <h1>{{ pageTitle }}</h1>
        <p>{{ scopeDescription }}</p>
      </div>
    </header>

    <a-alert type="info" show-icon class="context-alert">
      <template v-if="pluginState.configScope === 'rule'">
        当前配置仅作用于
        <strong>{{ pluginState.domain || '当前域名' }}</strong>
        对应的网关规则
        <span v-if="pluginState.ingressName">（Ingress：{{ pluginState.ingressName }}）</span>，不影响集群全局限流配置。
      </template>
      <template v-else>
        当前配置作用于整个集群的网关请求，不绑定具体域名或 Ingress；域名级差异策略请使用规则配置。
      </template>
    </a-alert>

    <router-view />
  </main>
</template>

<script>
import { loadPluginState, pluginState } from '@/utils/plugin-config'

export default {
  data() {
    return { pluginState }
  },
  computed: {
    pageTitle() {
      return this.$route.meta.title || '集群限流配置'
    },
    scopeDescription() {
      return this.pluginState.configScope === 'rule' ? '当前为域名规则限流配置' : '当前为集群全局限流配置'
    },
  },
  created() {
    loadPluginState()
  },
}
</script>

<style>
* {
  box-sizing: border-box;
}

html,
body,
#app {
  min-height: 100%;
  margin: 0;
}

body {
  color: #1d2129;
  background: #fff;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

.plugin-page {
  min-height: 100%;
  padding: 24px;
  background: #fff;
}

.page-header {
  padding-bottom: 16px;
  border-bottom: 1px solid #e5e6eb;
}

.page-header h1 {
  margin: 0;
  font-size: 20px;
  line-height: 28px;
}

.page-header p {
  margin: 6px 0 0;
  color: #86909c;
}

.context-alert {
  margin-top: 16px;
}

@media (max-width: 760px) {
  .plugin-page {
    padding: 16px;
  }
}
</style>
