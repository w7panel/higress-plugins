<template>
  <main class="plugin-page">
    <router-view />
  </main>
</template>

<script>
import { loadPluginState } from '@/utils/plugin-config'

export default {
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

@media (max-width: 760px) {
  .plugin-page {
    padding: 16px;
  }
}
</style>
