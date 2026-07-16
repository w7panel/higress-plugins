<template>
  <main class="plugin-page">
    <header class="page-header">
      <div>
        <h1>域名插件配置</h1>
        <p>{{ scopeDescription }}</p>
      </div>
      <div class="header-actions">
        <a-button type="primary" :loading="saving" @click="submit">保存配置</a-button>
      </div>
    </header>

    <a-tabs v-model:active-key="tab" class="config-tabs">
      <a-tab-pane key="whitelist" title="白名单配置">
        <a-table
          :columns="columns"
          :data="list"
          :pagination="false"
          row-key="_key"
          class="config-table"
        >
          <template #domain="{ record }">
            <a-input v-model="record.domain" placeholder="请输入域名，如 example.com" allow-clear />
          </template>
          <template #enable="{ record }">
            <a-switch v-model="record.enable" />
          </template>
          <template #operation="{ rowIndex }">
            <a-link status="danger" @click="removeDomain(rowIndex)">删除</a-link>
          </template>
        </a-table>
        <a-button long class="add-button" @click="addDomain">
          <template #icon><icon-plus /></template>
          添加域名
        </a-button>
      </a-tab-pane>

      <a-tab-pane key="error-page" title="错误页配置">
        <a-form :model="errpage" auto-label-width class="error-form">
          <a-form-item label="错误码">
            <a-input v-model="errpage.code" type="number" placeholder="请输入错误码" />
          </a-form-item>
          <a-form-item label="内容">
            <a-textarea
              v-model="errpage.content"
              placeholder="请输入错误页内容"
              :auto-size="{ minRows: 5, maxRows: 12 }"
            />
          </a-form-item>
        </a-form>
      </a-tab-pane>
    </a-tabs>
  </main>
</template>

<script>
import psl from 'psl'
import { IconPlus } from '@arco-design/web-vue/es/icon'

const defaultErrorPage = () => ({
  code: '404',
  content: '',
})

const clone = value => {
  if (!value || typeof value !== 'object') {
    return {}
  }
  return JSON.parse(JSON.stringify(value))
}

const getPluginProps = () => window.$wujie?.props || {}

export default {
  components: { IconPlus },
  data() {
    return {
      tab: 'whitelist',
      list: [],
      errpage: defaultErrorPage(),
      pluginEnabled: true,
      configScope: 'global',
      saving: false,
      nextKey: 1,
      columns: [
        { title: '域名', slotName: 'domain' },
        { title: '开启', slotName: 'enable', width: 120 },
        { title: '操作', slotName: 'operation', width: 100 },
      ],
    }
  },
  computed: {
    scopeDescription() {
      return this.configScope === 'rule' ? '当前配置作用于所选网关规则' : '当前配置为全局插件配置'
    },
  },
  created() {
    this.init()
  },
  methods: {
    init() {
      const props = getPluginProps()
      const config = clone(props.pluginConfig)
      this.configScope = props.configScope === 'rule' ? 'rule' : 'global'
      this.pluginEnabled = props.pluginEnabled ?? props.enabled ?? true
      this.list = Array.isArray(config.list)
        ? config.list.map(item => this.normalizeDomain(item))
        : []
      this.errpage = {
        ...defaultErrorPage(),
        ...(config.errpage && typeof config.errpage === 'object' ? config.errpage : {}),
      }
    },
    normalizeDomain(item = {}) {
      return {
        _key: this.nextKey++,
        domain: typeof item.domain === 'string' ? item.domain : '',
        enable: Boolean(item.enable),
      }
    },
    addDomain() {
      this.list.push(this.normalizeDomain())
    },
    removeDomain(index) {
      this.list.splice(index, 1)
    },
    async submit() {
      const invalidDomain = this.list.find(item => item.domain.trim() && !psl.isValid(item.domain.trim()))
      if (invalidDomain) {
        this.$message.error(`“${invalidDomain.domain}”包含无效的公共后缀`)
        return
      }

      const savePluginConfig = getPluginProps().savePluginConfig
      if (typeof savePluginConfig !== 'function') {
        this.$message.error('当前运行环境未提供 savePluginConfig')
        return
      }

      const config = {
        list: this.list
          .map(({ domain, enable }) => ({ domain: domain.trim(), enable }))
          .filter(item => item.domain),
        errpage: clone(this.errpage),
      }

      this.saving = true
      try {
        await Promise.resolve(savePluginConfig(config, this.pluginEnabled))
        this.$message.success('配置已保存')
      } catch (error) {
        this.$message.error(error?.message || '配置保存失败')
      } finally {
        this.saving = false
      }
    },
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
  background: #f7f8fa;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

.plugin-page {
  min-height: 100%;
  padding: 24px;
  background: #fff;
}

.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
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

.header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}

.config-tabs {
  margin-top: 8px;
}

.config-table .arco-table-th {
  background: #f2f3f5;
}

.add-button {
  margin-top: 12px;
  color: #4e5969;
  border-style: dashed;
}

.error-form {
  max-width: 720px;
  padding-top: 12px;
}

@media (max-width: 720px) {
  .plugin-page {
    padding: 16px;
  }

  .page-header {
    align-items: flex-start;
    flex-direction: column;
  }

  .header-actions {
    width: 100%;
    flex-wrap: wrap;
  }
}
</style>
