<template>
  <section class="settings-page">
    <div class="settings-section">
      <h2>响应内容</h2>
      <a-form :model="form" layout="vertical" class="settings-form">
        <a-form-item label="限流返回码">
          <a-input-number v-model="form.rejected_code" :min="100" :max="599" class="full-control" />
        </a-form-item>
        <a-form-item label="限流返回内容">
          <a-textarea
            v-model="form.rejected_msg"
            :spellcheck="false"
            placeholder="请输入返回内容"
            :auto-size="{ minRows: 5, maxRows: 12 }"
          />
        </a-form-item>
      </a-form>
    </div>

    <div class="settings-section">
      <h2>Redis 配置</h2>
      <a-form :model="form" layout="vertical" class="settings-form">
        <div class="form-grid">
          <a-form-item label="服务地址或 IP" class="grid-span-2">
            <a-input
              v-model="form.redis.service_name"
              :spellcheck="false"
              placeholder="例如：redis.default.svc.cluster.local 或 10.0.0.8"
            />
          </a-form-item>
          <a-form-item label="服务端口">
            <a-input-number v-model="form.redis.service_port" :min="1" :max="65535" class="full-control" />
          </a-form-item>
          <a-form-item label="超时时间（ms）">
            <a-input-number v-model="form.redis.timeout" :min="1" class="full-control" />
          </a-form-item>
          <a-form-item label="用户名">
            <a-input v-model="form.redis.username" :spellcheck="false" placeholder="可选" />
          </a-form-item>
          <a-form-item label="密码">
            <a-input-password v-model="form.redis.password" :spellcheck="false" placeholder="可选" />
          </a-form-item>
          <a-form-item label="数据库编号">
            <a-input-number v-model="form.redis.database" :min="0" class="full-control" />
          </a-form-item>
        </div>
      </a-form>
    </div>

    <div class="page-actions">
      <a-button type="primary" :loading="saving" @click="submit">保存配置</a-button>
    </div>
  </section>
</template>

<script>
import { clone, persistPluginConfig, pluginState } from '@/utils/plugin-config'

export default {
  data() {
    const config = clone(pluginState.config)
    return {
      saving: false,
      form: {
        rejected_code: Number(config.rejected_code || 429),
        rejected_msg: config.rejected_msg || 'Too many requests',
        redis: {
          service_name: config?.redis?.service_name || '',
          service_port: Number(config?.redis?.service_port || 6379),
          username: config?.redis?.username || '',
          password: config?.redis?.password || '',
          timeout: Number(config?.redis?.timeout || 1000),
          database: Number(config?.redis?.database || 0),
        },
      },
    }
  },
  methods: {
    validate() {
      if (Number(this.form.rejected_code) < 100 || Number(this.form.rejected_code) > 599) {
        this.$message.error('限流返回码必须在 100 到 599 之间')
        return false
      }
      if (!this.form.redis.service_name) {
        this.$message.error('请输入 Redis 服务地址或 IP')
        return false
      }
      return true
    },
    buildConfig() {
      const config = {
        ...clone(pluginState.config),
        rejected_code: Number(this.form.rejected_code || 429),
        rejected_msg: this.form.rejected_msg || 'Too many requests',
        redis: {
          service_name: this.form.redis.service_name,
          service_port: Number(this.form.redis.service_port || 6379),
          timeout: Number(this.form.redis.timeout || 1000),
          database: Number(this.form.redis.database || 0),
        },
      }
      if (this.form.redis.username) config.redis.username = this.form.redis.username
      if (this.form.redis.password) config.redis.password = this.form.redis.password
      return config
    },
    async submit() {
      if (!this.validate()) return
      this.saving = true
      try {
        await persistPluginConfig(this.buildConfig())
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

<style scoped>
.settings-page {
  width: 100%;
  padding-top: 20px;
}

.settings-section {
  padding: 20px;
  background: #f7f8fa;
  border: 1px solid #e5e6eb;
  border-radius: 4px;
}

.settings-section + .settings-section {
  margin-top: 20px;
}

.settings-section h2 {
  margin: 0 0 18px;
  font-size: 16px;
  line-height: 24px;
}

.settings-form {
  width: 100%;
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 20px;
}

.grid-span-2 {
  grid-column: span 2;
}

.full-control {
  width: 100%;
}

.page-actions {
  display: flex;
  justify-content: flex-end;
  margin-top: 20px;
}

@media (max-width: 760px) {
  .form-grid {
    grid-template-columns: 1fr;
  }

  .grid-span-2 {
    grid-column: span 1;
  }
}
</style>
