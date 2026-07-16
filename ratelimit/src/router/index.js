import { createRouter, createWebHashHistory } from 'vue-router'
import RateLimitView from '@/views/RateLimitView.vue'
import ResponseRedisView from '@/views/ResponseRedisView.vue'

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    {
      path: '/',
      redirect: '/rate-limit',
    },
    {
      path: '/rate-limit',
      name: 'rate-limit',
      component: RateLimitView,
      meta: { title: '限流管理' },
    },
    {
      path: '/response-redis',
      name: 'response-redis',
      component: ResponseRedisView,
      meta: { title: '响应内容与 Redis 配置' },
    },
  ],
})

export default router

