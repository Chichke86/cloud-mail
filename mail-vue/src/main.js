import {createApp} from 'vue';
import App from './App.vue';
import router from './router';
import './style.css';
import { init } from '@/init/init.js';
import { createPinia } from 'pinia';
import piniaPersistedState from 'pinia-plugin-persistedstate';
import 'element-plus/theme-chalk/dark/css-vars.css';
import 'nprogress/nprogress.css';
import perm from "@/perm/perm.js";
const pinia = createPinia().use(piniaPersistedState)
import i18n from "@/i18n/index.js";
const app = createApp(App).use(pinia)
// Drop private message/recipient caches written by older builds; keep explicit drafts.
try {
    localStorage.removeItem('email')
    localStorage.removeItem('writer')
} catch {
    // Storage may be disabled by the browser.
}
await init()
app.use(router).use(i18n).directive('perm',perm)
app.config.devtools = import.meta.env.DEV;

app.mount('#app');
