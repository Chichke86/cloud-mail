import {defineConfig, loadEnv, normalizePath} from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import {ElementPlusResolver} from 'unplugin-vue-components/resolvers'
import {cp} from 'node:fs/promises';

function packagedEditor() {
    let outDir
    return {
        name: 'packaged-tinymce',
        apply: 'build',
        configResolved(config) {
            outDir = path.resolve(config.root, config.build.outDir, 'tinymce')
        },
        async closeBundle() {
            const editor = new URL('./node_modules/tinymce/', import.meta.url)
            await Promise.all(['tinymce.min.js', 'icons', 'models', 'plugins', 'skins', 'themes', 'license.md', 'notices.txt']
                .map(name => cp(new URL(name, editor), normalizePath(path.join(outDir, name)), {recursive: true})))
        },
    }
}

export default defineConfig(({mode}) => {
    const env = loadEnv(mode, process.cwd(), 'VITE')
    return {
        server: {
            host: '127.0.0.1',
            port: 3001,
            hmr: true,
        },
        base: env.VITE_STATIC_URL || '/',
        plugins: [vue(), packagedEditor(),
            AutoImport({
                resolvers: [ElementPlusResolver()],
            }),
            Components({
                resolvers: [ElementPlusResolver()],
            })
        ],
        resolve: {
            alias: {
                '@': path.resolve(__dirname, 'src')
            }
        },
        build: {
            target: 'es2022',
            outDir: env.VITE_OUT_DIR || 'dist',
            emptyOutDir: true,
            assetsInclude: ['**/*.json']
        }
    }
})
