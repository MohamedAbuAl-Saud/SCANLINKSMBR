import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';
import { defineConfig, type UserConfig } from 'vite';

const projectDir = import.meta.dirname;

export default defineConfig((): UserConfig => {
  const isRailwayOrProd = Boolean(
    process.env.RAILWAY_ENVIRONMENT ||
      process.env.RAILWAY_SERVICE_ID ||
      process.env.RAILWAY_PROJECT_ID ||
      process.env.NODE_ENV === 'production'
  );

  return {
    plugins: [
      react(),
      tailwindcss(),

      // Copies src/assets into dist/ so root-relative asset URLs
      // continue to work in production builds. Do not remove.
      {
        name: 'copy-unbundled-src-assets',
        apply: 'build' as const,

        closeBundle(error?: Error): void {
          if (error) {
            return;
          }

          const distDir = path.resolve(projectDir, 'dist');
          const srcAssets = path.resolve(projectDir, 'src/assets');
          const distAssets = path.resolve(distDir, 'src/assets');

          if (fs.existsSync(distDir) && fs.existsSync(srcAssets)) {
            fs.cpSync(srcAssets, distAssets, {
              recursive: true,
              force: true,
            });
          }
        },
      },
    ],

    resolve: {
      alias: {
        '@': path.resolve(projectDir, '.'),
      },
    },

    build: {
      sourcemap: false,
      minify: 'esbuild',
    },

    server: {
      // Restrict to official Railway hostname in production/Railway; keep preview hosts in local dev.
      allowedHosts: isRailwayOrProd
        ? ['scanlinksm.up.railway.app']
        : ['scanlinksm.up.railway.app', '.run.app', 'localhost', '127.0.0.1'],

      // Preserve AI Studio HMR behavior.
      hmr: process.env.DISABLE_HMR !== 'true',

      // Disable file watching when requested.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
