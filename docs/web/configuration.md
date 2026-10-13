# Web Frontend Configuration

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [engineering.md](engineering.md) §8.3 and §9. `dev`/`build` are `next dev --webpack`/`next build --webpack`; the package manager is npm; Playwright runs `workers: 1` against `npm run dev:webpack`.

Complete configuration reference for the Trusted Platform Web Frontend.

## Environment Variables

### Development Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | `development` | Node.js environment mode |
| `HOSTNAME` | `localhost` | Server hostname |
| `PORT` | `3000` | Development server port |
| `ANALYZE` | `false` | Enable bundle analyzer |

### Production Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | `production` | Production mode |
| `HOSTNAME` | - | Production hostname |
| `PORT` | - | Production port (optional) |
| `VERCEL_URL` | - | Vercel deployment URL (auto-set) |

### Usage Example

```bash
# Development with custom port
PORT=3001 yarn dev

# Production build with bundle analysis
ANALYZE=true yarn build
```

## Next.js Configuration

### next.config.mjs

```javascript
import bundleAnalyzer from "@next/bundle-analyzer";

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Static HTML export for embedding
  output: "export",

  // Disable image optimization (no server runtime)
  images: {
    unoptimized: true,
  },

  // Generate trailing slashes: /page/ -> /page/index.html
  trailingSlash: true,

  // Enable React strict mode
  reactStrictMode: true,
};

// Bundle analyzer wrapper
const withBundleAnalyzer = bundleAnalyzer({
  enabled: process.env.ANALYZE === "true",
});

export default withBundleAnalyzer(nextConfig);
```

### Configuration Options

| Option | Value | Purpose |
|--------|-------|---------|
| `output` | `"export"` | Generate static HTML files |
| `images.unoptimized` | `true` | Disable Next.js image optimization |
| `trailingSlash` | `true` | URL format for static hosting |
| `reactStrictMode` | `true` | Enable React strict mode |

## TypeScript Configuration

### tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ES2017",
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "react-jsx",
    "incremental": true,
    "plugins": [{ "name": "next" }],
    "paths": {
      "@/*": ["./src/*"]
    }
  },
  "include": [
    "next-env.d.ts",
    "**/*.ts",
    "**/*.tsx",
    ".next/types/**/*.ts",
    ".next/dev/types/**/*.ts"
  ],
  "exclude": ["node_modules"]
}
```

### Key TypeScript Settings

| Setting | Value | Purpose |
|---------|-------|---------|
| `strict` | `true` | Enable all strict type checks |
| `moduleResolution` | `"bundler"` | Next.js bundler resolution |
| `paths` | `@/* -> ./src/*` | Import alias for clean imports |
| `incremental` | `true` | Faster rebuilds |

### Import Alias Usage

```typescript
// Instead of relative paths
import { getCookie } from "../../utils/cookie";

// Use alias
import { getCookie } from "@/utils/cookie";
```

## ESLint Configuration

### eslint.config.mjs

```javascript
import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

export default defineConfig([
  globalIgnores([".next/*", "out/*", "node_modules/*"]),
  nextVitals,
  nextTypescript,
]);
```

### Ignored Paths

- `.next/*` - Build output
- `out/*` - Static export
- `node_modules/*` - Dependencies

## Playwright Test Configuration

### playwright.config.ts

```typescript
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  // Test directory
  testDir: './e2e',

  // Run tests in parallel
  fullyParallel: true,

  // Fail CI if test.only is present
  forbidOnly: !!process.env.CI,

  // Retry on CI
  retries: process.env.CI ? 2 : 0,

  // Single worker on CI for stability
  workers: process.env.CI ? 1 : undefined,

  // Reporter based on environment
  reporter: process.env.CI ? 'github' : 'html',

  // Global test settings
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  // Timeouts
  timeout: 30000,
  expect: {
    timeout: 5000,
  },

  // Browser projects
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
    {
      name: 'mobile-chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'mobile-safari',
      use: { ...devices['iPhone 12'] },
    },
  ],

  // Start dev server for tests
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
```

### Browser Projects

| Project | Device | Purpose |
|---------|--------|---------|
| `chromium` | Desktop Chrome | Primary desktop browser |
| `firefox` | Desktop Firefox | Firefox compatibility |
| `webkit` | Desktop Safari | Safari/WebKit compatibility |
| `mobile-chrome` | Pixel 5 | Android mobile testing |
| `mobile-safari` | iPhone 12 | iOS mobile testing |

## Development vs Production Settings

### Development Mode

```bash
yarn dev
```

| Setting | Value |
|---------|-------|
| Hot Module Replacement | Enabled |
| Source Maps | Full |
| Error Overlay | Enabled |
| Turbopack | Enabled (fast refresh) |
| API Base URL | `http://localhost:3000` |

### Production Mode

```bash
yarn build
```

| Setting | Value |
|---------|-------|
| Minification | Enabled |
| Source Maps | Disabled |
| Tree Shaking | Enabled |
| Output | Static files in `out/` |

## Package Scripts

### package.json Scripts

```json
{
  "scripts": {
    "dev": "next dev --turbopack",
    "build": "next build",
    "start": "next start",
    "lint": "eslint src",
    "typecheck": "tsc --noEmit",
    "test:e2e": "playwright test",
    "test:e2e:ui": "playwright test --ui",
    "test:e2e:headed": "playwright test --headed"
  }
}
```

### Script Reference

| Script | Command | Description |
|--------|---------|-------------|
| `dev` | `next dev --turbopack` | Start development server |
| `build` | `next build` | Build for production |
| `start` | `next start` | Start production server (not used) |
| `lint` | `eslint src` | Run ESLint on source |
| `typecheck` | `tsc --noEmit` | Type check without emit |
| `test:e2e` | `playwright test` | Run E2E tests headless |
| `test:e2e:ui` | `playwright test --ui` | Run E2E tests with UI |
| `test:e2e:headed` | `playwright test --headed` | Run E2E tests in browser |

## Dependencies

### Production Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `next` | ^16 | React framework |
| `react` | ^19 | UI library |
| `react-dom` | ^19 | React DOM renderer |
| `@simplewebauthn/browser` | ^13 | WebAuthn client |
| `@next/bundle-analyzer` | ^16 | Bundle size analysis |

### Development Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `@playwright/test` | ^1.40.0 | E2E testing |
| `@types/node` | ^22 | Node.js types |
| `@types/react` | ^19 | React types |
| `@types/react-dom` | ^19 | React DOM types |
| `eslint` | ^9 | Code linting |
| `eslint-config-next` | ^16 | Next.js ESLint rules |
| `typescript` | ^5 | TypeScript compiler |

## Makefile Targets

The web frontend integrates with the main project Makefile:

```makefile
# From project root

# Start development server
cd web && yarn dev

# Build static export
cd web && yarn build

# Build complete public_html with Swagger
make build-public-html
```

### build-public-html Target

This target:
1. Builds Swagger/OpenAPI documentation
2. Downloads Swagger UI
3. Builds Next.js application
4. Copies output to `public_html/`
5. Creates `public_html.tar.gz` for ISO builds
