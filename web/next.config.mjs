import bundleAnalyzer from "@next/bundle-analyzer";

import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const sdkPath = path.resolve(__dirname, "../sdk/javascript");

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  images: {
    unoptimized: true,
  },
  trailingSlash: true,
  reactStrictMode: true,
  // Transpile the local SDK package for proper bundling
  transpilePackages: ["trusted-platform-sdk"],
  // Turbopack configuration - rely on transpilePackages and symlink resolution
  // Note: resolveAlias with absolute paths is not supported in Turbopack
  turbopack: {
    resolveExtensions: [".tsx", ".ts", ".jsx", ".js", ".mjs", ".json"],
  },
  // Configure webpack to properly resolve local SDK package
  webpack: (config) => {
    // Enable symlink resolution
    config.resolve.symlinks = true;
    // Add fallback resolution for the SDK subpath exports
    config.resolve.alias = {
      ...config.resolve.alias,
      // Map SDK subpath imports
      "trusted-platform-sdk/react": path.join(sdkPath, "dist/esm/react/index.js"),
      "trusted-platform-sdk": path.join(sdkPath, "dist/esm/index.js"),
    };
    return config;
  },
};

const withBundleAnalyzer = bundleAnalyzer({
  enabled: process.env.ANALYZE === "true",
});

export default withBundleAnalyzer(nextConfig);
