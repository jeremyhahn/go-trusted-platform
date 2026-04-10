export { ApiClient, createApiClient, apiClient, type RequestOptions } from './api-client.js';

export {
  type ApiClientConfig,
  type ResolvedApiClientConfig,
  type CredentialsMode,
  type RetryConfig,
  type TimeoutConfig,
  DEFAULT_RETRY_CONFIG,
  DEFAULT_TIMEOUT_CONFIG,
  resolveConfig,
  validateConfig,
  getDefaultBaseUrl,
  getDefaultFetch,
} from './config.js';

export {
  type RequestContext,
  type ResponseContext,
  type RequestInterceptor,
  type ResponseInterceptor,
  type ErrorInterceptor,
  type InterceptorHandle,
  InterceptorManager,
  createLoggingRequestInterceptor,
  createLoggingResponseInterceptor,
  createAuthInterceptor,
  createRequestIdInterceptor,
  createRetryAfterInterceptor,
} from './interceptors.js';

export {
  PlatformClient,
  createPlatformClient,
  type PlatformClientConfig,
} from './platform-client.js';

export { getClient, isDesktop, type ClientConfig } from './factory.js';
export { WailsPlatformClient } from './wails-client.js';
