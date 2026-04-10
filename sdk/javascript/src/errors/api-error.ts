import {
  type ApiErrorDetails,
  type ApiErrorResponse,
  type ErrorCodeValue,
  ErrorCode,
  getErrorCodeFromStatus,
} from './types.js';

/**
 * Custom error class for API errors
 *
 * Provides structured error information with type-safe access to error details.
 *
 * @example
 * ```typescript
 * try {
 *   await client.get('/users/123');
 * } catch (error) {
 *   if (error instanceof ApiError) {
 *     console.log(error.code); // 'NOT_FOUND'
 *     console.log(error.message); // 'User not found'
 *     console.log(error.status); // 404
 *   }
 * }
 * ```
 */
export class ApiError extends Error {
  /** Error code identifying the type of error */
  public readonly code: ErrorCodeValue | string;

  /** HTTP status code, if available */
  public readonly status?: number;

  /** Additional error details */
  public readonly details?: ApiErrorDetails;

  /** Request ID for debugging */
  public readonly requestId?: string;

  /** Original error that caused this error, if any */
  public readonly cause?: Error;

  constructor(
    message: string,
    code: ErrorCodeValue | string = ErrorCode.UNKNOWN,
    options?: {
      status?: number | undefined;
      details?: ApiErrorDetails | undefined;
      requestId?: string | undefined;
      cause?: Error | undefined;
    }
  ) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    if (options?.status !== undefined) {
      this.status = options.status;
    }
    if (options?.details !== undefined) {
      this.details = options.details;
    }
    const resolvedRequestId = options?.requestId ?? options?.details?.requestId;
    if (resolvedRequestId !== undefined) {
      this.requestId = resolvedRequestId;
    }
    if (options?.cause !== undefined) {
      this.cause = options.cause;
    }

    // Maintains proper stack trace for where error was thrown (V8 engines)
    if (Error.captureStackTrace !== undefined) {
      Error.captureStackTrace(this, ApiError);
    }
  }

  /**
   * Creates an ApiError from an HTTP response
   */
  static fromResponse(response: ApiErrorResponse, status?: number): ApiError {
    const code = response.code || (status !== undefined ? getErrorCodeFromStatus(status) : ErrorCode.UNKNOWN);

    const options: {
      status?: number | undefined;
      details?: ApiErrorDetails | undefined;
    } = {};

    if (status !== undefined) {
      options.status = status;
    }
    if (response.details !== undefined) {
      options.details = response.details;
    }

    return new ApiError(response.message, code, options);
  }

  /**
   * Creates an ApiError from an HTTP status code
   */
  static fromStatus(status: number, message?: string): ApiError {
    const code = getErrorCodeFromStatus(status);
    const defaultMessage = getDefaultMessageForStatus(status);

    return new ApiError(message ?? defaultMessage, code, { status });
  }

  /**
   * Creates a network error
   */
  static networkError(message: string, cause?: Error): ApiError {
    if (cause !== undefined) {
      return new ApiError(message, ErrorCode.NETWORK_ERROR, { cause });
    }
    return new ApiError(message, ErrorCode.NETWORK_ERROR);
  }

  /**
   * Creates a timeout error
   */
  static timeout(message = 'Request timed out'): ApiError {
    return new ApiError(message, ErrorCode.TIMEOUT);
  }

  /**
   * Creates a parse error
   */
  static parseError(message: string, cause?: Error): ApiError {
    if (cause !== undefined) {
      return new ApiError(message, ErrorCode.PARSE_ERROR, { cause });
    }
    return new ApiError(message, ErrorCode.PARSE_ERROR);
  }

  /**
   * Checks if this error represents a specific error code
   */
  isCode(code: ErrorCodeValue | string): boolean {
    return this.code === code;
  }

  /**
   * Checks if this is a network-related error
   */
  isNetworkError(): boolean {
    return this.code === ErrorCode.NETWORK_ERROR || this.code === ErrorCode.TIMEOUT;
  }

  /**
   * Checks if this is an authentication error
   */
  isAuthError(): boolean {
    return this.code === ErrorCode.UNAUTHORIZED || this.code === ErrorCode.FORBIDDEN;
  }

  /**
   * Checks if this is a client error (4xx)
   */
  isClientError(): boolean {
    return this.status !== undefined && this.status >= 400 && this.status < 500;
  }

  /**
   * Checks if this is a server error (5xx)
   */
  isServerError(): boolean {
    return this.status !== undefined && this.status >= 500;
  }

  /**
   * Checks if this error might be retryable
   */
  isRetryable(): boolean {
    if (this.isNetworkError()) {
      return true;
    }
    if (this.status !== undefined) {
      // Retry on 429 (rate limit) and 5xx server errors
      return this.status === 429 || this.status >= 500;
    }
    return false;
  }

  /**
   * Returns field-level validation errors, if any
   */
  getFieldErrors(): Record<string, string[]> | undefined {
    return this.details?.fieldErrors;
  }

  /**
   * Returns a JSON representation of the error
   */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      status: this.status,
      details: this.details,
      requestId: this.requestId,
    };
  }
}

/**
 * Gets a default error message for an HTTP status code
 */
function getDefaultMessageForStatus(status: number): string {
  const messages: Record<number, string> = {
    400: 'Bad request',
    401: 'Authentication required',
    403: 'Access denied',
    404: 'Resource not found',
    408: 'Request timeout',
    429: 'Too many requests',
    500: 'Internal server error',
    502: 'Bad gateway',
    503: 'Service unavailable',
    504: 'Gateway timeout',
  };

  return messages[status] ?? `HTTP error ${status}`;
}

/**
 * Type guard to check if an error is an ApiError
 */
export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}
