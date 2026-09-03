/**
 * Error codes used by the SDK
 */
export const ErrorCode = {
  /** Network-level error (connection failed, timeout, etc.) */
  NETWORK_ERROR: 'NETWORK_ERROR',
  /** Request was aborted */
  REQUEST_ABORTED: 'REQUEST_ABORTED',
  /** Request timed out */
  TIMEOUT: 'TIMEOUT',
  /** Invalid request parameters */
  INVALID_REQUEST: 'INVALID_REQUEST',
  /** Authentication required */
  UNAUTHORIZED: 'UNAUTHORIZED',
  /** Permission denied */
  FORBIDDEN: 'FORBIDDEN',
  /** Resource not found */
  NOT_FOUND: 'NOT_FOUND',
  /** Server error */
  SERVER_ERROR: 'SERVER_ERROR',
  /** Response parsing failed */
  PARSE_ERROR: 'PARSE_ERROR',
  /** Unknown error */
  UNKNOWN: 'UNKNOWN',
} as const;

export type ErrorCodeValue = (typeof ErrorCode)[keyof typeof ErrorCode];

/**
 * Error details structure
 */
export interface ApiErrorDetails {
  /** Field-level validation errors */
  fieldErrors?: Record<string, string[]>;
  /** Additional context about the error */
  context?: Record<string, unknown>;
  /** Stack trace (only in development) */
  stack?: string;
  /** Request ID for debugging */
  requestId?: string;
  /**
   * Stable, machine-readable discriminator emitted by the platform in
   * the error envelope's `reason` field (e.g. `SERVICE_NOT_CONFIGURED`
   * from the REST service registry). Clients branch on this instead of
   * pattern-matching the operator-facing `message` prose.
   */
  reason?: string;
  /** Platform service the error refers to, when the envelope names one. */
  service?: string;
}

/**
 * Raw error response from the API
 */
export interface ApiErrorResponse {
  code: string;
  message: string;
  details?: ApiErrorDetails;
  /**
   * HTTP status the response carried, when the error came from a
   * response rather than the transport. Preserved so callers reading
   * `ApiResponse.error` can branch on the status without needing the
   * `ApiError` instance the client built internally.
   */
  status?: number;
}

/**
 * HTTP status code to error code mapping
 */
export const httpStatusToErrorCode: Readonly<Record<number, ErrorCodeValue>> = {
  400: ErrorCode.INVALID_REQUEST,
  401: ErrorCode.UNAUTHORIZED,
  403: ErrorCode.FORBIDDEN,
  404: ErrorCode.NOT_FOUND,
  408: ErrorCode.TIMEOUT,
  500: ErrorCode.SERVER_ERROR,
  502: ErrorCode.SERVER_ERROR,
  503: ErrorCode.SERVER_ERROR,
  504: ErrorCode.TIMEOUT,
} as const;

/**
 * Maps HTTP status code to appropriate error code
 */
export function getErrorCodeFromStatus(status: number): ErrorCodeValue {
  return httpStatusToErrorCode[status] ?? ErrorCode.UNKNOWN;
}
