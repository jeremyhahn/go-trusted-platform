'use client';

/**
 * Toast notification hook
 *
 * Features:
 * - Multiple toast variants (default, destructive, success)
 * - Auto-dismiss with configurable duration
 * - Manual dismiss
 * - Toast queue management
 */

import { useState, useCallback, useEffect } from 'react';

export interface Toast {
  id: string;
  title?: string;
  description?: string;
  variant?: 'default' | 'destructive' | 'success';
  duration?: number;
}

export interface UseToastReturn {
  toast: (props: Omit<Toast, 'id'>) => string;
  dismiss: (id: string) => void;
  toasts: Toast[];
}

// Global state for toasts (allows usage outside React components)
let globalToasts: Toast[] = [];
let globalListeners: Array<(toasts: Toast[]) => void> = [];

const notifyListeners = () => {
  globalListeners.forEach((listener) => listener([...globalToasts]));
};

const addToast = (toast: Toast): string => {
  globalToasts = [...globalToasts, toast];
  notifyListeners();
  return toast.id;
};

const removeToast = (id: string): void => {
  globalToasts = globalToasts.filter((toast) => toast.id !== id);
  notifyListeners();
};

/**
 * Generate unique ID for toasts
 */
const generateId = (): string => {
  return `toast-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
};

/**
 * Hook for managing toast notifications
 *
 * @example
 * ```tsx
 * function MyComponent() {
 *   const { toast } = useToast();
 *
 *   const handleSuccess = () => {
 *     toast({
 *       title: 'Success',
 *       description: 'Your changes have been saved',
 *       variant: 'success',
 *       duration: 3000,
 *     });
 *   };
 *
 *   const handleError = () => {
 *     toast({
 *       title: 'Error',
 *       description: 'Something went wrong',
 *       variant: 'destructive',
 *     });
 *   };
 *
 *   return (
 *     <div>
 *       <button onClick={handleSuccess}>Show Success</button>
 *       <button onClick={handleError}>Show Error</button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useToast(): UseToastReturn {
  const [toasts, setToasts] = useState<Toast[]>(globalToasts);

  useEffect(() => {
    // Subscribe to global toast updates
    const listener = (newToasts: Toast[]) => {
      setToasts(newToasts);
    };

    globalListeners.push(listener);

    return () => {
      globalListeners = globalListeners.filter((l) => l !== listener);
    };
  }, []);

  /**
   * Show a toast notification
   */
  const toast = useCallback((props: Omit<Toast, 'id'>): string => {
    const id = generateId();
    const duration = props.duration ?? 5000; // Default 5 seconds

    const newToast: Toast = {
      id,
      ...props,
      duration,
    };

    addToast(newToast);

    // Auto-dismiss after duration
    if (duration > 0) {
      setTimeout(() => {
        removeToast(id);
      }, duration);
    }

    return id;
  }, []);

  /**
   * Dismiss a specific toast
   */
  const dismiss = useCallback((id: string): void => {
    removeToast(id);
  }, []);

  return {
    toast,
    dismiss,
    toasts,
  };
}

/**
 * Standalone toast function for use outside React components
 *
 * @example
 * ```tsx
 * // In a utility function or event handler
 * toast({
 *   title: 'Success',
 *   description: 'Operation completed',
 *   variant: 'success',
 * });
 * ```
 */
export const toast = (props: Omit<Toast, 'id'>): string => {
  const id = generateId();
  const duration = props.duration ?? 5000;

  const newToast: Toast = {
    id,
    ...props,
    duration,
  };

  addToast(newToast);

  if (duration > 0) {
    setTimeout(() => {
      removeToast(id);
    }, duration);
  }

  return id;
};

/**
 * Dismiss a toast by ID (standalone function)
 */
export const dismissToast = (id: string): void => {
  removeToast(id);
};
