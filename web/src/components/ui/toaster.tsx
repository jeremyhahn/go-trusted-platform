'use client';

/**
 * Toaster component - renders toast notifications
 *
 * This component should be included once at the root of your app
 */

import React from 'react';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';
import { X, CheckCircle2, AlertCircle } from 'lucide-react';

export interface ToasterProps {
  position?: 'top-right' | 'top-center' | 'top-left' | 'bottom-right' | 'bottom-center' | 'bottom-left';
}

/**
 * Toaster Component
 *
 * Renders all active toast notifications. Place this component at the root of your app.
 *
 * @example
 * ```tsx
 * // In your layout or root component
 * export default function RootLayout({ children }) {
 *   return (
 *     <html>
 *       <body>
 *         {children}
 *         <Toaster position="top-right" />
 *       </body>
 *     </html>
 *   );
 * }
 * ```
 */
export function Toaster({ position = 'top-right' }: ToasterProps): React.ReactElement {
  const { toasts, dismiss } = useToast();

  // Position classes
  const positionClasses = {
    'top-right': 'top-4 right-4',
    'top-center': 'top-4 left-1/2 -translate-x-1/2',
    'top-left': 'top-4 left-4',
    'bottom-right': 'bottom-4 right-4',
    'bottom-center': 'bottom-4 left-1/2 -translate-x-1/2',
    'bottom-left': 'bottom-4 left-4',
  };

  if (toasts.length === 0) {
    return <></>;
  }

  return (
    <div
      className={cn(
        'fixed z-50 flex flex-col gap-2 w-full max-w-md pointer-events-none',
        positionClasses[position]
      )}
      role="region"
      aria-label="Notifications"
    >
      {toasts.map((toast) => (
        <ToastItem
          key={toast.id}
          toast={toast}
          onDismiss={() => dismiss(toast.id)}
        />
      ))}
    </div>
  );
}

interface ToastItemProps {
  toast: {
    id: string;
    title?: string;
    description?: string;
    variant?: 'default' | 'destructive' | 'success';
  };
  onDismiss: () => void;
}

function ToastItem({ toast, onDismiss }: ToastItemProps): React.ReactElement {
  const { variant = 'default', title, description } = toast;

  // Variant styles
  const variantClasses = {
    default: 'bg-white border-gray-200 text-gray-900',
    destructive: 'bg-red-50 border-red-200 text-red-900',
    success: 'bg-green-50 border-green-200 text-green-900',
  };

  // Icon for each variant
  const Icon = variant === 'success'
    ? CheckCircle2
    : variant === 'destructive'
    ? AlertCircle
    : null;

  const iconClasses = {
    default: '',
    destructive: 'text-red-500',
    success: 'text-green-500',
  };

  return (
    <div
      className={cn(
        'pointer-events-auto relative w-full rounded-lg border p-4 shadow-lg transition-all',
        'animate-in slide-in-from-top-full duration-300',
        variantClasses[variant]
      )}
      role="alert"
      aria-live="polite"
      aria-atomic="true"
    >
      <div className="flex gap-3">
        {Icon && (
          <div className="flex-shrink-0 mt-0.5">
            <Icon className={cn('h-5 w-5', iconClasses[variant])} />
          </div>
        )}
        <div className="flex-1 space-y-1">
          {title && (
            <div className="font-semibold text-sm leading-none">
              {title}
            </div>
          )}
          {description && (
            <div className="text-sm opacity-90">
              {description}
            </div>
          )}
        </div>
        <button
          type="button"
          onClick={onDismiss}
          className={cn(
            'flex-shrink-0 rounded-md p-1 transition-colors',
            'hover:bg-black/5 focus:outline-none focus:ring-2 focus:ring-offset-2',
            variant === 'destructive' && 'hover:bg-red-100 focus:ring-red-500',
            variant === 'success' && 'hover:bg-green-100 focus:ring-green-500',
            variant === 'default' && 'hover:bg-gray-100 focus:ring-gray-500'
          )}
          aria-label="Dismiss notification"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
