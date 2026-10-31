'use client';

import { useCallback, useRef, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

import { cn } from '@/lib/utils';

export const DIALOG_ENTER_MS = 0;

export const DIALOG_EXIT_MS = 0;
type AnimatedDialogProps = {
  open: boolean;
  onClose: () => void;
  zIndex?: number;
  overlayClassName?: string;
  panelClassName?: string;
  closeOnOverlay?: boolean;
  children: ReactNode | ((dismiss: () => void) => ReactNode);
};

export function AnimatedDialog({
  open,
  onClose,
  zIndex = 50,
  overlayClassName,
  panelClassName,
  closeOnOverlay = true,
  children,
}: AnimatedDialogProps) {
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  const dismissRef = useRef<() => void>(() => {});
  const dismiss = useCallback(() => {
    onCloseRef.current();
  }, []);
  dismissRef.current = dismiss;
  if (!open) return null;
  if (typeof document === 'undefined') return null;
  const content = typeof children === 'function' ? children(() => dismissRef.current()) : children;
  return createPortal(
    <div
      className={cn(
        'fixed inset-0 flex items-center justify-center bg-black/70 p-4',
        overlayClassName,
      )}
      style={{ zIndex }}
      onClick={closeOnOverlay ? dismiss : undefined}
    >
      <div
        className={cn('w-full max-w-md', panelClassName)}
        onClick={(e) => e.stopPropagation()}
      >
        {content}
      </div>
    </div>,
    document.body,
  );
}
