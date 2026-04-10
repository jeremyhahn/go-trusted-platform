"use client";

import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { PanelLeft } from "lucide-react";

import { cn } from "@/lib/utils";
import { Sheet, SheetContent } from "@/components/ui/sheet";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";

// Constants for sidebar widths
export const SIDEBAR_WIDTH = "16rem";
export const SIDEBAR_WIDTH_MOBILE = "18rem";
export const SIDEBAR_WIDTH_ICON = "3rem";
export const SIDEBAR_COOKIE_NAME = "sidebar:state";
export const SIDEBAR_COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 days

// Types
type SidebarContext = {
  state: "expanded" | "collapsed";
  open: boolean;
  setOpen: (open: boolean) => void;
  openMobile: boolean;
  setOpenMobile: (open: boolean) => void;
  isMobile: boolean;
  toggleSidebar: () => void;
};

const SidebarContext = React.createContext<SidebarContext | null>(null);

/**
 * Hook to access sidebar state
 *
 * @example
 * ```tsx
 * const { state, toggleSidebar } = useSidebar();
 * ```
 */
export function useSidebar() {
  const context = React.useContext(SidebarContext);
  if (!context) {
    throw new Error("useSidebar must be used within a SidebarProvider");
  }
  return context;
}

interface SidebarProviderProps extends React.ComponentPropsWithoutRef<"div"> {
  defaultOpen?: boolean;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

/**
 * Sidebar provider for managing sidebar state
 * Handles desktop/mobile responsive behavior and state persistence
 *
 * @example
 * ```tsx
 * <SidebarProvider>
 *   <Sidebar>
 *     <SidebarHeader>Header</SidebarHeader>
 *     <SidebarContent>Content</SidebarContent>
 *   </Sidebar>
 *   <main>Main content</main>
 * </SidebarProvider>
 * ```
 */
export const SidebarProvider = React.forwardRef<
  HTMLDivElement,
  SidebarProviderProps
>(
  (
    {
      defaultOpen = true,
      open: openProp,
      onOpenChange: setOpenProp,
      className,
      style,
      children,
      ...props
    },
    ref
  ) => {
    const [_open, _setOpen] = React.useState(defaultOpen);
    const open = openProp ?? _open;
    const setOpen = React.useCallback(
      (value: boolean | ((value: boolean) => boolean)) => {
        const openState = typeof value === "function" ? value(open) : value;
        if (setOpenProp) {
          setOpenProp(openState);
        } else {
          _setOpen(openState);
        }

        // Persist to cookie
        document.cookie = `${SIDEBAR_COOKIE_NAME}=${openState}; path=/; max-age=${SIDEBAR_COOKIE_MAX_AGE}`;
      },
      [setOpenProp, open]
    );

    const [openMobile, setOpenMobile] = React.useState(false);
    const [isMobile, setIsMobile] = React.useState(false);

    // Detect mobile viewport
    React.useEffect(() => {
      const checkMobile = () => {
        setIsMobile(window.innerWidth < 768);
      };

      checkMobile();
      window.addEventListener("resize", checkMobile);
      return () => window.removeEventListener("resize", checkMobile);
    }, []);

    // Initialize from cookie
    React.useEffect(() => {
      const cookies = document.cookie.split("; ");
      const sidebarCookie = cookies.find((c) =>
        c.startsWith(`${SIDEBAR_COOKIE_NAME}=`)
      );
      if (sidebarCookie) {
        const value = sidebarCookie.split("=")[1];
        _setOpen(value === "true");
      }
    }, []);

    const toggleSidebar = React.useCallback(() => {
      if (isMobile) {
        setOpenMobile((prev) => !prev);
      } else {
        setOpen((prev) => !prev);
      }
    }, [isMobile, setOpen]);

    const state = open ? "expanded" : "collapsed";

    const contextValue = React.useMemo<SidebarContext>(
      () => ({
        state,
        open,
        setOpen,
        isMobile,
        openMobile,
        setOpenMobile,
        toggleSidebar,
      }),
      [state, open, setOpen, isMobile, openMobile, toggleSidebar]
    );

    return (
      <SidebarContext.Provider value={contextValue}>
        <div
          ref={ref}
          style={
            {
              "--sidebar-width": SIDEBAR_WIDTH,
              "--sidebar-width-icon": SIDEBAR_WIDTH_ICON,
              ...style,
            } as React.CSSProperties
          }
          className={cn(
            "group/sidebar-wrapper flex min-h-screen w-full",
            className
          )}
          {...props}
        >
          {children}
        </div>
      </SidebarContext.Provider>
    );
  }
);
SidebarProvider.displayName = "SidebarProvider";

/**
 * Main sidebar container
 * Handles responsive behavior (sheet on mobile, collapsible on desktop)
 */
export const Sidebar = React.forwardRef<
  HTMLDivElement,
  React.ComponentPropsWithoutRef<"div"> & {
    side?: "left" | "right";
    collapsible?: "offcanvas" | "icon" | "none";
  }
>(
  (
    {
      side = "left",
      collapsible = "icon",
      className,
      children,
      ...props
    },
    ref
  ) => {
    const { isMobile, state, openMobile, setOpenMobile } = useSidebar();

    if (collapsible === "none") {
      return (
        <div
          ref={ref}
          className={cn(
            "flex h-full w-[--sidebar-width] flex-col bg-neutral-100 dark:bg-neutral-900",
            className
          )}
          {...props}
        >
          {children}
        </div>
      );
    }

    if (isMobile) {
      return (
        <Sheet open={openMobile} onOpenChange={setOpenMobile}>
          <SheetContent
            side={side}
            className="w-[--sidebar-width-mobile] p-0 [&>button]:hidden"
          >
            <div className="flex h-full w-full flex-col">{children}</div>
          </SheetContent>
        </Sheet>
      );
    }

    return (
      <div
        ref={ref}
        className={cn(
          "group peer hidden md:block transition-all duration-300 ease-in-out",
          state === "expanded" ? "w-[--sidebar-width]" : "w-[--sidebar-width-icon]"
        )}
      >
        <div
          className={cn(
            "fixed inset-y-0 z-10 hidden h-screen flex-col border-r bg-neutral-100 transition-all duration-300 ease-in-out md:flex dark:bg-neutral-900",
            state === "expanded" ? "w-[--sidebar-width]" : "w-[--sidebar-width-icon]",
            className
          )}
          {...props}
        >
          {children}
        </div>
      </div>
    );
  }
);
Sidebar.displayName = "Sidebar";

/**
 * Sidebar trigger button
 * Toggles sidebar open/collapsed state
 */
export const SidebarTrigger = React.forwardRef<
  HTMLButtonElement,
  React.ComponentPropsWithoutRef<"button">
>(({ className, onClick, ...props }, ref) => {
  const { toggleSidebar } = useSidebar();

  return (
    <button
      ref={ref}
      type="button"
      onClick={(e) => {
        onClick?.(e);
        toggleSidebar();
      }}
      className={cn(
        "inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors hover:bg-neutral-200 hover:text-neutral-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-950 disabled:pointer-events-none disabled:opacity-50 dark:hover:bg-neutral-800 dark:hover:text-neutral-50 dark:focus-visible:ring-neutral-300",
        "h-9 w-9",
        className
      )}
      {...props}
    >
      <PanelLeft className="h-4 w-4" />
      <span className="sr-only">Toggle Sidebar</span>
    </button>
  );
});
SidebarTrigger.displayName = "SidebarTrigger";

/**
 * Sidebar rail - clickable edge to expand collapsed sidebar
 */
export const SidebarRail = React.forwardRef<
  HTMLButtonElement,
  React.ComponentPropsWithoutRef<"button">
>(({ className, ...props }, ref) => {
  const { toggleSidebar, state } = useSidebar();

  return (
    <button
      ref={ref}
      type="button"
      onClick={toggleSidebar}
      className={cn(
        "absolute inset-y-0 z-20 hidden w-4 -translate-x-1/2 transition-all ease-linear after:absolute after:inset-y-0 after:left-1/2 after:w-[2px] hover:after:bg-neutral-300 group-data-[state=collapsed]:translate-x-2 dark:hover:after:bg-neutral-700 [[data-side=right]_&]:translate-x-1/2 [[data-side=right][data-state=collapsed]_&]:-translate-x-2",
        state === "collapsed" ? "md:flex" : "md:hidden",
        className
      )}
      {...props}
    >
      <span className="sr-only">Toggle Sidebar</span>
    </button>
  );
});
SidebarRail.displayName = "SidebarRail";

/**
 * Sidebar header container
 */
export const SidebarHeader = React.forwardRef<
  HTMLDivElement,
  React.ComponentPropsWithoutRef<"div">
>(({ className, ...props }, ref) => {
  return (
    <div
      ref={ref}
      className={cn("flex flex-col gap-2 p-2", className)}
      {...props}
    />
  );
});
SidebarHeader.displayName = "SidebarHeader";

/**
 * Sidebar footer container
 */
export const SidebarFooter = React.forwardRef<
  HTMLDivElement,
  React.ComponentPropsWithoutRef<"div">
>(({ className, ...props }, ref) => {
  return (
    <div
      ref={ref}
      className={cn("flex flex-col gap-2 p-2", className)}
      {...props}
    />
  );
});
SidebarFooter.displayName = "SidebarFooter";

/**
 * Sidebar separator
 */
export const SidebarSeparator = React.forwardRef<
  HTMLDivElement,
  React.ComponentPropsWithoutRef<"div">
>(({ className, ...props }, ref) => {
  return (
    <div
      ref={ref}
      className={cn("mx-2 h-px bg-neutral-200 dark:bg-neutral-800", className)}
      {...props}
    />
  );
});
SidebarSeparator.displayName = "SidebarSeparator";

/**
 * Sidebar main content area
 */
export const SidebarContent = React.forwardRef<
  HTMLDivElement,
  React.ComponentPropsWithoutRef<"div">
>(({ className, ...props }, ref) => {
  return (
    <div
      ref={ref}
      className={cn("flex flex-1 flex-col gap-2 overflow-auto p-2", className)}
      {...props}
    />
  );
});
SidebarContent.displayName = "SidebarContent";

/**
 * Sidebar group container with optional collapsible behavior
 */
export const SidebarGroup = React.forwardRef<
  HTMLDivElement,
  React.ComponentPropsWithoutRef<"div">
>(({ className, ...props }, ref) => {
  return (
    <div
      ref={ref}
      className={cn("relative flex w-full min-w-0 flex-col gap-1", className)}
      {...props}
    />
  );
});
SidebarGroup.displayName = "SidebarGroup";

/**
 * Sidebar group label
 */
export const SidebarGroupLabel = React.forwardRef<
  HTMLDivElement,
  React.ComponentPropsWithoutRef<"div"> & { asChild?: boolean }
>(({ className, asChild = false, ...props }, ref) => {
  const Comp = asChild ? Slot : "div";

  return (
    <Comp
      ref={ref}
      className={cn(
        "flex h-8 shrink-0 items-center rounded-md px-2 text-xs font-medium text-neutral-500 outline-none transition-all hover:bg-neutral-200 hover:text-neutral-900 focus-visible:ring-2 focus-visible:ring-neutral-950 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-neutral-50 dark:focus-visible:ring-neutral-300",
        "group-data-[state=collapsed]/sidebar-wrapper:opacity-0",
        className
      )}
      {...props}
    />
  );
});
SidebarGroupLabel.displayName = "SidebarGroupLabel";

/**
 * Sidebar group content
 */
export const SidebarGroupContent = React.forwardRef<
  HTMLDivElement,
  React.ComponentPropsWithoutRef<"div">
>(({ className, ...props }, ref) => {
  return <div ref={ref} className={cn("w-full", className)} {...props} />;
});
SidebarGroupContent.displayName = "SidebarGroupContent";

/**
 * Sidebar menu list
 */
export const SidebarMenu = React.forwardRef<
  HTMLUListElement,
  React.ComponentPropsWithoutRef<"ul">
>(({ className, ...props }, ref) => {
  return (
    <ul
      ref={ref}
      className={cn("flex w-full min-w-0 flex-col gap-1", className)}
      {...props}
    />
  );
});
SidebarMenu.displayName = "SidebarMenu";

/**
 * Sidebar menu item
 */
export const SidebarMenuItem = React.forwardRef<
  HTMLLIElement,
  React.ComponentPropsWithoutRef<"li">
>(({ className, ...props }, ref) => {
  return <li ref={ref} className={cn("group/menu-item", className)} {...props} />;
});
SidebarMenuItem.displayName = "SidebarMenuItem";

const sidebarMenuButtonVariants = cva(
  "peer/menu-button flex w-full items-center gap-2 overflow-hidden rounded-md p-2 text-left text-sm outline-none transition-colors hover:bg-neutral-200 hover:text-neutral-900 focus-visible:ring-2 focus-visible:ring-neutral-950 active:bg-neutral-200 disabled:pointer-events-none disabled:opacity-50 dark:hover:bg-neutral-800 dark:hover:text-neutral-50 dark:focus-visible:ring-neutral-300 dark:active:bg-neutral-800 aria-disabled:pointer-events-none aria-disabled:opacity-50 [&>svg]:size-4 [&>svg]:shrink-0",
  {
    variants: {
      variant: {
        default:
          "hover:bg-neutral-200 hover:text-neutral-900 dark:hover:bg-neutral-800 dark:hover:text-neutral-50",
        outline:
          "bg-white shadow-sm border border-neutral-200 hover:bg-neutral-100 hover:text-neutral-900 dark:border-neutral-800 dark:bg-neutral-950 dark:hover:bg-neutral-800 dark:hover:text-neutral-50",
      },
      size: {
        default: "h-9 text-sm",
        sm: "h-7 text-xs",
        lg: "h-12 text-base",
      },
      isActive: {
        true: "bg-neutral-200 text-neutral-900 dark:bg-neutral-800 dark:text-neutral-50",
        false: "",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
      isActive: false,
    },
  }
);

/**
 * Sidebar menu button with active state and icon support
 *
 * @example
 * ```tsx
 * <SidebarMenuItem>
 *   <SidebarMenuButton asChild isActive>
 *     <a href="/dashboard">
 *       <Home />
 *       <span>Dashboard</span>
 *     </a>
 *   </SidebarMenuButton>
 * </SidebarMenuItem>
 * ```
 */
export const SidebarMenuButton = React.forwardRef<
  HTMLButtonElement,
  React.ComponentPropsWithoutRef<"button"> & {
    asChild?: boolean;
    isActive?: boolean;
    tooltip?: string | React.ComponentPropsWithoutRef<"div">;
  } & VariantProps<typeof sidebarMenuButtonVariants>
>(
  (
    {
      asChild = false,
      isActive = false,
      variant = "default",
      size = "default",
      tooltip,
      className,
      ...props
    },
    ref
  ) => {
    const Comp = asChild ? Slot : "button";
    const { state } = useSidebar();

    const button = (
      <Comp
        ref={ref}
        className={cn(
          sidebarMenuButtonVariants({ variant, size, isActive }),
          state === "collapsed" &&
            "justify-center group-data-[state=collapsed]/sidebar-wrapper:w-9 group-data-[state=collapsed]/sidebar-wrapper:p-2 [&>span:last-child]:group-data-[state=collapsed]/sidebar-wrapper:hidden",
          className
        )}
        {...props}
      />
    );

    // Show tooltip in collapsed mode
    if (tooltip && state === "collapsed") {
      return (
        <div className="relative group/tooltip">
          {button}
          <div className="pointer-events-none absolute left-full top-1/2 z-50 ml-2 hidden -translate-y-1/2 rounded-md bg-neutral-900 px-2 py-1 text-xs text-neutral-50 opacity-0 transition-opacity group-hover/tooltip:block group-hover/tooltip:opacity-100 dark:bg-neutral-50 dark:text-neutral-900">
            {typeof tooltip === "string" ? tooltip : null}
          </div>
        </div>
      );
    }

    return button;
  }
);
SidebarMenuButton.displayName = "SidebarMenuButton";

/**
 * Sidebar submenu list
 */
export const SidebarMenuSub = React.forwardRef<
  HTMLUListElement,
  React.ComponentPropsWithoutRef<"ul">
>(({ className, ...props }, ref) => {
  return (
    <ul
      ref={ref}
      className={cn(
        "ml-3.5 flex min-w-0 flex-col gap-1 border-l border-neutral-200 pl-2.5 dark:border-neutral-800",
        className
      )}
      {...props}
    />
  );
});
SidebarMenuSub.displayName = "SidebarMenuSub";

/**
 * Sidebar submenu item
 */
export const SidebarMenuSubItem = React.forwardRef<
  HTMLLIElement,
  React.ComponentPropsWithoutRef<"li">
>(({ ...props }, ref) => {
  return <li ref={ref} {...props} />;
});
SidebarMenuSubItem.displayName = "SidebarMenuSubItem";

/**
 * Sidebar submenu button
 */
export const SidebarMenuSubButton = React.forwardRef<
  HTMLAnchorElement,
  React.ComponentPropsWithoutRef<"a"> & {
    asChild?: boolean;
    size?: "sm" | "md";
    isActive?: boolean;
  }
>(({ asChild = false, size = "md", isActive, className, ...props }, ref) => {
  const Comp = asChild ? Slot : "a";

  return (
    <Comp
      ref={ref}
      className={cn(
        "flex h-7 min-w-0 items-center gap-2 overflow-hidden rounded-md px-2 text-xs outline-none transition-colors hover:bg-neutral-200 hover:text-neutral-900 focus-visible:ring-2 focus-visible:ring-neutral-950 active:bg-neutral-200 disabled:pointer-events-none disabled:opacity-50 dark:hover:bg-neutral-800 dark:hover:text-neutral-50 dark:focus-visible:ring-neutral-300 dark:active:bg-neutral-800 aria-disabled:pointer-events-none aria-disabled:opacity-50 [&>svg]:size-4 [&>svg]:shrink-0",
        size === "sm" && "h-6 text-xs",
        isActive &&
          "bg-neutral-200 text-neutral-900 dark:bg-neutral-800 dark:text-neutral-50",
        className
      )}
      {...props}
    />
  );
});
SidebarMenuSubButton.displayName = "SidebarMenuSubButton";

/**
 * SidebarInset - Container for the main content area next to the sidebar
 * Adjusts padding/margin based on sidebar state
 */
export const SidebarInset = React.forwardRef<
  HTMLDivElement,
  React.ComponentPropsWithoutRef<"div">
>(({ className, ...props }, ref) => {
  return (
    <div
      ref={ref}
      className={cn(
        "relative flex min-h-screen flex-1 flex-col bg-white dark:bg-neutral-950",
        "peer-data-[state=expanded]:ml-[--sidebar-width] peer-data-[state=collapsed]:ml-[--sidebar-width-icon]",
        "transition-all duration-300 ease-in-out",
        "max-md:ml-0",
        className
      )}
      {...props}
    />
  );
});
SidebarInset.displayName = "SidebarInset";

export {
  Collapsible as SidebarCollapsible,
  CollapsibleTrigger as SidebarCollapsibleTrigger,
  CollapsibleContent as SidebarCollapsibleContent,
};
