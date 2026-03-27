# Error Collection Runbook

## Overview
- Error collection now relies solely on global `error` and `unhandledrejection` handlers; console method wrapping was removed for security and stability.
- Purpose: capture actionable runtime failures (message, stack, filename/line) and persist recent entries without mutating browser globals.

## What Is Captured
- `UNHANDLED_ERROR`: window-level errors with message, stack, filename, line, column, and timestamp.
- `UNHANDLED_REJECTION`: unhandled promise rejections with message, stack (when available), and timestamp.
- Warnings and info logs from inside the collector itself; no interception of `console.*`.

## Expected Behavior
- Errors are de-duped within a 5s window to prevent bursts.
- Persistence is debounced to minimize storage writes; only the most recent entries are kept.
- Console calls (`console.error|warn|log`) are **not** intercepted—this is intentional to avoid recursion and DevTools breakage.

## Operator Checks
1) Trigger an uncaught error in the extension context; confirm it appears as `UNHANDLED_ERROR`.
2) Trigger an unhandled promise rejection; confirm it appears as `UNHANDLED_REJECTION`.
3) Call `console.error` and verify it is **not** captured (by design).
4) Export errors (JSON or text) from the UI and ensure timestamps and stacks are present.
