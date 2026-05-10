/**
 * Helpers for reading the real ID segment from a Next.js static-export
 * dynamic route. The static export only pre-renders the literal
 * `__placeholder__` segment, so when a real ID is requested the server
 * falls back to that pre-rendered HTML and `useParams()` returns the
 * placeholder instead of the live URL value.
 *
 * Use `resolveDynamicId(params, pathname, segment)` from a client
 * component that wraps Next's `useParams()` and `usePathname()`:
 *
 *     const params = useParams();
 *     const pathname = usePathname();
 *     const id = resolveDynamicId(params, pathname, "users", "id");
 *
 * The function trusts `params[paramName]` first; only when that value is
 * missing or equal to `__placeholder__` does it walk the URL pathname
 * looking for the segment immediately after the named parent segment.
 */

const PLACEHOLDER = "__placeholder__";

export function resolveDynamicId(
  params: Record<string, string | string[] | undefined> | null | undefined,
  pathname: string | null | undefined,
  parentSegment: string,
  paramName: string = "id",
): string {
  const raw = params?.[paramName];
  const fromParams = Array.isArray(raw) ? raw[0] : raw;
  if (fromParams && fromParams !== PLACEHOLDER) {
    return fromParams;
  }
  const segments = (pathname || "").split("/").filter(Boolean);
  const idx = segments.indexOf(parentSegment);
  if (idx >= 0 && segments.length > idx + 1) {
    const fromUrl = decodeURIComponent(segments[idx + 1]);
    if (fromUrl && fromUrl !== PLACEHOLDER) {
      return fromUrl;
    }
  }
  return "";
}
