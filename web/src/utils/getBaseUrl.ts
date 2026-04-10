export function getBaseUrl(): string {
  if (typeof window !== "undefined") {
    const { protocol, hostname, port } = window.location;
    return `${protocol}//${hostname}${port ? `:${port}` : ""}`;
  }

  const protocol =
    process.env.VERCEL_URL || process.env.NODE_ENV === "production"
      ? "https:"
      : "http:";
  const hostname = process.env.VERCEL_URL ?? process.env.HOSTNAME ?? "localhost";
  const port = process.env.PORT ? `:${process.env.PORT}` : "";

  return `${protocol}//${hostname}${port}`;
}
