interface CookieOptions {
  expires?: Date;
  path?: string;
  domain?: string;
  secure?: boolean;
  sameSite?: "Strict" | "Lax" | "None";
  "max-age"?: number;
}

export function getCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop()?.split(";").shift() ?? null;
  return null;
}

export function setCookie(
  name: string,
  value: string,
  options: CookieOptions = {}
): void {
  if (typeof document === "undefined") return;

  let updatedCookie =
    encodeURIComponent(name) + "=" + encodeURIComponent(value);

  if (options.expires) {
    updatedCookie += "; expires=" + options.expires.toUTCString();
  }

  if (options["max-age"] !== undefined) {
    updatedCookie += "; max-age=" + options["max-age"];
  }

  updatedCookie += "; path=" + (options.path ?? "/");

  if (options.domain) {
    updatedCookie += "; domain=" + options.domain;
  }

  if (options.secure) {
    updatedCookie += "; secure";
  }

  if (options.sameSite) {
    updatedCookie += "; samesite=" + options.sameSite;
  }

  document.cookie = updatedCookie;
}

export function deleteCookie(name: string): void {
  setCookie(name, "", { "max-age": -1 });
}
