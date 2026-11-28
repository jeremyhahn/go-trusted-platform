"use client";

import { useDNS, useMutation } from "@/hooks";
import type { RegisterRequest, RegisterResponse, ResolveRequest, ResolveResponse } from "trusted-platform-sdk";

/** Resolve a name against the managed zones and register a name (client.dns.resolve / client.dns.register, #2060). */
export function useDNSLookup() {
  const dns = useDNS();
  const resolve = useMutation<ResolveResponse, ResolveRequest>((request) => dns.resolve(request));
  const register = useMutation<RegisterResponse, RegisterRequest>((request) => dns.register(request));
  return {
    resolve: resolve.mutateAsync,
    isResolving: resolve.isLoading,
    register: register.mutateAsync,
    isRegistering: register.isLoading,
  };
}
