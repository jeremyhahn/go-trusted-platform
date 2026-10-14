# Security Primitives and Policy Engine — Using It

> **Status: NORMATIVE** · Scope: `pkg/security/`, `pkg/policy/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## What this covers, and what it does not

This section is the platform's **local policy engine** — an embedded Open Policy
Agent runtime with built-in Rego policies for attestation and proxy
authorization — plus two library packages that are not currently wired into
anything.

If you came here looking for something else:

| You want | Go to |
|---|---|
| Logging in, certificates, tokens | [`docs/auth/`](../auth/) |
| Users, roles, permissions, who-may-do-what | [`docs/iam/`](../iam/) |
| Keys and encryption | [`docs/kms/`](../kms/) |
| Issuing certificates | [`docs/ca/`](../ca/) |
| Whether a node or workload is trustworthy | [`docs/attestation/`](../attestation/) |
| Keeping secrets out of config files | [`docs/secrets/`](../secrets/) |
| Edge gateway routing and authorization | [`docs/proxy/`](../proxy/) |

---

## The policy engine, in one paragraph

The gateway can require that a request pass a **Rego policy** before it is
proxied, and the platform can require that host, VM, container, image and quote
evidence pass a Rego policy before a workload is admitted. Those policies ship
compiled into the binary, so a node with no configuration still has working
defaults. You can override any of them by dropping a file with the same name
into a policy directory.

**The default is deny.** A policy that does not explicitly allow, denies.

---

## The six built-in policies

| File name | Rego package | Decides |
|---|---|---|
| `host.rego` | `attestation.host` | Whether host attestation evidence is acceptable |
| `vm.rego` | `attestation.vm` | Whether VM attestation evidence is acceptable |
| `container.rego` | `attestation.container` | Whether a container may be admitted |
| `image.rego` | `attestation.image` | Whether an image may be admitted |
| `quote.rego` | `attestation.quote` | Whether a TPM quote is acceptable |
| `proxy_authz.rego` | `proxy.authz` | Whether a proxied request is authorized |

The **file name** (without `.rego`) is the policy's name — what a route's
`auth.opa-policy` refers to. The **Rego package** determines where the engine
looks for the `allow` and `violations` rules.

---

## Turning it on for the gateway

```yaml
opa:
  enabled: true
  policy-dir: /etc/trusted-platform/policies   # optional
```

Then name a policy on a route's `auth.opa-policy`. A route with no policy name
is not policy-checked at all.

Leaving `policy-dir` unset is fine — the built-in policies still load.

---

## Overriding a built-in policy

Write a file with the **same name** into `policy-dir`:

```bash
sudo install -d -m 0750 /etc/trusted-platform/policies
sudo install -m 0640 ./proxy_authz.rego /etc/trusted-platform/policies/proxy_authz.rego
sudo systemctl restart gatewayd
```

Directory policies load first and win; the built-in of the same name is skipped.

Every policy needs two rules in its package:

```rego
package proxy.authz

default allow := false

allow if {
    input.identity.tenant == "platform"
    input.request.method == "GET"
}

violations contains msg if {
    not allow
    msg := "tenant not permitted for this method"
}
```

`allow` is the decision. `violations` is the explanation — logged and audited
server-side, and **never returned to the client**.

---

## Three things that will catch you out

**1. Policies load once, at startup.** The engine has a file watcher; the
gateway does not use it. Editing a policy on a running gateway changes nothing
until you restart. If you need the change live, restart the service.

**2. A broken policy stops the gateway from starting.** That is deliberate — the
alternative is a gateway that starts and denies every request with an opaque
error. Validate before you deploy:

```bash
opa check ./proxy_authz.rego
opa eval -d ./proxy_authz.rego -i ./input.json 'data.proxy.authz.allow'
```

Note that this is upstream OPA tooling. **There is no `platformctl` verb for
policies** — no list, no test, no reload. [cli.md](cli.md).

**3. A policy that forgets `default allow := false` still denies.** The engine
applies its configured default action when `allow` produces no result, and the
gateway hard-codes that default to `deny` regardless of configuration. Write the
`default` line anyway — it makes the intent readable.

---

## The one setting that can flip the default

`attestation.policy.default-action` accepts `deny` (the platform default) and
`allow`. Setting it to `allow` means **any policy whose `allow` rule is silent
permits**. The gateway is immune because it hard-codes deny, but other consumers
of that configuration are not. Leave it at `deny`.

```yaml
attestation:
  policy:
    engine: opa
    policy-dir: /etc/trusted-platform/policies
    default-action: deny
```

`engine: rego` is an accepted value with no implementation behind it. Use `opa`.

---

## Protect the policy directory

Anything in `policy-dir` that parses as Rego is compiled and can override a
built-in policy. There is **no signature check and no provenance requirement**.
Write access to that directory is write access to the platform's admission
rules. Treat its permissions the way you treat a private key directory.

---

## Troubleshooting

**The gateway will not start, complaining about a policy.**
Working as intended. Either the directory does not exist, a file does not parse,
or the set does not compile. `opa check` the directory.

**A request is denied and you cannot see why.**
Violations are logged server-side, never returned. Look in the gateway's logs
for the audit record. The two reasons are `opa_denied` (the policy said no) and
`opa_error` (evaluation failed — treated as a denial).

**A policy change did nothing.**
Restart. Policies load once at startup.

**Everything is denied after adding a policy.**
Two likely causes: the Rego package path does not match what the engine queries
(`data.<package>.allow`), or `allow` is never satisfied. `opa eval` the same
input document against the file.

**Everything is allowed.**
Check `default-action`. If it is `allow`, a silent policy permits.

**You edited a built-in policy and it came back.**
The built-ins are compiled into the binary. To change one, put a file with the
same name in `policy-dir` — that overrides it. Editing the source requires a
rebuild.

---

## One thing to be aware of

`pkg/security/ratelimit` and `pkg/security/validation` are complete,
well-tested libraries — and **nothing in the platform calls them**. Do not
assume the platform rate-limits an endpoint or sanitizes an input because those
packages exist. Whatever protection a given surface has, it has for its own
reasons. [architecture.md](architecture.md) §3.

The deleted legacy `README.md` also documented a `pkg/security/audit`
package with an async audit logger and HTTP/gRPC middleware. **That package does
not exist.** Do not plan against it. [architecture.md](architecture.md) §8.

---

## Where to go next

- [architecture.md](architecture.md) — default-deny, the trust boundary around the policy directory, and the corrections against the legacy README
- [engineering.md](engineering.md) — the engine's exported surface and error semantics
- [api.md](api.md) — why none of this is on a transport, and what is
- [`docs/proxy/`](../proxy/) · [`docs/attestation/`](../attestation/) · [`docs/iam/`](../iam/)
