# IDN-13 — Enterprise transport: PAC, resume, mTLS (§14.4, T18) — **partial**

**Priority:** P2 — hardening and reach

Done: **resumable ranged downloads** (`Options.Resume`, `ResumeAttempts`, exponential
backoff capped at 30 s), **proxy authentication** (`ProxyUser`/`ProxyPassword`, Basic,
attached only to a proxy the resolver chose; a 407 is `fetch.ErrProxyAuth` and is never
retried), **mTLS client certificates** (`ClientCertPEM`/`ClientKeyPEM`, caller-supplied
bytes only, refused at construction if unusable), and the **`ProxyResolver` seam**
(nil = `http.ProxyFromEnvironment`; a resolver error fails the request, never goes
direct).

Resume widens how bytes are obtained, not what is accepted: go-tuf's hash check still
decides. The fetcher's own obligation is the offset — a 206 is used only if it carries
exactly one well-formed `Content-Range` starting at the requested byte, consistent with
its `Content-Length`, the total length and strong ETag seen before, and the body does not
overrun it; anything else fails closed with no bytes returned. A 200 to a range request
or a 416 starts over from zero; `If-Range` carries a strong ETag so a changed file comes
back whole. Negative tests: lying/malformed/duplicated `Content-Range`, wrong offset,
overrun, truncated and zero-byte resumes, total above the ceiling, 200 to a range, proxy
auth failure (no credential disclosure, no retry), credentials never sent direct, mTLS
without a certificate and with one from another authority.

Open: the **OS-native proxy resolvers**, PAC/WPAD included — WinHTTP/WinINET,
`SCDynamicStore`, GSettings. Each needs cgo or a substantial per-platform implementation
and cannot be exercised on a runner with no proxy configuration; a host that needs one
today supplies a `ProxyResolver`. Also open: hosts (`cmd/installer`) do not yet expose
these options, and a client key held in an OS store or HSM (a `crypto.Signer` rather
than PEM bytes) is not supported.
