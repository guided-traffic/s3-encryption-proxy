# ADR 0030: The network boundary belongs to the administrator

## Status

**Accepted.** Date: 2026-09-13. Both halves were decided with the owner on **2026-09-12**: the
monitoring half in the 5.0.0 review of the unauthenticated metrics listener, the chart half in the
decision list of the documentation audit. The monitoring decision was taken and never written up,
so the repository has been holding both positions at once — a decision that no network policy
ships, and a chart that still ships one. This record is where the decision is written down.

**Not built.** As of 2026-09-13 the chart still declares its `networkPolicy` values and still
renders the object wherever it is switched on, so D1 and D3 are outstanding in full. Of D2 the
statement half already stands: the security architecture says that restricting who can reach the
metrics port is the operator's. What is outstanding is the removal itself and the upgrade note,
and they land together, in 5.0.0.

## Context

The chart ships an optional network policy: `networkPolicy.enabled`, off by default,
`policyTypes: [Ingress, Egress]`, one ingress rule admitting TCP 8080 and one egress rule allowing
443 and 53. The production values profile the chart ships turns it on and adds a second ingress
rule for the metrics port.

None of these rules names a peer. An empty `from` is **allow from anywhere**, not a selector, and
an empty `to` is the same in the other direction. What ships is therefore not a restriction on
*who* may talk to the proxy; it is port filtering with the peer set left wide open — a blanket
grant wearing the name of a security control. An operator reading a values file that offers
`networkPolicy` has every reason to believe the box is ticked once they set it to `true`.

The chart cannot write these rules correctly for anyone, and that is the reason the feature cannot
be fixed in place. Which namespaces may reach the proxy, which addresses the S3 backend answers on,
which port it listens on, whether DNS is in the cluster or outside it — none of that is knowable
from a chart. A default that is correct for one topology is wrong for the next one, and there is no
value the chart could ship that is right by default.

The default also contradicts the chart itself. It admits the proxy's own port and nothing else,
so enabling it with stock values cuts the metrics port — `monitoring.bind_address` is `:9090`. The
Service's own TLS listener escapes only because it shares that same port (ADR 0026). The one
control the chart offers breaks a feature the same chart ships, at the moment it is switched on.

Beside that sits the monitoring listener. It carries no authentication at all and is **to be fenced
by the network, not by the proxy** (ADR 0014 D11). That sentence names a fence without naming who
builds it, and the shipped policy answers it in two contradictory ways depending on which values
profile is used: at stock values it closes the metrics port to everything, Prometheus included,
while the production profile adds a metrics-port rule with an empty peer set and so opens that
port to everything that can route to the pod.

## Decision

**D1. The chart ships no network policy at all.** No values key, no rendered object, no toggle. The
administrator writes the policy for their own cluster and maintains it, because they are the only
party that knows the topology it has to describe. The project does not pretend otherwise by
shipping a control it cannot aim.

**D2. This covers the monitoring listener specifically.** The listener is unauthenticated by design
(ADR 0014 D11), and restricting who may reach it is the administrator's boundary, not something the
chart supplies. It is carried as a stated residual risk in the security documentation — where an
unshipped control belongs — rather than papered over with an object that grants everything.

**D3. The removal is announced where an operator upgrading will read it.** Dropping a values key is
silent: a chart ignores value keys it no longer declares, so an operator who set
`networkPolicy.enabled: true` gets no error, no warning and no rendered policy. The chart's upgrade
note names the key, says the policy is gone, and says it is now theirs to write and maintain. The
release is a major, which is where a removal like this belongs (ADR 0018) — the note is not
optional on top of that, it is the only signal that reaches the operator at all.

## Consequences

* **An operator who had enabled the shipped policy loses it on upgrade with no error.** That is the
  security-relevant half of this decision and the reason D3 exists. What they lose is smaller than
  it looks — the policy restricted ports, never peers — but an egress rule limited to 443 and 53 is
  not nothing, and after the upgrade their pod has whatever the cluster default is.
* **The project will ship no network-level control for this proxy.** Not a weak one, not a
  default-off one: none. Everything on that axis is documentation — the security architecture
  carries the exposure as a residual risk, and the chart's documentation says whose job it is.
* **The chart stops contradicting itself.** No shipped value can cut the metrics port, because no
  shipped value touches the network at all.
* **A deployment that never enabled the policy sees no change**, which is every deployment using
  stock values, since the key defaults to `false`.
* Nothing in the chart's tests asserts the policy's shape, so its removal breaks no test — and
  equally, nothing catches the wrong-port default before an operator does.

## Alternatives Considered

**Derive the default ingress from the chart's own switches** — admit the metrics port when
monitoring is enabled. Rejected: it fixes the self-contradiction and leaves the actual defect
untouched. The peer set is still *anywhere*, so it is the same blanket grant, only better aimed. A
control that admits the whole cluster to the proxy port is not a posture worth handing an operator
by default, however neatly its port list is computed.

**Ship an empty ingress rule list and force an explicit rule.** Rejected, and it is the worst of
the options: in Kubernetes an `Ingress` policy type with no rule denies everything, so enabling the
policy as shipped would cut the proxy's own port as well — the chart would ship a switch whose
documented purpose is protection and whose effect is an outage.

**Document the limitation and leave the values in place.** Rejected: it leaves the trap armed
behind a sentence that the person flipping the switch is not reading. Someone who sets
`networkPolicy.enabled: true` is looking for a control, not for a caveat about one, and the chart
would keep offering the word while the object grants everything.

## Residual risks

* **The monitoring listener has no network-level protection and none is planned.** Anything that
  can route to the pod can scrape it. The exposure is bounded by what the listener exports rather
  than by who can reach it, and that is the accepted position, not an oversight.
* **Whether administrators actually write a policy is unverified**, and it is outside what this
  project can assert. Nothing renders, nothing checks, and no test or end-to-end run can observe a
  cluster's policy from here. The claim this record makes is about ownership, not about outcome.
* **D3's note reaches only an operator who reads it.** A silent upgrade is silent; there is no
  mechanism that can make a removed values key fail loudly, so the note is a best effort and the
  gap it leaves is real.

## References

* [ADR 0014](0014-authentication-is-sigv4-no-rate-limiting.md) — D11: the monitoring listener is
  unauthenticated by design and is to be fenced by the network, not by the proxy. This record says
  whose fence it is.
* [ADR 0026](0026-the-proxy-terminates-tls-at-its-own-service.md) — the Service's own TLS listener,
  which shares the proxy's own port and so is not what the shipped default's ingress rule cuts.
* [ADR 0013](0013-a-configuration-key-exists-only-if-code-reads-it.md) — the same rule one level
  down: a key that does not deliver what it names is removed, not documented as a limitation.
* [ADR 0018](0018-a-major-release-is-declared-by-a-label.md) — a removal with no compatibility shim
  lands in a release declared major by its label.
* [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — the home of the residual risk this
  decision leaves standing; its statement about a shipped policy goes with the object.
