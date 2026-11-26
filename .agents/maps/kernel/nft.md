# kernel/nft Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/nft.md` for the paired decision history (not yet created; pre-split decisions D4, D5, D8–D11 and the nftables half of D13 stay in `.agents/decisions/kernel/netns.md`).
>
> Verified: 2026-11-15 (split out of the kernel/netns full mapping of 2026-11-03; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-25 (targeted verification only since the full mapping; latest change: `filter_with_mark`, `filter_prerouting` and `PRI_NAT_DST` (`-100`) split PREROUTING filter chains around Linux's `NF_IP_PRI_NAT_DST` hook priority)

## Responsibilities

`kernel/nft` owns nftables rulesets, the `NETLINK_NETFILTER` control plane and synthetic-packet
expression evaluation. Root: `core/kernel/src/nft.rs`. Namespace translation, path construction,
hook selection and forwarding remain in `kernel/netns`; socket error handling stays in `kernel/net`,
and netlink transport in `kernel/netlink`.

## Key types

- `Nft` — generation and tables; `Table`, `Chain`/`Base` (hook, priority, type, policy), `Rule`
  (raw expression attributes), `Set` (key length, flags, raw elements).
- `nft::Packet` (fake IP/TCP/UDP packet built from the socket), `Iif`, `Outcome` (accept, drop,
  reject with errno, dnat), `Eval`; namespace-side packet construction is in `kernel/netns`.

## Public entry points

- `nft::handle` handles one netfilter datagram.
- `Nft::nat`, `Nft::filter_with_mark`, `Nft::filter_prerouting`, `PRI_NAT_DST`, `has_nat`,
  `has_filter` and `tracks` serve namespace and socket callers.

## Data flow / lifecycle

### nftables control plane

- One ruleset per namespace; every request (queries too) needs `CAP_NET_ADMIN` over the
  namespace owner. Changes come in `BATCH_BEGIN`/`END` pairs within one datagram: the batch runs
  on a clone, every error is reported, and the clone replaces the ruleset only if all succeeded;
  `NFNL_BATCH_GENID` mismatches `ERESTART`; the generation increases per committed batch.
- Tables (families inet, ip, ip6, arp, bridge, netdev; only `DORMANT` flag, `OWNER` `EOPNOTSUPP`),
  chains (base chains with hook, priority, type filter/nat/route, policy; existing chains can
  change policy and userdata and be renamed by handle with `CHAIN_HANDLE` + new `CHAIN_NAME`,
  updating rule and verdict-map references and returning `EEXIST` on collision; `EBUSY` when
  referenced by rules or verdict-map elements), rules (raw
  expressions; position, append, replace — replacing preserves the rule's handle), sets and elements
  (key length 1..64, `%d` names, anonymous sets dropped when unused; `EBUSY` while referenced;
  verdict-map elements validate jump targets and count toward `CHAIN_USE`).
  Stateful objects and flowtables `EOPNOTSUPP`; `DESTROY*` maps to delete ignoring `ENOENT`.
  `DELTABLE`/`DESTROYTABLE` with family 0 or without a name and handle flush instead (Linux's
  `nft_flush`, what `nft flush ruleset` sends): every table of the family, of all families for 0,
  only those with the name when one is given; matching nothing succeeds. Other requests with
  family 0 are `EAFNOSUPPORT`. `DELTABLE` honours `NLM_F_NONREC` (`EBUSY` when the table still has
  chains or sets).
- Validation: expression names must be known (39); jump targets must exist and not be base chains;
  loops `EMLINK`; set references rewritten to names. Arguments are not validated.
- Queries outside batches: `GETGEN`, dumps of tables, chains, rules (filters by table and chain),
  sets and elements in 6.8's format, returned as resumable `NetlinkItem::Dump` entries packed on
  demand to the caller's receive buffer; `GETSETELEM` (`SetElemDump`) splits elements across
  bounded multipart `NFT_MSG_NEWSETELEM` messages (at most `min(max, 3776)` bytes per chunk)
  followed by the trailing empty `NFT_MSG_NEWSETELEM` and `NLMSG_DONE`; `nft_compat` revision
  queries; empty ctnetlink dumps. No `NLM_F_ECHO`, no monitor notifications. Base-chain counters
  are 0.
- An initial-namespace commit re-evaluates port forwarding.

### Expression evaluation

- Expressions: `meta` (len, protocol, mark get/set, iif/oif and names, skuid/skgid on OUTPUT,
  nfproto, l4proto, pkttype), `payload`, `cmp`, `bitwise`, `lookup`, `immediate`, `ct` (state is
  NEW, or ESTABLISHED for UDP to a peer already heard from; others no match), `fib` (address type
  only), `nat` (DNAT, range minimum; SNAT no-op), `redir` (127.0.0.1/`::1` on OUTPUT, the input
  interface's address on PREROUTING), `reject`, `queue` (drop), `limit` (a token bucket per rule
  expression, packets or bytes, `over` inverting) and `quota` (bytes counted per rule expression,
  `over` inverting); a packet's length, for them as for `meta len`, is its headers only. `counter`,
  `log`, `notrack`, `objref`, `last`, `masq`, `connlimit`, `dup` always match without
  effect. xt targets DNAT, REDIRECT, MARK, ACCEPT, DROP, REJECT (others no-ops) and matches
  comment, mark, owner, conntrack (state and masked original destination address, independently
  invertible, using the destination before DNAT in the evaluating namespace), state, addrtype,
  tcp, udp, limit (the same bucket from avg and burst), hashlimit (revisions 1–3), and recent
  (named per-netns address histories with SET, CHECK, UPDATE, REMOVE, masks, expiry, hit counts,
  TTL checks and optional reaping). Unknown or
  unevaluable expressions break the rule. Jumps to missing chains or deeper than 16 drop; 100,000
  steps accept; chains end in their policy.
- Native `dynset` adds, updates and deletes set members during evaluation. Limits and quotas
  keep separate state for each key. Updates refresh timeouts, and lookups and element dumps see
  live dynamic members. xt hashlimit rules sharing a table name and family in one network namespace
  use the same keyed state for packet, byte or rate-window matching.
- `kernel/netns` builds packets and selects hooks at connect/sendto and forwarding probes;
  matching-family base chains run in priority order. `Outcome` returns accept, drop, reject
  with errno or DNAT to that caller. `tracks()` decides whether `SO_ORIGINAL_DST` answers.
- POSTROUTING (nat and filter), INPUT-hook nat and arp/bridge/netdev tables are never evaluated
  by the integration; SNAT and MASQUERADE have no effect.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/netlink` dispatches `NETLINK_NETFILTER` requests through `KernelHost`.
- `kernel/netns` constructs packets and chooses hooks; `kernel/net` queries NAT/conntrack presence.

### Outbound

- `kernel/ns` owns `NetNs` and its `nft` field; `kernel/cred` checks namespace capability.
- `kernel/netlink` provides message/attribute encoding.
- `kernel/netlink` compares the initial ruleset generation before/after requests and calls
  `kernel/net` to refresh `kernel/netns` forwarding when it changes.

## Invariants and gotchas

- A named recent list holds at most 100 addresses. Its first installed match chooses the mask.
  History survives unrelated and rejected batches; increasing timestamp capacity or committing
  removal of the last referencing rule clears it.
- Rulesets are per network namespace; requests, including queries, require `CAP_NET_ADMIN`.
- Evaluation uses synthetic headers, not host packets. Hook placement and verdict application
  must stay consistent with `kernel/netns`; changing either side requires reading both maps.

## Confirmed bugs / technical debt

- Byte limits and quotas count headers only.
- **nft control-plane gaps:** no `NLM_F_ECHO` and no monitor notifications.
- POSTROUTING, SNAT and MASQUERADE have no effect; unsupported expression effects are listed above.

## Open questions

None.

## To verify

- Linux 6.1's results for `NLM_F_NONREC` on `DELTABLE` and generation bumps for no-op batches (taken
  from knowledge, not a source checkout).
