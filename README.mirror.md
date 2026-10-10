# nostr (Hyphae mirror)

Pinned mirror of the canonical `fiatjaf.com/nostr` module, used by
[iDoris-ai/Hyphae](https://github.com/iDoris-ai/Hyphae) to consume one upstream
bug fix that has not been released yet.

## Provenance

- Upstream: `https://gitnostr.com/npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6/nostrlib.git`
- Base commit: `58e4c715304e3e443cc05cdb6894c90d91729554` (verbatim, first commit)
- License: Unlicense, unchanged (see `LICENSE`)
- The module path stays `fiatjaf.com/nostr` on purpose: it is consumed through a
  module `replace`, and renaming it makes Go report the same module under two
  paths.

## Patch on top of the base

`subscription.go` + `subscription_dispatch_test.go`: `Subscription.mu` becomes
`sync.RWMutex` and the `dispatchEvent` goroutine holds `RLock` for the whole
send/select, so `close(sub.Events)` in `Relay.PrepareSubscription` can no longer
run concurrently with a send. The test is a deterministic `testing/synctest`
regression covering stored/live sends under unsub, parent cancellation, relay
cancellation, and late dispatch.

Upstream PR: `e6561592ddc2132bc8304260b1d40affc2f79c67368f66769c88acdcfeccd08e`

## Removal

Delete the `replace fiatjaf.com/nostr => github.com/iDoris-ai/nostr ...` line in
Hyphae's `go.mod` once the canonical module ships the fix upstream, then re-run
`go mod tidy`.
