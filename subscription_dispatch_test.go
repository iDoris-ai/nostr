package nostr

import (
	"context"
	"math"
	"testing"
	"testing/synctest"
)

func TestSubscriptionDispatchCancellation(t *testing.T) {
	for _, stored := range []bool{true, false} {
		phase := "live"
		if stored {
			phase = "stored"
		}
		for _, cancellation := range []string{"unsub", "parent", "relay"} {
			t.Run(phase+"/"+cancellation, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					relay := NewRelay(ctx, "wss://relay.test", RelayOptions{})
					defer relay.Close()
					sub := relay.PrepareSubscription(ctx, Filter{}, SubscriptionOptions{MaxWaitForEOSE: math.MaxInt64})
					defer sub.Unsub()
					if err := sub.Fire(); err != nil {
						t.Fatal(err)
					}
					sub.eosed.Store(!stored)

					sub.dispatchEvent(Event{Content: "delivered"})
					if event := <-sub.Events; event.Content != "delivered" {
						t.Fatalf("unexpected event: %q", event.Content)
					}

					// With no receiver, both dispatches must block in their send selects.
					sub.dispatchEvent(Event{Content: "pending one"})
					sub.dispatchEvent(Event{Content: "pending two"})
					synctest.Wait()
					if sub.mu.TryLock() {
						sub.mu.Unlock()
						t.Fatal("pending dispatches did not protect Events from closure")
					}

					switch cancellation {
					case "unsub":
						sub.Unsub()
					case "parent":
						cancel()
					case "relay":
						relay.Close()
					}
					synctest.Wait()
					sub.storedwg.Wait()
					select {
					case _, open := <-sub.Events:
						if open {
							t.Fatal("event delivered after pending dispatches finished")
						}
					default:
						t.Fatal("Events was not closed after cancellation")
					}

					// A dispatch arriving after closure must also finish without sending.
					sub.dispatchEvent(Event{Content: "late"})
					synctest.Wait()
					sub.storedwg.Wait()
					// synctest.Test waits for every goroutine in the bubble to exit.
				})
			})
		}
	}
}
