package nip46

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip44"
)

// stubKeyer satisfies nostr.Keyer. Only GetPublicKey is reached by the tests
// here, the rest exist to satisfy the interface.
type stubKeyer struct{ pub nostr.PubKey }

func (s stubKeyer) GetPublicKey(context.Context) (nostr.PubKey, error)            { return s.pub, nil }
func (s stubKeyer) SignEvent(context.Context, *nostr.Event) error                 { return nil }
func (s stubKeyer) Encrypt(context.Context, string, nostr.PubKey) (string, error) { return "", nil }
func (s stubKeyer) Decrypt(context.Context, string, nostr.PubKey) (string, error) { return "", nil }
func (s stubKeyer) Nip04Encrypt(context.Context, string, nostr.PubKey) (string, error) {
	return "", nil
}
func (s stubKeyer) Nip04Decrypt(context.Context, string, nostr.PubKey) (string, error) {
	return "", nil
}

func buildRequest(t *testing.T, handler, client nostr.SecretKey, id string) nostr.Event {
	t.Helper()

	conversationKey, err := nip44.GenerateConversationKey(client.Public(), handler)
	if err != nil {
		t.Fatalf("conversation key: %v", err)
	}

	// Request.String() marshals it; "encoding/json" can't be imported here
	// because this package already declares a json identifier
	body := Request{ID: id, Method: "ping"}.String()
	ciphertext, err := nip44.Encrypt(body, conversationKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	evt := nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      nostr.KindNostrConnect,
		Content:   ciphertext,
		Tags:      nostr.Tags{nostr.Tag{"p", handler.Public().Hex()}},
		PubKey:    client.Public(),
	}
	if err := evt.Sign(client); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return evt
}

// A slow session must not stall unrelated ones. A single lock shared by the
// whole signer would make one hung threshold-signing ceremony block every other
// client on the server.
func TestDynamicSignerDoesNotBlockOtherSessions(t *testing.T) {
	handler1, handler2 := nostr.Generate(), nostr.Generate()
	client := nostr.Generate()

	secrets := map[string]nostr.SecretKey{
		handler1.Public().Hex(): handler1,
		handler2.Public().Hex(): handler2,
	}

	release := make(chan struct{})
	entered := make(chan string, 8)
	openGate := sync.OnceFunc(func() { close(release) })

	// requests run in the background, so release and join them before the test
	// returns -- a defer runs ahead of t.Cleanup
	var wg sync.WaitGroup
	defer func() { openGate(); wg.Wait() }()

	signer := &DynamicSigner{
		GetHandlerSecretKey: func(ctx context.Context, handlerPubkey nostr.PubKey) (context.Context, nostr.SecretKey, error) {
			entered <- handlerPubkey.Hex()
			select {
			case <-release:
			case <-ctx.Done():
				return ctx, nostr.SecretKey{}, ctx.Err()
			}
			return ctx, secrets[handlerPubkey.Hex()], nil
		},
		GetUserKeyer: func(ctx context.Context, _ nostr.PubKey) (context.Context, nostr.Keyer, error) {
			return ctx, stubKeyer{pub: nostr.Generate().Public()}, nil
		},
	}
	signer.Init()

	var mu sync.Mutex
	var errs []error
	send := func(handler nostr.SecretKey, id string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, resp, _, err := signer.HandleRequest(context.Background(), buildRequest(t, handler, client, id))
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			if resp.Result != "pong" {
				mu.Lock()
				errs = append(errs, errors.New("unexpected result: "+resp.Result))
				mu.Unlock()
			}
		}()
	}

	// occupies handler one
	send(handler1, "a1")
	select {
	case got := <-entered:
		if got != handler1.Public().Hex() {
			t.Fatalf("expected the first request to be handled, got %s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first request never reached the signer")
	}

	// a second request on the same session must wait its turn
	send(handler1, "a2")
	select {
	case got := <-entered:
		t.Fatalf("request %s ran while the first one was still going", got)
	case <-time.After(200 * time.Millisecond):
	}

	// a request on a different session must not be blocked by it
	send(handler2, "b1")
	select {
	case got := <-entered:
		if got != handler2.Public().Hex() {
			t.Fatalf("expected the other session to run, got %s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a request for a different session was blocked by the first one")
	}

	openGate()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
}

// Serializing per session is only safe if the replay window still works.
func TestDynamicSignerRejectsReplayedRequest(t *testing.T) {
	handler, client := nostr.Generate(), nostr.Generate()

	signer := &DynamicSigner{
		GetHandlerSecretKey: func(ctx context.Context, _ nostr.PubKey) (context.Context, nostr.SecretKey, error) {
			return ctx, handler, nil
		},
		GetUserKeyer: func(ctx context.Context, _ nostr.PubKey) (context.Context, nostr.Keyer, error) {
			return ctx, stubKeyer{pub: handler.Public()}, nil
		},
	}
	signer.Init()

	if _, _, _, err := signer.HandleRequest(context.Background(), buildRequest(t, handler, client, "same")); err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	_, _, _, err := signer.HandleRequest(context.Background(), buildRequest(t, handler, client, "same"))
	if !errors.Is(err, AlreadyHandled) {
		t.Fatalf("expected the replay to be rejected, got %v", err)
	}
}

func TestStaticKeySignerRejectsReplayedRequest(t *testing.T) {
	handler := nostr.Generate()
	client := nostr.Generate()
	signer := NewStaticKeySigner(handler)

	if _, _, _, err := signer.HandleRequest(context.Background(), buildRequest(t, handler, client, "same")); err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	_, _, _, err := signer.HandleRequest(context.Background(), buildRequest(t, handler, client, "same"))
	if !errors.Is(err, AlreadyHandled) {
		t.Fatalf("expected the replay to be rejected, got %v", err)
	}
}

// A short "p" tag must be rejected rather than panicking on handler[1].
func TestHandleRequestRejectsMalformedPtag(t *testing.T) {
	signer := &DynamicSigner{
		GetHandlerSecretKey: func(ctx context.Context, _ nostr.PubKey) (context.Context, nostr.SecretKey, error) {
			return ctx, nostr.Generate(), nil
		},
		GetUserKeyer: func(ctx context.Context, _ nostr.PubKey) (context.Context, nostr.Keyer, error) {
			return ctx, stubKeyer{pub: nostr.Generate().Public()}, nil
		},
	}
	signer.Init()

	for _, tags := range []nostr.Tags{
		{},
		{{"p"}},
		{{"p", "not-hex"}},
		{{"p", "abcd"}},
	} {
		_, _, _, err := signer.HandleRequest(context.Background(), nostr.Event{
			Kind: nostr.KindNostrConnect,
			Tags: tags,
		})
		if err == nil {
			t.Fatalf("expected tags %v to be rejected", tags)
		}
	}
}
