package nip46

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"sync"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip44"
	"github.com/mailru/easyjson"
)

var _ Signer = (*DynamicSigner)(nil)

// sessionKey identifies a single NIP-46 conversation: a client talking to one
// of our handler pubkeys.
type sessionKey struct {
	handler nostr.PubKey
	client  nostr.PubKey
}

type DynamicSigner struct {
	// { [handlePubkey]: {[clientKey]: Session} }
	sessions map[nostr.PubKey]map[nostr.PubKey]*Session

	// used for switch_relays call
	DefaultRelays []string

	// mu guards sessions and sessionLocks, nothing else. It is never held
	// across a user callback or any cryptographic work, both of which can be
	// arbitrarily slow.
	mu sync.Mutex

	// { {handler, client}: lock } -- one lock per session, see lockSession.
	sessionLocks map[sessionKey]*sync.Mutex

	// the handler is the keypair we use to communicate with the NIP-46 client, decrypt requests, encrypt responses etc
	// the context can be returned as is, but it can also be returned with some values in it so they can be passed
	//   to other functions later in the chain.
	GetHandlerSecretKey func(
		ctx context.Context,
		handlerPubkey nostr.PubKey,
	) (context.Context, nostr.SecretKey, error)

	// called when a client calls "connect", use it to associate the client pubkey with a secret or something like that
	OnConnect func(ctx context.Context, from nostr.PubKey, secret string) error

	// this should correspond to the actual user on behalf of which we will respond to requests
	// the context works the same as for GetHandlerSecretKey
	GetUserKeyer func(ctx context.Context, handlerPubkey nostr.PubKey) (context.Context, nostr.Keyer, error)

	// this is called on every sign_event call, if it is nil it will be assumed that everything is authorized
	AuthorizeSigning func(ctx context.Context, event nostr.Event, from nostr.PubKey) error

	// this is called on every encrypt or decrypt calls, if it is nil it will be assumed that everything is authorized
	AuthorizeEncryption func(ctx context.Context, from nostr.PubKey) bool

	// unless it is nil, this is called after every event is signed
	OnEventSigned func(event nostr.Event)
}

func (p *DynamicSigner) Init() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
}

func (p *DynamicSigner) initLocked() {
	p.sessions = make(map[nostr.PubKey]map[nostr.PubKey]*Session)
	p.sessionLocks = make(map[sessionKey]*sync.Mutex)
}

// lockSession returns the lock that serializes requests for a single
// (handler, client) pair.
//
// Sessions must not share a lock with each other. The callbacks below
// (GetHandlerSecretKey, GetUserKeyer, AuthorizeSigning) and the signer they
// wrap can take arbitrarily long -- a sign_event may mean a multi-round
// threshold signing ceremony with remote signers -- so a single global lock
// would let one slow session stall every other client on the server.
//
// The lock is still needed per session: Session keeps a replay window that
// ParseRequest mutates, and requests for the same session must not overlap.
func (p *DynamicSigner) lockSession(handlerPubkey, clientPubkey nostr.PubKey) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.sessionLocks == nil {
		p.initLocked()
	}

	key := sessionKey{handler: handlerPubkey, client: clientPubkey}
	lock, exists := p.sessionLocks[key]
	if !exists {
		lock = new(sync.Mutex)
		p.sessionLocks[key] = lock
	}
	return lock
}

// sessionFor returns the session for the given pair, creating it via create if
// there isn't one yet. The caller must hold the lock from lockSession for that
// same pair, so create runs at most once per pair.
//
// mu is not held while create runs, since creating a session involves deriving
// a conversation key and calling back into the user-supplied GetUserKeyer.
func (p *DynamicSigner) sessionFor(
	handlerPubkey, clientPubkey nostr.PubKey,
	create func() (*Session, error),
) (*Session, error) {
	p.mu.Lock()
	if p.sessions == nil {
		p.initLocked()
	}
	session, exists := p.sessions[handlerPubkey][clientPubkey]
	p.mu.Unlock()

	if exists {
		return session, nil
	}

	session, err := create()
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sessions[handlerPubkey] == nil {
		p.sessions[handlerPubkey] = make(map[nostr.PubKey]*Session)
	}
	p.sessions[handlerPubkey][clientPubkey] = session
	return session, nil
}

// HandleNostrConnectURI works like HandleRequest, but takes a nostrconnect:// URI as input, as scanned/pasted
// by the user, produced by the client. Since DynamicSigner can serve multiple handler keys, the caller must
// specify which handlerPubkey should respond to this connection.
func (p *DynamicSigner) HandleNostrConnectURI(ctx context.Context, handlerPubkey nostr.PubKey, uri *url.URL) (
	resp Response,
	eventResponse nostr.Event,
	err error,
) {
	clientPublicKey, err := nostr.PubKeyFromHex(uri.Host)
	if err != nil {
		return resp, eventResponse, err
	}

	secret := uri.Query().Get("secret")

	_, handlerSecret, err := p.GetHandlerSecretKey(ctx, handlerPubkey)
	if err != nil {
		return resp, eventResponse, fmt.Errorf("no private key for %s: %w", handlerPubkey, err)
	}

	// pretend they started with a request
	conversationKey, err := nip44.GenerateConversationKey(clientPublicKey, handlerSecret)
	if err != nil {
		return resp, eventResponse, err
	}
	reqj, _ := json.Marshal(Request{
		ID:     "nostrconnect-" + strconv.FormatInt(int64(nostr.Now()), 10),
		Method: "imagined-nostrconnect",
		Params: []string{clientPublicKey.Hex(), secret},
	})
	ciphertext, err := nip44.Encrypt(string(reqj), conversationKey)
	if err != nil {
		return resp, eventResponse, err
	}

	_, resp, eventResponse, err = p.HandleRequest(ctx, nostr.Event{
		PubKey:  clientPublicKey,
		Kind:    nostr.KindNostrConnect,
		Content: ciphertext,
		Tags:    nostr.Tags{nostr.Tag{"p", handlerPubkey.Hex()}},
	})
	return resp, eventResponse, err
}

func (p *DynamicSigner) HandleRequest(ctx context.Context, event nostr.Event) (
	req Request,
	resp Response,
	eventResponse nostr.Event,
	err error,
) {
	if event.Kind != nostr.KindNostrConnect {
		return req, resp, eventResponse,
			fmt.Errorf("event kind is %d, but we expected %d", event.Kind, nostr.KindNostrConnect)
	}

	handler := event.Tags.Find("p")
	if handler == nil || len(handler) < 2 || !nostr.IsValid32ByteHex(handler[1]) {
		return req, resp, eventResponse, fmt.Errorf("invalid \"p\" tag")
	}

	handlerPubkey, err := nostr.PubKeyFromHex(handler[1])
	if err != nil {
		return req, resp, eventResponse, fmt.Errorf("%x is invalid pubkey: %w", handler[1], err)
	}

	// serialize only against other requests for this same session -- everything
	// from here on is either a user callback or crypto work, and holding a
	// server-wide lock across it would let one slow session stall every client
	sessionLock := p.lockSession(handlerPubkey, event.PubKey)
	sessionLock.Lock()
	defer sessionLock.Unlock()

	ctx, handlerSecret, err := p.GetHandlerSecretKey(ctx, handlerPubkey)
	if err != nil {
		return req, resp, eventResponse, fmt.Errorf("no private key for %s: %w", handlerPubkey, err)
	}
	ctx, userKeyer, err := p.GetUserKeyer(ctx, handlerPubkey)
	if err != nil {
		return req, resp, eventResponse, fmt.Errorf("failed to get user keyer for %s: %w", handlerPubkey, err)
	}

	session, err := p.sessionFor(handlerPubkey, event.PubKey, func() (*Session, error) {
		// create session if it doesn't exist
		session := &Session{}

		conversationKey, err := nip44.GenerateConversationKey(event.PubKey, handlerSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to compute shared secret: %w", err)
		}
		session.ConversationKey = conversationKey

		publicKey, err := userKeyer.GetPublicKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key: %w", err)
		}
		session.PublicKey = publicKey

		return session, nil
	})
	if err != nil {
		return req, resp, eventResponse, err
	}

	// use this session to handle the request
	req, err = session.ParseRequest(event)
	if err != nil {
		return req, resp, eventResponse, fmt.Errorf("error parsing request: %w", err)
	}

	var result string
	var resultErr error

	switch req.Method {
	case "imagined-nostrconnect":
		// this is a fake request we pretend has existed, but was actually just we reading the nostrconnect:// uri
		if len(req.Params) < 2 || req.Params[1] == "" {
			resultErr = fmt.Errorf("needs a second argument 'secret'")
			break
		}
		if p.OnConnect != nil {
			if err := p.OnConnect(ctx, event.PubKey, req.Params[1]); err != nil {
				resultErr = err
				break
			}
		}
		result = req.Params[1]
	case "connect":
		var secret string
		if len(req.Params) >= 2 {
			secret = req.Params[1]
		}

		if p.OnConnect != nil {
			if err := p.OnConnect(ctx, event.PubKey, secret); err != nil {
				resultErr = err
				break
			}
		}

		result = "ack"
	case "get_public_key":
		result = nostr.HexEncodeToString(session.PublicKey[:])
	case "sign_event":
		if len(req.Params) != 1 {
			resultErr = fmt.Errorf("wrong number of arguments to 'sign_event'")
			break
		}
		evt := nostr.Event{}
		err = easyjson.Unmarshal([]byte(req.Params[0]), &evt)
		if err != nil {
			resultErr = fmt.Errorf("failed to decode event/2: %w", err)
			break
		}
		if p.AuthorizeSigning != nil {
			if err := p.AuthorizeSigning(ctx, evt, event.PubKey); err != nil {
				resultErr = fmt.Errorf("refusing to sign: %s", err)
				break
			}
		}

		err = userKeyer.SignEvent(ctx, &evt)
		if err != nil {
			resultErr = fmt.Errorf("failed to sign event: %w", err)
			break
		}

		jrevt, _ := easyjson.Marshal(evt)
		result = string(jrevt)
	case "nip44_encrypt":
		if len(req.Params) != 2 {
			resultErr = fmt.Errorf("wrong number of arguments to 'nip44_encrypt'")
			break
		}
		thirdPartyPubkey, err := nostr.PubKeyFromHex(req.Params[0])
		if err != nil {
			resultErr = fmt.Errorf("first argument to 'nip44_encrypt' is not a valid pubkey hex")
			break
		}
		if p.AuthorizeEncryption != nil && !p.AuthorizeEncryption(ctx, event.PubKey) {
			resultErr = fmt.Errorf("refusing to encrypt")
			break
		}
		plaintext := req.Params[1]

		ciphertext, err := userKeyer.Encrypt(ctx, plaintext, thirdPartyPubkey)
		if err != nil {
			resultErr = fmt.Errorf("failed to encrypt: %w", err)
			break
		}
		result = ciphertext
	case "nip44_decrypt":
		if len(req.Params) != 2 {
			resultErr = fmt.Errorf("wrong number of arguments to 'nip04_decrypt'")
			break
		}
		thirdPartyPubkey, err := nostr.PubKeyFromHex(req.Params[0])
		if err != nil {
			resultErr = fmt.Errorf("first argument to 'nip04_decrypt' is not a valid pubkey hex")
			break
		}
		if p.AuthorizeEncryption != nil && !p.AuthorizeEncryption(ctx, event.PubKey) {
			resultErr = fmt.Errorf("refusing to decrypt")
			break
		}
		ciphertext := req.Params[1]

		plaintext, err := userKeyer.Decrypt(ctx, ciphertext, thirdPartyPubkey)
		if err != nil {
			resultErr = fmt.Errorf("failed to decrypt: %w", err)
			break
		}
		result = plaintext
	case "nip04_encrypt":
		if len(req.Params) != 2 {
			resultErr = fmt.Errorf("wrong number of arguments to 'nip04_encrypt'")
			break
		}
		thirdPartyPubkey, err := nostr.PubKeyFromHex(req.Params[0])
		if err != nil {
			resultErr = fmt.Errorf("first argument to 'nip04_encrypt' is not a valid pubkey hex")
			break
		}
		if p.AuthorizeEncryption != nil && !p.AuthorizeEncryption(ctx, event.PubKey) {
			resultErr = fmt.Errorf("refusing to encrypt")
			break
		}
		plaintext := req.Params[1]

		ciphertext, err := userKeyer.Nip04Encrypt(ctx, plaintext, thirdPartyPubkey)
		if err != nil {
			resultErr = fmt.Errorf("failed to encrypt: %w", err)
			break
		}
		result = ciphertext
	case "nip04_decrypt":
		if len(req.Params) != 2 {
			resultErr = fmt.Errorf("wrong number of arguments to 'nip04_decrypt'")
			break
		}
		thirdPartyPubkey, err := nostr.PubKeyFromHex(req.Params[0])
		if err != nil {
			resultErr = fmt.Errorf("first argument to 'nip04_decrypt' is not a valid pubkey hex")
			break
		}
		if p.AuthorizeEncryption != nil && !p.AuthorizeEncryption(ctx, event.PubKey) {
			resultErr = fmt.Errorf("refusing to decrypt")
			break
		}
		ciphertext := req.Params[1]

		plaintext, err := userKeyer.Nip04Decrypt(ctx, ciphertext, thirdPartyPubkey)
		if err != nil {
			resultErr = fmt.Errorf("failed to decrypt: %w", err)
			break
		}
		result = plaintext
	case "ping":
		result = "pong"
	case "switch_relays":
		j, _ := json.Marshal(p.DefaultRelays)
		result = string(j)
	default:
		return req, resp, eventResponse,
			fmt.Errorf("unknown method '%s'", req.Method)
	}

	resp, eventResponse, err = session.MakeResponse(req.ID, event.PubKey, result, resultErr)
	if err != nil {
		return req, resp, eventResponse, err
	}

	err = eventResponse.Sign(handlerSecret)
	if err != nil {
		return req, resp, eventResponse, err
	}

	return req, resp, eventResponse, err
}
