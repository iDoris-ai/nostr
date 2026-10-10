package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip02"
	"fiatjaf.com/nostr/nip05"
	"fiatjaf.com/nostr/nip19"
	"fiatjaf.com/nostr/sdk/hints"
)

// ProfileMetadata represents user profile information from kind 0 events.
// It contains both the raw event and parsed metadata fields.
type ProfileMetadata struct {
	PubKey nostr.PubKey `json:"-"` // must always be set otherwise things will break
	Event  *nostr.Event `json:"-"` // may be empty if a profile metadata event wasn't found

	// every one of these may be empty
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	About       string `json:"about,omitempty"`
	Website     string `json:"website,omitempty"`
	Picture     string `json:"picture,omitempty"`
	Banner      string `json:"banner,omitempty"`
	NIP05       string `json:"nip05,omitempty"`
	LUD16       string `json:"lud16,omitempty"`

	nip05Valid       bool
	nip05LastAttempt time.Time
}

// Npub returns the NIP-19 npub encoding of the profile's public key.
func (p ProfileMetadata) Npub() string {
	return nip19.EncodeNpub(p.PubKey)
}

// NpubShort returns a shortened version of the NIP-19 npub encoding,
// showing only the first 7 and last 5 characters.
func (p ProfileMetadata) NpubShort() string {
	npub := p.Npub()
	return npub[0:7] + "…" + npub[58:]
}

// Nprofile returns the NIP-19 nprofile encoding of the profile,
// including relay hints from the user's outbox.
func (p ProfileMetadata) Nprofile(ctx context.Context, sys *System, nrelays int) string {
	return nip19.EncodeNprofile(p.PubKey, sys.FetchOutboxRelays(ctx, p.PubKey, 2))
}

// ShortName returns the best available name for display purposes.
// It tries Name, then DisplayName, and falls back to a shortened npub.
func (p ProfileMetadata) ShortName() string {
	if p.Name != "" {
		return p.Name
	}
	if p.DisplayName != "" {
		return p.DisplayName
	}
	return p.NpubShort()
}

// NIP05Valid checks if the profile's NIP-05 identifier is valid.
func (p *ProfileMetadata) NIP05Valid(ctx context.Context) bool {
	if p.NIP05 == "" {
		return false
	}

	now := time.Now()
	if p.nip05LastAttempt.Before(now.AddDate(0, 0, -7)) {
		// must revalidate
		p.nip05LastAttempt = now
		pp, err := nip05.QueryIdentifier(ctx, p.NIP05)
		if err != nil {
			p.nip05Valid = false
		} else {
			p.nip05Valid = pp.PublicKey == p.PubKey
		}
	}
	return p.nip05Valid
}

// FetchProfileFromInput takes an nprofile, npub, nip05, hex pubkey or a NIP-02 petname path
// like "~erin/david/frank" and returns a ProfileMetadata,
// updating the hintsDB in the process with any eventual relay hints.
// Petname paths are resolved relative to `from` (the caller's own pubkey), except when the
// first segment itself is a nip05/npub/etc reference resolvable via InputToProfile.
// Returns an error if the profile reference couldn't be decoded.
func (sys System) FetchProfileFromInput(ctx context.Context, nip19OrNip05Code string, from ...nostr.PubKey) (ProfileMetadata, error) {
	if strings.HasPrefix(nip19OrNip05Code, "~") {
		var fromPk nostr.PubKey
		if len(from) > 0 {
			fromPk = from[0]
		}
		pk, err := sys.ResolvePetnamePath(ctx, fromPk, nip19OrNip05Code)
		if err != nil {
			return ProfileMetadata{}, err
		}

		pm := sys.FetchProfileMetadata(ctx, pk)
		return pm, nil
	}

	p := InputToProfile(ctx, nip19OrNip05Code)
	if p == nil {
		return ProfileMetadata{}, fmt.Errorf("couldn't decode profile reference")
	}

	for _, r := range p.Relays {
		if !IsVirtualRelay(r) {
			sys.Hints.Save(p.PublicKey, nostr.NormalizeURL(r), hints.LastInHint, nostr.Now())
		}
	}

	pm := sys.FetchProfileMetadata(ctx, p.PublicKey)
	return pm, nil
}

// ResolvePetnamePath resolves NIP-02 petname references like "~erin/david/frank" to a pubkey
// by walking the follow lists of each name in the chain. The first name is either directly
// decodable via InputToProfile (npub, nprofile, hex, nip05 -- e.g. "~erin@names.com/david"),
// a petname relative to `from`'s follow list, or empty to use `from` itself ("~/david").
// See https://github.com/nostr-protocol/nips/blob/master/02.md.
func (sys *System) ResolvePetnamePath(ctx context.Context, from nostr.PubKey, value string) (nostr.PubKey, error) {
	parts, err := nip02.ParsePetnamePath(value)
	if err != nil {
		return nostr.ZeroPK, err
	}

	// resolve the root: a directly decodable reference wins, otherwise a petname of `from`.
	var pk nostr.PubKey
	if parts[0] == "" {
		if from == nostr.ZeroPK {
			return nostr.ZeroPK, fmt.Errorf("can't resolve current user without an identity")
		}
		pk = from
	} else if pp := InputToProfile(ctx, parts[0]); pp != nil {
		pk = pp.PublicKey
	} else {
		if !nip02.IsValidPetname(parts[0]) {
			return nostr.ZeroPK, fmt.Errorf("invalid petname \"%s\"", parts[0])
		}
		if from == nostr.ZeroPK {
			return nostr.ZeroPK, fmt.Errorf("can't resolve relative petname \"%s\" without an identity", parts[0])
		}

		fl := sys.FetchFollowList(ctx, from)
		if fl.Event == nil {
			return nostr.ZeroPK, fmt.Errorf("failed to resolve \"%s\": couldn't get your own follow list (needed to resolve \"%s\")", value, parts[0])
		}
		next, ok := findPetnameInFollowList(fl, parts[0])
		if !ok {
			return nostr.ZeroPK, fmt.Errorf("failed to resolve \"%s\": no one in your follow list is named \"%s\"", value, parts[0])
		}
		pk = next
	}

	// walk the rest of the chain.
	for _, petname := range parts[1:] {
		fl := sys.FetchFollowList(ctx, pk)
		if fl.Event == nil {
			return nostr.ZeroPK, fmt.Errorf("failed to resolve \"%s\": couldn't get follow list of %s", value, pk.Hex())
		}
		next, ok := findPetnameInFollowList(fl, petname)
		if !ok {
			return nostr.ZeroPK, fmt.Errorf("failed to resolve \"%s\": %s doesn't follow anyone named \"%s\"", value, pk.Hex(), petname)
		}
		pk = next
	}

	return pk, nil
}

func findPetnameInFollowList(fl GenericList[nostr.PubKey, ProfileRef], petname string) (nostr.PubKey, bool) {
	for _, item := range fl.Items {
		if item.Petname == petname {
			return item.Pubkey, true
		}
	}
	return nostr.ZeroPK, false
}

// FetchProfileMetadata fetches metadata for a given user from the local cache, or from the local store,
// or, failing these, from the target user's defined outbox relays -- then caches the result.
// It always returns a ProfileMetadata, even if no metadata was found (in which case only the PubKey field is set).
func (sys *System) FetchProfileMetadata(ctx context.Context, pubkey nostr.PubKey) (pm ProfileMetadata) {
	if v, ok := sys.MetadataCache.Get(pubkey); ok {
		return v
	}

	pm.PubKey = pubkey

	for evt := range sys.Store.QueryEvents(nostr.Filter{Kinds: []nostr.Kind{0}, Authors: []nostr.PubKey{pubkey}}, 1) {
		// ok, we found something locally
		pm, _ = ParseMetadata(evt)
		pm.PubKey = pubkey
		pm.Event = &evt

		// but if we haven't tried fetching from the network recently we should do it
		lastFetchKey := makeLastFetchKey(0, pubkey)
		lastFetchData, _ := sys.KVStore.Get(lastFetchKey)
		if lastFetchData == nil || nostr.Now()-decodeTimestamp(lastFetchData) > 7*24*60*60 {
			newM := sys.tryFetchMetadataFromNetwork(ctx, pubkey)
			if newM != nil && newM.Event.CreatedAt > pm.Event.CreatedAt {
				pm = *newM

				sys.Store.ReplaceEvent(*pm.Event)
			}

			// even if we didn't find anything register this because we tried
			// (and we still have the previous event in our local store)
			sys.KVStore.Set(lastFetchKey, encodeTimestamp(nostr.Now()))
		}

		// and finally save this to cache
		sys.MetadataCache.SetWithTTL(pubkey, pm, time.Hour*6)

		return pm
	}

	if newM := sys.tryFetchMetadataFromNetwork(ctx, pubkey); newM != nil {
		pm = *newM

		sys.Store.ReplaceEvent(*pm.Event)

		// we'll only save this if we got something which means we found at least one event
		lastFetchKey := makeLastFetchKey(0, pubkey)
		sys.KVStore.Set(lastFetchKey, encodeTimestamp(nostr.Now()))
	}

	// save cache even if we didn't get anything
	sys.MetadataCache.SetWithTTL(pubkey, pm, time.Hour*6)

	return pm
}

func (sys *System) tryFetchMetadataFromNetwork(ctx context.Context, pubkey nostr.PubKey) *ProfileMetadata {
	evt, err := sys.replaceableLoaders[kind_0].Load(ctx, pubkey)
	if err != nil {
		return nil
	}

	pm, err := ParseMetadata(evt)
	if err != nil {
		return nil
	}

	pm.PubKey = pubkey
	pm.Event = &evt
	sys.Publisher.Publish(ctx, evt)
	sys.MetadataCache.SetWithTTL(pubkey, pm, time.Hour*6)
	return &pm
}

// ParseMetadata parses a kind 0 event into a ProfileMetadata struct.
// Returns an error if the event is not kind 0 or if the content is not valid JSON.
func ParseMetadata(event nostr.Event) (meta ProfileMetadata, err error) {
	if event.Kind != 0 {
		err = fmt.Errorf("event %s is kind %d, not 0", event.ID, event.Kind)
	} else if er := json.Unmarshal([]byte(event.Content), &meta); er != nil {
		cont := event.Content
		if len(cont) > 100 {
			cont = cont[0:99]
		}
		err = fmt.Errorf("failed to parse metadata (%s) from event %s: %w", cont, event.ID, er)
	}

	meta.PubKey = event.PubKey
	meta.Event = &event
	return meta, err
}
