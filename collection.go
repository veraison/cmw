// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmw

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

const CmwCType string = "__cmwc_t"

type collection struct {
	cmap map[any]CMW
	ctyp string

	format Format
}

func (o collection) validate() error {
	if len(o.cmap) < 1 {
		return errors.New("empty CMW collection")
	}

	for k, v := range o.cmap {
		if err := v.validate(); err != nil {
			return fmt.Errorf("invalid collection at key %q: %w", k, err)
		}
	}

	return nil
}

func validateCollectionKey(key any) error {
	switch t := key.(type) {
	case string:
		// make sure it's not reserved and it's not empty/whitespace-only
		if t == CmwCType {
			return fmt.Errorf("bad collection key: %s is reserved", CmwCType)
		}
		if len(strings.TrimSpace(t)) == 0 {
			return errors.New("bad collection key: empty or whitespace only")
		}
		return nil
	case int64, uint64:
		return nil
	default:
		return fmt.Errorf("unknown collection key type: want string or int, got %T", t)
	}
}

var oidRe = regexp.MustCompile(`^([0-2])(([.]0)|([.][1-9][0-9]*))*$`)

func validateCollectionType(ctyp string) error {
	// "__cmwc_t": ~uri / oid

	if oidRe.MatchString(ctyp) {
		return nil
	}

	u, uriErr := url.Parse(ctyp)
	if uriErr != nil {
		return fmt.Errorf("invalid collection type: %q.  MUST be URI or OID", ctyp)
	}

	if !u.IsAbs() {
		return fmt.Errorf("invalid collection type: %q.  URI is not absolute", ctyp)
	}

	return nil
}

func (o *collection) addItem(key any, node *CMW) error {
	if err := validateCollectionKey(key); err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}

	if node == nil {
		return errors.New("nil node")
	}

	o.cmap[key] = *node

	return nil
}

// GetItem returns the CMW associated with label k
func (o collection) getItem(k any) (*CMW, error) {
	v, found := o.cmap[k]
	if !found {
		return nil, fmt.Errorf("item not found for key %q", k)
	}
	return &v, nil
}

func (o collection) getType() string {
	return o.ctyp
}

func (o Meta) getKeyForSorting() string {
	switch t := o.Key.(type) {
	case string:
		return t
	case uint64:
		return fmt.Sprintf("##%d", t)
	default:
		panic(fmt.Sprintf("key with unknown type %T", t))
	}
}

func (o collection) getMeta() []Meta {
	var m []Meta

	for k, v := range o.cmap {
		m = append(m, Meta{k, v.kind})
	}

	sort.Slice(m, func(i, j int) bool {
		return m[i].getKeyForSorting() < m[j].getKeyForSorting()
	})

	return m
}

// MarshalJSON serializes the collection to JSON
func (o collection) MarshalJSON() ([]byte, error) {
	m := make(map[string]json.RawMessage)

	if o.ctyp != "" {
		ct, _ := json.Marshal(o.ctyp)
		m[CmwCType] = json.RawMessage(ct)
	}

	for i, v := range o.cmap {
		c, err := v.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("marshaling JSON collection item %v: %w", i, err)
		}
		switch t := i.(type) {
		case string:
			m[t] = c
		default:
			return nil, fmt.Errorf("JSON collection, key error: want string, got %T", t)
		}
	}

	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshaling JSON collection: %w", err)
	}

	return b, nil
}

// MarshalCBOR serializes the collection to CBOR
func (o collection) MarshalCBOR() ([]byte, error) {
	m := make(map[any]cbor.RawMessage)

	if o.ctyp != "" {
		ct, _ := em.Marshal(o.ctyp)
		m[CmwCType] = cbor.RawMessage(ct)
	}

	for i, v := range o.cmap {
		c, err := v.MarshalCBOR()
		if err != nil {
			return nil, fmt.Errorf("marshaling CBOR collection item %v: %w", i, err)
		}
		m[i] = c
	}

	b, err := em.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshaling CBOR collection: %w", err)
	}

	return b, nil
}

// UnmarshalCBOR unmarshal the supplied CBOR buffer to a CMW collection
func (o *collection) UnmarshalCBOR(b []byte) error {
	var tmp map[any]cbor.RawMessage

	if err := dm.Unmarshal(b, &tmp); err != nil {
		return fmt.Errorf("unmarshaling CBOR collection: %w", err)
	}

	// extract CMW collection type
	cmwcT, found := tmp[CmwCType]
	if found {
		var s string
		if err := dm.Unmarshal(cmwcT, &s); err != nil {
			return fmt.Errorf("extracting CBOR collection type: %w", err)
		}
		if err := validateCollectionType(s); err != nil {
			return fmt.Errorf("checking CBOR collection type: %w", err)
		}
		o.ctyp = s
		delete(tmp, CmwCType)
	}

	m := make(map[any]CMW)

	for k, v := range tmp {
		var c CMW

		start := v[0]

		switch {
		case startCBORRecord(start) || startCBORTag(start):
			if err := c.monad.UnmarshalCBOR(v); err != nil {
				return fmt.Errorf("unmarshaling CBOR record or tag item %v: %w", k, err)
			}
			c.kind = KindMonad
		case startCBORCollection(start):
			if err := c.collection.UnmarshalCBOR(v); err != nil {
				return fmt.Errorf("unmarshaling CBOR collection item %v: %w", k, err)
			}
			c.kind = KindCollection
		default:
			return fmt.Errorf("want CBOR map, CBOR array or CBOR Tag start symbols, got: 0x%02x", start)
		}

		m[k] = c
	}

	o.cmap = m
	o.format = FormatCBORCollection

	return nil
}

// UnmarshalJSON unmarshals the supplied JSON buffer to a CMW collection
func (o *collection) UnmarshalJSON(b []byte) error {
	var tmp map[string]json.RawMessage

	if err := json.Unmarshal(b, &tmp); err != nil {
		return fmt.Errorf("unmarshaling JSON collection: %w", err)
	}

	// extract CMW collection type
	cmwcT, found := tmp[CmwCType]
	if found {
		var s string
		if err := json.Unmarshal(cmwcT, &s); err != nil {
			return fmt.Errorf("extracting JSON collection type: %w", err)
		}
		if err := validateCollectionType(s); err != nil {
			return fmt.Errorf("checking JSON collection type: %w", err)
		}
		o.ctyp = s
		delete(tmp, CmwCType)
	}

	m := make(map[any]CMW)

	for k, v := range tmp {
		var c CMW

		start := v[0]

		switch {
		case startJSONRecord(start):
			if err := c.monad.UnmarshalJSON(v); err != nil {
				return fmt.Errorf("unmarshaling JSON record item %v: %w", k, err)
			}
			c.kind = KindMonad
		case startJSONCollection(start):
			if err := c.collection.UnmarshalJSON(v); err != nil {
				return fmt.Errorf("unmarshaling JSON collection item %v: %w", k, err)
			}
			c.kind = KindCollection
		default:
			return fmt.Errorf("want JSON object or JSON array start symbols, got: 0x%02x", start)
		}

		m[k] = c
	}

	o.cmap = m
	o.format = FormatJSONCollection

	return nil
}
