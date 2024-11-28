package cmw

import (
	"errors"
	"fmt"
)

// CMW holds the internal representation of a RATS conceptual message wrapper
type CMW struct {
	kind Kind

	monad      // Record CMW or CBOR-encoded Tag CMW
	collection // Collection CMW
}

type Kind uint

const (
	KindUnknown = Kind(iota)
	KindMonad
	KindCollection
)

func (o Kind) String() string {
	switch o {
	case KindCollection:
		return "collection"
	case KindMonad:
		return "monad"
	case KindUnknown:
		fallthrough
	default:
		return "unknown"
	}
}

func (o CMW) GetKind() Kind { return o.kind }
func (o CMW) GetFormat() Format {
	switch o.kind {
	case KindMonad:
		return o.monad.format
	case KindCollection:
		return o.collection.format
	default:
		return FormatUnknown
	}
}

type Format uint

const (
	FormatUnknown = Format(iota)
	// JSON formats
	FormatJSONRecord
	FormatJSONCollection
	// CBOR formats
	FormatCBORRecord
	FormatCBORCollection
	FormatCBORTag
)

func (o Format) String() string {
	switch o {
	case FormatJSONRecord:
		return "JSON record"
	case FormatJSONCollection:
		return "JSON collection"
	case FormatCBORRecord:
		return "CBOR record"
	case FormatCBORCollection:
		return "CBOR collection"
	case FormatCBORTag:
		return "CBOR tag"
	case FormatUnknown:
		fallthrough
	default:
		return "unknown"
	}
}

func NewMonad(mediaType any, value []byte, indicators ...Indicator) (*CMW, error) {
	var c CMW
	if err := c.val.Set(value); err != nil {
		return nil, err
	}
	if err := c.typ.Set(mediaType); err != nil {
		return nil, err
	}
	c.setIndicators(indicators...)
	c.kind = KindMonad
	return &c, nil
}

func (o CMW) GetMonadType() (string, error) {
	if o.kind != KindMonad {
		return "", fmt.Errorf("want monad, got %q", o.kind)
	}
	return o.monad.getType(), nil
}

func (o CMW) GetMonadValue() ([]byte, error) {
	if o.kind != KindMonad {
		return nil, fmt.Errorf("want monad, got %q", o.kind)
	}
	return o.monad.getValue(), nil
}

func (o CMW) GetMonadIndicator() (Indicator, error) {
	if o.kind != KindMonad {
		return IndicatorNone, fmt.Errorf("want monad, got %q", o.kind)
	}
	return o.monad.getIndicator(), nil
}

func (o *CMW) UseCBORTagFormat() { o.monad.format = FormatCBORTag }

// NewCollection instantiate a new Collection CMW with the supplied __cmwc_t
// Pass an empty string to avoid setting __cmwc_t
func NewCollection(cmwct string) (*CMW, error) {
	if cmwct != "" {
		if err := validateCollectionType(cmwct); err != nil {
			return nil, err
		}
	}
	var c CMW
	c.cmap = make(map[any]CMW)
	c.ctyp = cmwct
	c.kind = KindCollection
	return &c, nil
}

// GetCollectionType returns the Collection CMW's __cmwc_t
// If __cmwc_t is not set, an empty string is returned
func (o CMW) GetCollectionType() (string, error) {
	if o.kind != KindCollection {
		return "", fmt.Errorf("want collection, got %q", o.kind)
	}
	return o.collection.getType(), nil
}

func (o *CMW) AddCollectionItem(key any, node *CMW) error {
	if o.kind != KindCollection {
		return fmt.Errorf("want collection, got %q", o.kind)
	}
	err := o.collection.addItem(key, node)
	return err
}

func (o CMW) GetCollectionItem(key any) (*CMW, error) {
	if o.kind != KindCollection {
		return nil, fmt.Errorf("want collection, got %q", o.kind)
	}
	return o.collection.getItem(key)
}

func (o CMW) ValidateCollection() error {
	if o.kind != KindCollection {
		return fmt.Errorf("want collection, got %q", o.kind)
	}
	return o.collection.validate()
}

type Meta struct {
	Key  any
	Kind Kind
}

// GetCollectionMeta retrieves a (sorted) list of keys and associated types in a
// collection
func (o *CMW) GetCollectionMeta() ([]Meta, error) {
	if o.kind != KindCollection {
		return nil, fmt.Errorf("want collection, got %q", o.kind)
	}
	return o.collection.getMeta(), nil
}

func (o *CMW) setIndicators(indicators ...Indicator) {
	var v Indicator

	for _, ind := range indicators {
		v.Set(ind)
	}

	o.ind = v
}

func (o CMW) MarshalJSON() ([]byte, error) {
	switch o.kind {
	case KindMonad:
		return o.monad.MarshalJSON()
	case KindCollection:
		return o.collection.MarshalJSON()
	default:
		return nil, errors.New("unknown CMW kind")
	}
}

func (o CMW) MarshalCBOR() ([]byte, error) {
	switch o.kind {
	case KindMonad:
		return o.monad.MarshalCBOR()
	case KindCollection:
		return o.collection.MarshalCBOR()
	default:
		return nil, errors.New("unknown CMW kind")
	}
}

func (o *CMW) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return errors.New("empty buffer")
	}

	start := b[0]

	switch start {
	case '[':
		if err := o.monad.UnmarshalJSON(b); err != nil {
			return err
		}
		o.kind = KindMonad
	case '{':
		if err := o.collection.UnmarshalJSON(b); err != nil {
			return err
		}
		o.kind = KindCollection
	default:
		return fmt.Errorf("want JSON object or JSON array start symbols, got: 0x%02x", start)
	}

	return nil
}

func (o *CMW) UnmarshalCBOR(b []byte) error {
	if len(b) == 0 {
		return errors.New("empty buffer")
	}

	start := b[0]

	switch {
	case startCBORRecord(start) || startCBORTag(start):
		if err := o.monad.UnmarshalCBOR(b); err != nil {
			return err
		}
		o.kind = KindMonad
	case startCBORCollection(start):
		if err := o.collection.UnmarshalCBOR(b); err != nil {
			return err
		}
		o.kind = KindCollection
	default:
		return fmt.Errorf("want CBOR map, CBOR array or CBOR Tag start symbols, got: 0x%02x", start)
	}

	return nil
}

func (o *CMW) Deserialize(b []byte) error {
	if len(b) == 0 {
		return errors.New("empty buffer")
	}
	s := b[0]
	if startCBORCollection(s) || startCBORRecord(s) || startCBORTag(s) {
		return o.UnmarshalCBOR(b)
	} else if startJSONRecord(s) || startJSONCollection(s) {
		return o.UnmarshalJSON(b)
	} else {
		return fmt.Errorf("unknown start symbol for CMW: %c", b)
	}
}

func Sniff(b []byte) Format {
	if len(b) == 0 {
		return FormatUnknown
	}

	start := b[0]

	if startCBORCollection(start) {
		return FormatCBORCollection
	} else if startCBORRecord(start) {
		return FormatCBORRecord
	} else if startCBORTag(start) {
		return FormatCBORTag
	} else if startJSONCollection(start) {
		return FormatJSONCollection
	} else if startJSONRecord(start) {
		return FormatJSONRecord
	}

	return FormatUnknown
}
