package cmw

import (
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

var (
	em, emError = initCBOREncMode()
	dm, dmError = initCBORDecMode()
)

func initCBOREncMode() (en cbor.EncMode, err error) {
	o := cbor.CoreDetEncOptions() // use preset options as a starting point
	return o.EncMode()
}

func initCBORDecMode() (en cbor.DecMode, err error) {
	tags := cbor.NewTagSet()
	tags.Add(
		cbor.TagOptions{EncTag: cbor.EncTagNone, DecTag: cbor.DecTagOptional},
		reflect.TypeOf(CMW{}),
		765)

	return cbor.DecOptions{}.DecModeWithTags(tags)
}

func init() {
	if emError != nil {
		panic(emError)
	}
	if dmError != nil {
		panic(dmError)
	}
}
