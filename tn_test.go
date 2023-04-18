package cmw

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_TN_RoundTrip(t *testing.T) {
	for cf := uint16(CfMin); cf < CfMax; cf++ {
		actual, err := CF(TN(cf))
		assert.NoError(t, err)
		assert.Equal(t, cf, actual)
	}
}

func Test_TN_OutOfRange(t *testing.T) {
	assert.Equal(t, TN(65535), uint64(18446744073709551615))
}

func Test_CF_OutOfRange(t *testing.T) {
	_, err := CF(TnMin - 1)
	assert.EqualError(t, err, "TN 1668546816 out of range")

	for tn := TnMin; tn <= TnMax; tn++ {
		_, err = CF(tn)
		assert.NoError(t, err)
	}

	_, err = CF(TnMax + 1)
	assert.EqualError(t, err, "TN 1668612096 out of range")
}
