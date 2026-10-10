package nip02

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePetnamePath(t *testing.T) {
	parts, err := ParsePetnamePath("~erin/david/frank")
	require.NoError(t, err)
	require.Equal(t, []string{"erin", "david", "frank"}, parts)

	parts, err = ParsePetnamePath("~erin")
	require.NoError(t, err)
	require.Equal(t, []string{"erin"}, parts)

	parts, err = ParsePetnamePath("~/david")
	require.NoError(t, err)
	require.Equal(t, []string{"", "david"}, parts)

	_, err = ParsePetnamePath("~")
	require.Error(t, err)

	_, err = ParsePetnamePath("~erin//frank")
	require.Error(t, err)

	_, err = ParsePetnamePath("~erin/")
	require.Error(t, err)

	_, err = ParsePetnamePath("~/")
	require.Error(t, err)

	_, err = ParsePetnamePath("erin")
	require.Error(t, err)
}

func TestIsValidPetname(t *testing.T) {
	require.True(t, IsValidPetname("erin"))
	require.True(t, IsValidPetname("erin@names.com"))
	require.False(t, IsValidPetname("er\tin"))
	require.False(t, IsValidPetname("er in"))
	require.False(t, IsValidPetname(string(make([]byte, 65))))
}
