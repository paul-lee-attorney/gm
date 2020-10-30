package sm2

import (
	"crypto/rand"
	"testing"
)

const (
	KeyBits = 128
)

var (
	initiatorId = []byte("ABCDEFG1234")
	responderId = []byte("1234567ABCD")
)

func TestSM2KeyExchange(t *testing.T) {
	initiatorStaticPriv, _ := GenerateKey(rand.Reader)
	initiatorEphemeralPriv, _ := GenerateKey(rand.Reader)
	responderStaticPriv, _ := GenerateKey(rand.Reader)
	responderEphemeralPriv, _ := GenerateKey(rand.Reader)

	responderResult, err := CalculateKeyWithConfirmation(false, KeyBits, nil,
		responderStaticPriv, responderEphemeralPriv, responderId,
		initiatorId)
	if err != nil {
		t.Error(err.Error())
		return
	}

	initiatorResult, err := CalculateKeyWithConfirmation(true, KeyBits, responderResult.S1,
		initiatorStaticPriv, initiatorEphemeralPriv, initiatorId,
		responderId)
	if err != nil {
		t.Error(err.Error())
		return
	}

	if !ResponderConfirm(responderResult.S2, initiatorResult.S2) {
		t.Error("responder confirm s2 failed")
		return
	}
}
