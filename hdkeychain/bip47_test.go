// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hdkeychain_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
)

const (
	Alice       = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA"
	Bob         = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97"
	AliceNotify = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW"
	BobNotify   = "1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV"
)

func TestSerialization(t *testing.T) {
	a, err := hdkeychain.ReadPaymentCode(Alice)
	if err != nil {
		t.Fatalf("Could not decode payment code: %s", err)
	}

	b, err := hdkeychain.ReadPaymentCode(Bob)
	if err != nil {
		t.Fatalf("Could not decode payment code: %s", err)
	}

	if a.String() != Alice {
		t.Errorf("Could not serialize payment code. Expected %s, got %s.", Alice, a.String())
	}

	if b.String() != Bob {
		t.Errorf("Could not serialize payment code. Expected %s, got %s.", Bob, b.String())
	}
}

func TestNotificationAddr(t *testing.T) {
	a, err := hdkeychain.ReadPaymentCode(Alice)
	if err != nil {
		t.Fatalf("Could not decode payment code: %s", err)
	}

	b, err := hdkeychain.ReadPaymentCode(Bob)
	if err != nil {
		t.Fatalf("Could not decode payment code: %s", err)
	}

	an, err := a.NotificationAddress(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("Could not derive address: %s", err)
	}

	bn, err := b.NotificationAddress(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("Could not derive address: %s", err)
	}

	if an.String() != AliceNotify {
		t.Errorf("Wrong address; expected %s, got %s", AliceNotify, an.String())
	}

	if bn.String() != BobNotify {
		t.Errorf("Wrong address; expected %s, got %s", BobNotify, bn.String())
	}
}

func TestNotificationTx(t *testing.T) {
	// The address we're going to send from.
	fromPk, _ := btcutil.DecodeWIF("Kx983SRhAZpAhj7Aac1wUXMJ6XZeyJKqCxJJ49dxEbYCT4a1ozRD")

	// Alice's and Bob's payment codes.
	a, _ := hdkeychain.ReadPaymentCode(Alice)
	b, _ := hdkeychain.ReadPaymentCode(Bob)

	outPoint, _ := hex.DecodeString("86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c01000000")

	expected, _ := hex.DecodeString("010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b00000000000000000000000000")

	code, err := hdkeychain.NotificationCode(a, b, fromPk.PrivKey, outPoint, &chaincfg.MainNetParams)
	if err != nil {
		t.Error("Notification Code returned error ", err)
	}

	if !bytes.Equal(code, expected) {
		t.Error("Expected ",
			hex.EncodeToString(expected), " got ", hex.EncodeToString(code))
	}
}
