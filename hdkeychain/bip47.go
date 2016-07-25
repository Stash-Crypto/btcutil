// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hdkeychain

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
)

// A bip47 payment code.
type PaymentCode struct {
	version   byte
	features  byte
	sign      byte     // The sign of the y-value of the ec point.
	x         [32]byte // The x value of the ec point.
	chainCode [32]byte // The chain code for the extended public key.
	data      [13]byte // additional data (unused).
}

// Decode a payment code string into bytes.
func ReadPaymentCode(code string) (*PaymentCode, error) {
	bytes, version, err := base58.CheckDecode(code)
	if err != nil {
		return nil, err
	}
	if version != 0x47 {
		return nil, errors.New("Wrong version byte. It should be 0x47, or 'P'")
	}
	if len(bytes) != 80 {
		return nil, errors.New("Invalid length. Should be 80.")
	}

	pc := PaymentCode{
		version:  bytes[0],
		features: bytes[1],
		sign:     bytes[2],
	}

	copy(pc.x[:], bytes[3:35])
	copy(pc.chainCode[:], bytes[35:67])
	copy(pc.data[:], bytes[67:80])

	return &pc, nil
}

// Decode into a byte array.
func (pc *PaymentCode) Bytes() []byte {
	encoded := make([]byte, 80)
	encoded[0] = pc.version
	encoded[1] = pc.features
	encoded[2] = pc.sign
	copy(encoded[3:35], pc.x[:])
	copy(encoded[35:67], pc.chainCode[:])
	copy(encoded[67:80], pc.data[:])
	return encoded
}

// Decode into a string.
func (pc *PaymentCode) String() string {
	return base58.CheckEncode(pc.Bytes(), 0x47)
}

func (pc *PaymentCode) getKey() []byte {
	return append(append(make([]byte, 0, 33), pc.sign), pc.x[:]...)
}

// Derive the pubkey corresponding to a notification address.
func (pc *PaymentCode) NotificationPubkey() (*ExtendedKey, error) {

	return (&ExtendedKey{
		key:       pc.getKey(),
		chainCode: pc.chainCode[:],
		isPrivate: false,
	}).Child(0)
}

// Derive a bip47 payment code notification address.
func (pc *PaymentCode) NotificationAddress(params *chaincfg.Params) (btcutil.Address, error) {

	ex0, err := pc.NotificationPubkey()

	if err != nil {
		return nil, err
	}

	return ex0.Address(params)
}

// Returns the notification code to be put in the op_return output of a
// notifiction transaction.
func NotificationCode(from, to *PaymentCode, pk *btcec.PrivateKey,
	outPoint []byte, params *chaincfg.Params) ([]byte, error) {

	// Get the pubkey associated with the notification address.
	pubExtended, err := to.NotificationPubkey()
	if err != nil {
		return nil, err
	}

	pub, err := pubExtended.ECPubKey()
	if err != nil {
		return nil, err
	}

	h := hmac.New(sha512.New, outPoint)

	_, err = h.Write(btcec.GenerateSharedSecret(pk, pub))
	if err != nil {
		return nil, err
	}

	blind := h.Sum(nil)

	nc := from.Bytes()

	for i := 0; i < 64; i++ {
		nc[i+3] ^= blind[i]
	}

	return nc, nil
}
