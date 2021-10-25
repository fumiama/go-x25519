// Package x25519 implements Elliptic Curve Diffie-Hellman (ECDH) function over Curve25519.
// Details at https://cr.yp.to/ecdh.html and https://tools.ietf.org/html/rfc7748
package x25519

import (
	"crypto/rand"
	"io"
	"sync"
	"unsafe"

	"golang.org/x/crypto/curve25519"
)

// KEYSZ is the size of keys in bytes used in this package.
const KEYSZ = 32

// PublicKey is the type of Curve25519 public keys.
type PublicKey = [KEYSZ]byte

// PrivateKey is the type of Curve25519 secret keys.
type PrivateKey = [KEYSZ]byte

// Curve is the type of Curve25519 secret keys.
type Curve struct {
	sk      PrivateKey
	pk      PublicKey
	ispkset bool
	pkmu    sync.Mutex
}

// Private returns the secret key as a byte array pointer.
func (k *Curve) Private() *PrivateKey { return &k.sk }

// Public returns the PublicKey corresponding to the secret key.
func (k *Curve) Public() *PublicKey {
	if !k.ispkset {
		sk := k.sk
		var pk PublicKey
		curve25519.ScalarBaseMult(&pk, &sk)
		k.pkmu.Lock()
		if !k.ispkset {
			k.pk = pk
		}
		k.pkmu.Unlock()
		k.ispkset = true
	}
	return &k.pk
}

// Shared computes the shared secret between our secret key and peer's public key.
func (k *Curve) Shared(peer *PublicKey) ([]byte, error) {
	return curve25519.X25519(k.sk[:], (*peer)[:])
}

// Get creates a PrivateKey from []byte sk and len(sk) must be 32.
func Get(sk []byte) *Curve {
	if len(sk) == KEYSZ {
		k := new(Curve)
		k.sk = *(*PrivateKey)(*(*unsafe.Pointer)(unsafe.Pointer(&sk)))
		return k
	}
	return nil
}

// New generates a secret key using entropy from random, or crypto/rand.Reader
// if random is nil.
func New(random io.Reader) (k *Curve, err error) {
	if random == nil {
		random = rand.Reader
	}
	k = new(Curve)
	_, err = random.Read(k.sk[:])
	return
}
