/*
Copyright (c) 2019 Simon Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


/*
A variant of the Lioness Cipher with Poly1305 as Hash function and the Salsa20
core as Stream cipher.
*/
package salsapoly

import (
	"crypto/cipher"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20/salsa"
)

// Key-Schedule
type KeySchedule [4][32]byte

func xor(a,b *[16]byte) {
	for i,w := range b[:] { a[i] ^= w }
}

func (k *KeySchedule) MinimumBlockSize() int { return 17 }

func (k *KeySchedule) Encrypt(dst, src []byte) {
	if len(src)!=len(dst) { panic("size mismatch") }
	L,R := new([16]byte),dst[16:]
	T := new([16]byte)
	
	copy(L[:],src[:16])
	salsa.XORKeyStream(R, src[16:],L,&(k[0]))
	
	poly1305.Sum(T,R,&(k[1])); xor(L,T)
	
	salsa.XORKeyStream(R, R,L,&(k[2]))
	
	poly1305.Sum(T,R,&(k[3])); xor(L,T)
	copy(dst[:16],L[:])
}
func (k *KeySchedule) Decrypt(dst, src []byte) {
	if len(src)!=len(dst) { panic("size mismatch") }
	L,R := new([16]byte),dst[16:]
	T := new([16]byte)
	
	copy(L[:],src[:16])
	poly1305.Sum(T,src[16:],&(k[3])); xor(L,T)
	
	salsa.XORKeyStream(R, src[16:],L,&(k[2]))
	
	poly1305.Sum(T,R,&(k[1])); xor(L,T)
	
	salsa.XORKeyStream(R,R,L,&(k[0]))
	copy(dst[:16],L[:])
}

type Block struct {
	*KeySchedule
	Size int
}
func (b *Block) BlockSize() int { return b.Size }
var _ cipher.Block = (*Block)(nil)

// ###
