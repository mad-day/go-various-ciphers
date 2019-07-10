/*
Copyright 2013 The Go Authors. All rights reserved.
Use of this source code is governed by a BSD-style
license that can be found in the LICENSE file.

-----

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


package eax

import (
	"errors"
	"crypto/cipher"
	"crypto/subtle"
	"hash"
	"github.com/mad-day/go-various-ciphers/crypto/cmac"
)

var (
	ETagTooSmall = errors.New("tagsize < 1")
	ETagTooBig = errors.New("tagsize > blocksize")
)

// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}


type eaxMode struct {
	ciph cipher.Block
	mac hash.Hash
	tag int
}

func (e *eaxMode) NonceSize() int { return e.ciph.BlockSize() }

func (e *eaxMode) Overhead() int { return e.tag }

func (e *eaxMode) crypt(dst, src, ctr []byte) {
	cipher.NewCTR(e.ciph,ctr).XORKeyStream(dst,src)
}

func (e *eaxMode) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	tag := make([]byte,e.mac.BlockSize())
	
	tag[len(tag)-1] = 0 // nonce tag
	e.mac.Reset()
	e.mac.Write(tag)
	e.mac.Write(nonce)
	auth1 := e.mac.Sum(nil)
	
	tag[len(tag)-1] = 1 // additional data tag
	e.mac.Reset()
	e.mac.Write(tag)
	e.mac.Write(additionalData)
	auth2 := e.mac.Sum(nil)
	
	ret,out := sliceForAppend(dst,len(plaintext)+e.tag)
	e.crypt(out[:len(plaintext)],plaintext,auth1)
	
	tag[len(tag)-1] = 2 // ciphertext data tag
	e.mac.Reset()
	e.mac.Write(tag)
	e.mac.Write(out[:len(plaintext)])
	tag = e.mac.Sum(tag[:0])
	
	for i := range tag {
		tag[i] ^= auth1[i] ^ auth2[i]
	}
	copy(out[len(plaintext):],tag)
	
	return ret
}

// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
var errOpen = errors.New("cipher: message authentication failed")

func (e *eaxMode) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	tag := make([]byte,e.mac.BlockSize())
	
	ctl := len(ciphertext)-e.tag
	
	tag[len(tag)-1] = 0 // nonce tag
	e.mac.Reset()
	e.mac.Write(tag)
	e.mac.Write(nonce)
	auth1 := e.mac.Sum(nil)
	
	tag[len(tag)-1] = 1 // additional data tag
	e.mac.Reset()
	e.mac.Write(tag)
	e.mac.Write(additionalData)
	auth2 := e.mac.Sum(nil)
	
	tag[len(tag)-1] = 2 // ciphertext data tag
	e.mac.Reset()
	e.mac.Write(tag)
	e.mac.Write(ciphertext[:ctl])
	tag = e.mac.Sum(tag[:0])
	
	for i := range tag {
		tag[i] ^= auth1[i] ^ auth2[i]
	}
	if subtle.ConstantTimeCompare(tag[:e.tag], ciphertext[ctl:]) != 1 {
		return nil,errOpen
	}
	
	ret,out := sliceForAppend(dst,ctl)
	e.crypt(out,ciphertext[:ctl],auth1)
	
	return ret,nil
}

func New(c cipher.Block,tagsize int) (cipher.AEAD,error) {
	if tagsize<1 { return nil,ETagTooSmall }
	if tagsize>c.BlockSize() { return nil,ETagTooBig }
	h,err := cmac.New(c)
	if err!=nil { return nil,err }
	return &eaxMode{c,h,tagsize},nil
}


