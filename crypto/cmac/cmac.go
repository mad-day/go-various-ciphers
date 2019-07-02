/*
Copyright (c) 2000-2017 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
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


package cmac

import (
	"errors"
	"crypto/cipher"
	"crypto/subtle"
	
	"hash"
	"fmt"
)

func debug(i ...interface{}) {
	fmt.Println(i...)
}

var EInvalidBlockSize = errors.New("unsupported blocksize")

func lsh(dst, src []byte) int {
	r := int(src[0]>>7)
	med := src[0]<<1
	for i,w := range src[1:] {
		dst[i] = med|(w>>7)
		med = w<<1
	}
	dst[len(dst)-1] = med
	return r
}
func clearbuf(buf []byte) {
	for i := range buf { buf[i] = 0 }
}
func xorinto(buf, data []byte) {
	for i,w := range data {
		buf[i] ^= w
	}
}

// Ripped straight out of BouncyCastle
func lookupPoly(blockSizeLength int) int {
	switch (blockSizeLength * 8) {
	case 64: return 0x1B;
	case 128: return 0x87;
	case 160: return 0x2D;
	case 192: return 0x87;
	case 224: return 0x309;
	case 256: return 0x425;
	case 320: return 0x1B;
	case 384: return 0x100D;
	case 448: return 0x851;
	case 512: return 0x125;
	case 768: return 0xA0011;
	case 1024: return 0x80043;
	case 2048: return 0x86001;
        }
	return -1
}
func polyshft(dst,src []byte,poly int) {
	mybit := lsh(dst,src)
	j := len(dst)
	poly = subtle.ConstantTimeSelect(mybit, poly, 0)
	for j>0 {
		j--
		dst[j] ^= byte(poly)
		poly >>= 8
	}
}

type hafu struct {
	cipher cipher.Block
	size   int
	buffer []byte
	offset int
	
	fullfin,parfin []byte
}
func hafuN(c cipher.Block) (*hafu,error) {
	size := c.BlockSize()
	poly := lookupPoly(size)
	if poly<0 { return nil,EInvalidBlockSize }
	
	h := new(hafu)
	h.cipher = c
	h.size = size
	h.buffer = make([]byte,size)
	h.fullfin = make([]byte,size)
	h.parfin = make([]byte,size)
	
	c.Encrypt(h.fullfin,h.fullfin)
	polyshft(h.fullfin,h.fullfin,poly)
	polyshft(h.parfin,h.fullfin,poly)
	return h,nil
}

func (h *hafu) Size() int { return h.size }
func (h *hafu) BlockSize() int { return h.size }
func (h *hafu) Reset() { clearbuf(h.buffer) }
func (h *hafu) Write(data []byte) (ret int,_ error) {
	ret = len(data)
	
	if rest := h.size - h.offset ; rest < h.size {
		if ret > rest {
			xorinto(h.buffer[h.offset:],data[:rest])
			h.cipher.Encrypt(h.buffer,h.buffer)
			data = data[rest:]
			h.offset = 0
		} else {
			xorinto(h.buffer[h.offset:],data)
			h.offset += ret
			return
		}
	}
	
	if SZ := h.size; len(data) > SZ {
		l := len(data)/SZ
		if (len(data)%SZ)==0 { l-- }
		
		for i := 0 ; i<l ; i++ {
			xorinto(h.buffer,data[i*SZ:][:SZ])
			h.cipher.Encrypt(h.buffer,h.buffer)
		}
		data = data[l*SZ:]
	}
	
	if len(data) > 0 {
		xorinto(h.buffer,data)
		h.offset = len(data)
	}
	
	return
}

func (h *hafu) hashit() []byte {
	hash := make([]byte,h.size)

	copy(hash,h.buffer)
	if h.offset < h.size {
		xorinto(hash,h.parfin)
		hash[h.offset] ^= 0x80
	} else {
		xorinto(hash,h.fullfin)
	}
	h.cipher.Encrypt(hash, hash)
	return hash
}

func (h *hafu) Sum(b []byte) []byte {
	hash := h.hashit()
	if len(b)==0 && cap(b)<len(hash) { return hash }
	return append(b,hash...)
}

/*
Returns a new hash.Hash instance, that will compute the CMAC aka OMAC1.
If the block cipher's block size is not supported by OMAC1, the hash.Hash
object will be nill and error will be non-nil.
*/
func New(c cipher.Block) (hash.Hash,error) {
	return hafuN(c)
}
