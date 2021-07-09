// Copyright 2018 ProximaX Limited. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

// Ported in 2021 to Go

// README: This is copied from tweeetnacl/nacl.fast.js and is updated to export custom hash functions.

// Ported in 2014 by Dmitry Chestnykh and Devi Mandiri.
// Public domain.
//

//
// Implementation derived from TweetNaCl version 20140427.
// See for details: http://tweetnacl.cr.yp.to/

/* eslint-disable */

package crypto

import (
	"encoding/binary"
)

func initNine() [32]byte {
	val := [32]byte{}
	val[0] = 9
	return val
}

var (
	_0 = [16]byte{}
	_9 = initNine()
)

func gf(init []int64) [16 * 8]byte {
	r := [16 * 8]byte{}
	if len(init) > 0 {
		for i := 0; i < len(init); i++ {
			b := r[(i * 8):(i*8 + 8)]
			binary.LittleEndian.PutUint64(b, uint64(init[i]))
		}
	}
	return r
}

var (
	gf0     = gf([]int64{})
	gf1     = gf([]int64{1})
	_121665 = gf([]int64{0xdb41, 1})
	D       = gf([]int64{
		0x78a3,
		0x1359,
		0x4dca,
		0x75eb,
		0xd8ab,
		0x4141,
		0x0a4d,
		0x0070,
		0xe898,
		0x7779,
		0x4079,
		0x8cc7,
		0xfe73,
		0x2b6f,
		0x6cee,
		0x5203,
	})
	D2 = gf([]int64{
		0xf159,
		0x26b2,
		0x9b94,
		0xebd6,
		0xb156,
		0x8283,
		0x149a,
		0x00e0,
		0xd130,
		0xeef3,
		0x80f2,
		0x198e,
		0xfce7,
		0x56df,
		0xd9dc,
		0x2406,
	})
	X = gf([]int64{
		0xd51a,
		0x8f25,
		0x2d60,
		0xc956,
		0xa7b2,
		0x9525,
		0xc760,
		0x692c,
		0xdc5c,
		0xfdd6,
		0xe231,
		0xc0a4,
		0x53fe,
		0xcd6e,
		0x36d3,
		0x2169,
	})
	Y = gf([]int64{
		0x6658,
		0x6666,
		0x6666,
		0x6666,
		0x6666,
		0x6666,
		0x6666,
		0x6666,
		0x6666,
		0x6666,
		0x6666,
		0x6666,
		0x6666,
		0x6666,
		0x6666,
		0x6666,
	})
	I = gf([]int64{
		0xa0b0,
		0x4a0e,
		0x1b27,
		0xc4ee,
		0xe478,
		0xad2f,
		0x1806,
		0x2f43,
		0xd7a7,
		0x3dfb,
		0x0099,
		0x2b4d,
		0xdf0b,
		0x4fc1,
		0x2480,
		0x2b83,
	})
)

var L = [...]int64{
	0xed,
	0xd3,
	0xf5,
	0x5c,
	0x1a,
	0x63,
	0x12,
	0x58,
	0xd6,
	0x9c,
	0xf7,
	0xa2,
	0xde,
	0xf9,
	0xde,
	0x14,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0x10,
}

func B(o *[128]byte, a [128]byte, b [128]byte) {
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint64(o[i*8:i*8+8], binary.LittleEndian.Uint64(a[8*i:8*i+8])+binary.LittleEndian.Uint64(b[8*i:8*i+8]))
	}
}

func Z(o *[128]byte, a [128]byte, b [128]byte) {
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint64(o[i*8:i*8+8], binary.LittleEndian.Uint64(a[8*i:8*i+8])-binary.LittleEndian.Uint64(b[8*i:8*i+8]))
	}
}

func M(o *[128]byte, a [128]byte, b [128]byte) {
	v := uint64(0)
	c := uint64(0)
	t0 := uint64(0)
	t1 := uint64(0)
	t2 := uint64(0)
	t3 := uint64(0)
	t4 := uint64(0)
	t5 := uint64(0)
	t6 := uint64(0)
	t7 := uint64(0)
	t8 := uint64(0)
	t9 := uint64(0)
	t10 := uint64(0)
	t11 := uint64(0)
	t12 := uint64(0)
	t13 := uint64(0)
	t14 := uint64(0)
	t15 := uint64(0)
	t16 := uint64(0)
	t17 := uint64(0)
	t18 := uint64(0)
	t19 := uint64(0)
	t20 := uint64(0)
	t21 := uint64(0)
	t22 := uint64(0)
	t23 := uint64(0)
	t24 := uint64(0)
	t25 := uint64(0)
	t26 := uint64(0)
	t27 := uint64(0)
	t28 := uint64(0)
	t29 := uint64(0)
	t30 := uint64(0)
	b0 := binary.LittleEndian.Uint64(b[0:8])
	b1 := binary.LittleEndian.Uint64(b[8:16])
	b2 := binary.LittleEndian.Uint64(b[16:24])
	b3 := binary.LittleEndian.Uint64(b[24:32])
	b4 := binary.LittleEndian.Uint64(b[32:40])
	b5 := binary.LittleEndian.Uint64(b[40:48])
	b6 := binary.LittleEndian.Uint64(b[48:56])
	b7 := binary.LittleEndian.Uint64(b[56:64])
	b8 := binary.LittleEndian.Uint64(b[64:72])
	b9 := binary.LittleEndian.Uint64(b[72:80])
	b10 := binary.LittleEndian.Uint64(b[80:88])
	b11 := binary.LittleEndian.Uint64(b[88:96])
	b12 := binary.LittleEndian.Uint64(b[96:104])
	b13 := binary.LittleEndian.Uint64(b[104:112])
	b14 := binary.LittleEndian.Uint64(b[112:120])
	b15 := binary.LittleEndian.Uint64(b[120:])
	v = binary.LittleEndian.Uint64(a[0:8])
	t0 += v * b0
	t1 += v * b1
	t2 += v * b2
	t3 += v * b3
	t4 += v * b4
	t5 += v * b5
	t6 += v * b6
	t7 += v * b7
	t8 += v * b8
	t9 += v * b9
	t10 += v * b10
	t11 += v * b11
	t12 += v * b12
	t13 += v * b13
	t14 += v * b14
	t15 += v * b15
	v = binary.LittleEndian.Uint64(a[8:16])
	t1 += v * b0
	t2 += v * b1
	t3 += v * b2
	t4 += v * b3
	t5 += v * b4
	t6 += v * b5
	t7 += v * b6
	t8 += v * b7
	t9 += v * b8
	t10 += v * b9
	t11 += v * b10
	t12 += v * b11
	t13 += v * b12
	t14 += v * b13
	t15 += v * b14
	t16 += v * b15
	v = binary.LittleEndian.Uint64(a[16:24])
	t2 += v * b0
	t3 += v * b1
	t4 += v * b2
	t5 += v * b3
	t6 += v * b4
	t7 += v * b5
	t8 += v * b6
	t9 += v * b7
	t10 += v * b8
	t11 += v * b9
	t12 += v * b10
	t13 += v * b11
	t14 += v * b12
	t15 += v * b13
	t16 += v * b14
	t17 += v * b15
	v = binary.LittleEndian.Uint64(a[24:32])
	t3 += v * b0
	t4 += v * b1
	t5 += v * b2
	t6 += v * b3
	t7 += v * b4
	t8 += v * b5
	t9 += v * b6
	t10 += v * b7
	t11 += v * b8
	t12 += v * b9
	t13 += v * b10
	t14 += v * b11
	t15 += v * b12
	t16 += v * b13
	t17 += v * b14
	t18 += v * b15
	v = binary.LittleEndian.Uint64(a[32:40])
	t4 += v * b0
	t5 += v * b1
	t6 += v * b2
	t7 += v * b3
	t8 += v * b4
	t9 += v * b5
	t10 += v * b6
	t11 += v * b7
	t12 += v * b8
	t13 += v * b9
	t14 += v * b10
	t15 += v * b11
	t16 += v * b12
	t17 += v * b13
	t18 += v * b14
	t19 += v * b15
	v = binary.LittleEndian.Uint64(a[40:48])
	t5 += v * b0
	t6 += v * b1
	t7 += v * b2
	t8 += v * b3
	t9 += v * b4
	t10 += v * b5
	t11 += v * b6
	t12 += v * b7
	t13 += v * b8
	t14 += v * b9
	t15 += v * b10
	t16 += v * b11
	t17 += v * b12
	t18 += v * b13
	t19 += v * b14
	t20 += v * b15
	v = binary.LittleEndian.Uint64(a[48:56])
	t6 += v * b0
	t7 += v * b1
	t8 += v * b2
	t9 += v * b3
	t10 += v * b4
	t11 += v * b5
	t12 += v * b6
	t13 += v * b7
	t14 += v * b8
	t15 += v * b9
	t16 += v * b10
	t17 += v * b11
	t18 += v * b12
	t19 += v * b13
	t20 += v * b14
	t21 += v * b15
	v = binary.LittleEndian.Uint64(a[56:64])
	t7 += v * b0
	t8 += v * b1
	t9 += v * b2
	t10 += v * b3
	t11 += v * b4
	t12 += v * b5
	t13 += v * b6
	t14 += v * b7
	t15 += v * b8
	t16 += v * b9
	t17 += v * b10
	t18 += v * b11
	t19 += v * b12
	t20 += v * b13
	t21 += v * b14
	t22 += v * b15
	v = binary.LittleEndian.Uint64(a[64:72])
	t8 += v * b0
	t9 += v * b1
	t10 += v * b2
	t11 += v * b3
	t12 += v * b4
	t13 += v * b5
	t14 += v * b6
	t15 += v * b7
	t16 += v * b8
	t17 += v * b9
	t18 += v * b10
	t19 += v * b11
	t20 += v * b12
	t21 += v * b13
	t22 += v * b14
	t23 += v * b15
	v = binary.LittleEndian.Uint64(a[72:80])
	t9 += v * b0
	t10 += v * b1
	t11 += v * b2
	t12 += v * b3
	t13 += v * b4
	t14 += v * b5
	t15 += v * b6
	t16 += v * b7
	t17 += v * b8
	t18 += v * b9
	t19 += v * b10
	t20 += v * b11
	t21 += v * b12
	t22 += v * b13
	t23 += v * b14
	t24 += v * b15
	v = binary.LittleEndian.Uint64(a[80:88])
	t10 += v * b0
	t11 += v * b1
	t12 += v * b2
	t13 += v * b3
	t14 += v * b4
	t15 += v * b5
	t16 += v * b6
	t17 += v * b7
	t18 += v * b8
	t19 += v * b9
	t20 += v * b10
	t21 += v * b11
	t22 += v * b12
	t23 += v * b13
	t24 += v * b14
	t25 += v * b15
	v = binary.LittleEndian.Uint64(a[88:96])
	t11 += v * b0
	t12 += v * b1
	t13 += v * b2
	t14 += v * b3
	t15 += v * b4
	t16 += v * b5
	t17 += v * b6
	t18 += v * b7
	t19 += v * b8
	t20 += v * b9
	t21 += v * b10
	t22 += v * b11
	t23 += v * b12
	t24 += v * b13
	t25 += v * b14
	t26 += v * b15
	v = binary.LittleEndian.Uint64(a[96:104])
	t12 += v * b0
	t13 += v * b1
	t14 += v * b2
	t15 += v * b3
	t16 += v * b4
	t17 += v * b5
	t18 += v * b6
	t19 += v * b7
	t20 += v * b8
	t21 += v * b9
	t22 += v * b10
	t23 += v * b11
	t24 += v * b12
	t25 += v * b13
	t26 += v * b14
	t27 += v * b15
	v = binary.LittleEndian.Uint64(a[104:112])
	t13 += v * b0
	t14 += v * b1
	t15 += v * b2
	t16 += v * b3
	t17 += v * b4
	t18 += v * b5
	t19 += v * b6
	t20 += v * b7
	t21 += v * b8
	t22 += v * b9
	t23 += v * b10
	t24 += v * b11
	t25 += v * b12
	t26 += v * b13
	t27 += v * b14
	t28 += v * b15
	v = binary.LittleEndian.Uint64(a[112:120])
	t14 += v * b0
	t15 += v * b1
	t16 += v * b2
	t17 += v * b3
	t18 += v * b4
	t19 += v * b5
	t20 += v * b6
	t21 += v * b7
	t22 += v * b8
	t23 += v * b9
	t24 += v * b10
	t25 += v * b11
	t26 += v * b12
	t27 += v * b13
	t28 += v * b14
	t29 += v * b15
	v = binary.LittleEndian.Uint64(a[120:128])
	t15 += v * b0
	t16 += v * b1
	t17 += v * b2
	t18 += v * b3
	t19 += v * b4
	t20 += v * b5
	t21 += v * b6
	t22 += v * b7
	t23 += v * b8
	t24 += v * b9
	t25 += v * b10
	t26 += v * b11
	t27 += v * b12
	t28 += v * b13
	t29 += v * b14
	t30 += v * b15

	t0 += 38 * t16
	t1 += 38 * t17
	t2 += 38 * t18
	t3 += 38 * t19
	t4 += 38 * t20
	t5 += 38 * t21
	t6 += 38 * t22
	t7 += 38 * t23
	t8 += 38 * t24
	t9 += 38 * t25
	t10 += 38 * t26
	t11 += 38 * t27
	t12 += 38 * t28
	t13 += 38 * t29
	t14 += 38 * t30

	// first car
	c = 1
	v = t0 + c + 65535
	c = v / 65536
	t0 = v - c*65536
	v = t1 + c + 65535
	c = v / 65536
	t1 = v - c*65536
	v = t2 + c + 65535
	c = v / 65536
	t2 = v - c*65536
	v = t3 + c + 65535
	c = v / 65536
	t3 = v - c*65536
	v = t4 + c + 65535
	c = v / 65536
	t4 = v - c*65536
	v = t5 + c + 65535
	c = v / 65536
	t5 = v - c*65536
	v = t6 + c + 65535
	c = v / 65536
	t6 = v - c*65536
	v = t7 + c + 65535
	c = v / 65536
	t7 = v - c*65536
	v = t8 + c + 65535
	c = v / 65536
	t8 = v - c*65536
	v = t9 + c + 65535
	c = v / 65536
	t9 = v - c*65536
	v = t10 + c + 65535
	c = v / 65536
	t10 = v - c*65536
	v = t11 + c + 65535
	c = v / 65536
	t11 = v - c*65536
	v = t12 + c + 65535
	c = v / 65536
	t12 = v - c*65536
	v = t13 + c + 65535
	c = v / 65536
	t13 = v - c*65536
	v = t14 + c + 65535
	c = v / 65536
	t14 = v - c*65536
	v = t15 + c + 65535
	c = v / 65536
	t15 = v - c*65536
	t0 += c - 1 + 37*(c-1)

	// second car
	c = 1
	v = t0 + c + 65535
	c = v / 65536
	t0 = v - c*65536
	v = t1 + c + 65535
	c = v / 65536
	t1 = v - c*65536
	v = t2 + c + 65535
	c = v / 65536
	t2 = v - c*65536
	v = t3 + c + 65535
	c = v / 65536
	t3 = v - c*65536
	v = t4 + c + 65535
	c = v / 65536
	t4 = v - c*65536
	v = t5 + c + 65535
	c = v / 65536
	t5 = v - c*65536
	v = t6 + c + 65535
	c = v / 65536
	t6 = v - c*65536
	v = t7 + c + 65535
	c = v / 65536
	t7 = v - c*65536
	v = t8 + c + 65535
	c = v / 65536
	t8 = v - c*65536
	v = t9 + c + 65535
	c = v / 65536
	t9 = v - c*65536
	v = t10 + c + 65535
	c = v / 65536
	t10 = v - c*65536
	v = t11 + c + 65535
	c = v / 65536
	t11 = v - c*65536
	v = t12 + c + 65535
	c = v / 65536
	t12 = v - c*65536
	v = t13 + c + 65535
	c = v / 65536
	t13 = v - c*65536
	v = t14 + c + 65535
	c = v / 65536
	t14 = v - c*65536
	v = t15 + c + 65535
	c = v / 65536
	t15 = v - c*65536
	t0 += c - 1 + 37*(c-1)
	binary.LittleEndian.PutUint64(o[0:8], t0)
	binary.LittleEndian.PutUint64(o[8:16], t1)
	binary.LittleEndian.PutUint64(o[16:24], t2)
	binary.LittleEndian.PutUint64(o[24:32], t3)
	binary.LittleEndian.PutUint64(o[32:40], t4)
	binary.LittleEndian.PutUint64(o[40:48], t5)
	binary.LittleEndian.PutUint64(o[48:56], t6)
	binary.LittleEndian.PutUint64(o[56:64], t7)
	binary.LittleEndian.PutUint64(o[64:72], t8)
	binary.LittleEndian.PutUint64(o[72:80], t9)
	binary.LittleEndian.PutUint64(o[80:88], t10)
	binary.LittleEndian.PutUint64(o[88:96], t11)
	binary.LittleEndian.PutUint64(o[96:104], t12)
	binary.LittleEndian.PutUint64(o[104:112], t13)
	binary.LittleEndian.PutUint64(o[112:120], t14)
	binary.LittleEndian.PutUint64(o[120:128], t15)
}

func S(o *[128]byte, a [128]byte) {
	M(o, a, a)
}

func vn(x []byte, xi int, y []byte, yi int, n int) bool {
	var d byte = 0
	for i := 0; i < n; i++ {
		d |= x[xi+i] ^ y[yi+i]
	}
	e := uint16(d)

	//VERIFY
	//using e uint16 so d-1 can scroll back to 65535?
	return ((1 & ((e - 1) >> 8)) - 1) == 1
	/* original
	return (1 & ((d - 1) >> 8)) - 1
	*/
}

func pow2523(o *[128]byte, i [128]byte) {
	c := gf(nil)
	for a := 0; a < 128; a++ {
		c[a] = i[a]
	}
	for a := 250; a >= 0; a-- {
		S(&c, c)
		if a != 1 {
			M(&c, c, i)
		}
	}
	for a := 0; a < 128; a++ {
		o[a] = c[a]
	}
}

//i is 8 byte array
func inv25519(o *[128]byte, i [128]byte) {
	c := gf(nil)
	for a := 0; a < 128; a++ {
		c[a] = i[a]
	}
	for a := 253; a >= 0; a-- {
		S(&c, c)
		if a != 2 && a != 4 {
			M(&c, c, i)
		}
	}
	for a := 0; a < 128; a++ {
		o[a] = c[a]
	}
}
func set25519(r *[128]byte, a [128]byte) {
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint64(r[i*8:i*8+8], binary.LittleEndian.Uint64(a[i*8:i*8+8])|0)
	}
}
func car25519(o *[128]byte) {
	c := uint64(1)
	var v uint64
	for i := 0; i < 16; i++ {
		v = binary.LittleEndian.Uint64(o[i*8:i*8+8]) + c + 65535
		c = v / 65536
		binary.LittleEndian.PutUint64(o[i*8:i*8+8], v-c*65536)
	}
	binary.LittleEndian.PutUint64(o[0:8], c-1+37*(c-1))
}

func sel25519(p *[128]byte, q *[128]byte, b uint64) {
	var t uint64
	c := ^(b - 1)
	for i := 0; i < 16; i++ {
		t = c & (binary.LittleEndian.Uint64(p[i*8:i*8+8]) ^ binary.LittleEndian.Uint64(q[i*8:i*8+8]))
		binary.LittleEndian.PutUint64(p[i*8:i*8+8], binary.LittleEndian.Uint64(p[i*8:i*8+8])^t)
		binary.LittleEndian.PutUint64(q[i*8:i*8+8], binary.LittleEndian.Uint64(q[i*8:i*8+8])^t)
	}
}

func pack25519(o *[32]byte, n [128]byte) {
	m := gf(nil)
	t := n
	car25519(&t)
	car25519(&t)
	car25519(&t)
	for j := 0; j < 2; j++ {
		binary.LittleEndian.PutUint64(m[0:8], binary.LittleEndian.Uint64(t[0:8])-0xffed)
		for i := 0; i < 15; i++ {
			binary.LittleEndian.PutUint64(m[i*8:i*8+8], binary.LittleEndian.Uint64(t[i*8:i*8+8])-0xffff-((binary.LittleEndian.Uint64(m[(i-1)*8:(i-1)*8+8])>>16)&1))
			binary.LittleEndian.PutUint64(m[(i-1)*8:(i-1)*8+8], binary.LittleEndian.Uint64(m[(i-1)*8:(i-1)*8+8])&0xffff)
		}
		binary.LittleEndian.PutUint64(m[15*8:15*8+8], binary.LittleEndian.Uint64(t[15*8:15*8+8])-0x7fff-((binary.LittleEndian.Uint64(m[14*8:14*8+8])>>16)&1))
		b := (binary.LittleEndian.Uint64(m[15*8:15*8+8]) >> 16) & 1
		binary.LittleEndian.PutUint64(m[14*8:14*8+8], binary.LittleEndian.Uint64(m[14*8:14*8+8])&0xffff)
		sel25519(&t, &m, 1-b)
	}
	for i := 0; i < 16; i++ { //VERIFY THIS!!!!!!!

		o[2*i] = t[i*8+7]
		o[2*i+1] = t[i*8+6]
		/* original
				o[2 * i] = t[i] & 0xff;
		        o[2 * i + 1] = t[i] >> 8;
		*/
	}
}

func cswap(p *[4][128]byte, q *[4][128]byte, b uint64) {
	for i := 0; i < 4; i++ {
		sel25519(&p[i], &q[i], b)
	}
}

func neq25519(a [128]byte, b [128]byte) bool {
	c := [32]byte{}
	d := [32]byte{}
	pack25519(&c, a)
	pack25519(&d, b)
	return crypto_verify_32(c, 0, d, 0)
}

func par25519(a [128]byte) byte {
	d := [32]byte{}
	pack25519(&d, a)
	return d[0] & 1
}

func unpack25519(o *[128]byte, n [32]byte) {
	for i := 0; i < 16; i++ { //VERIFY THIS!!!!!
		//NOTE(ERASE THIS): filling two last bytes of each 8 byte section
		//sum is basically setting penultimate byte because all zeroes
		TempBinary64 := make([]byte, 8)
		TempBinary64[6] = n[2*i+1]
		TempBinary64[7] = n[2*i]
		binary.LittleEndian.PutUint64(o[i*8:i*8+8], binary.LittleEndian.Uint64(TempBinary64))
		/* original
		o[i] = n[2*i] + (n[2*i+1] << 8)
		*/
	}
	binary.LittleEndian.PutUint64(o[120:128], binary.LittleEndian.Uint64(o[120:128])&0x7fff)
}

func crypto_verify_32(x [32]byte, xi int, y [32]byte, yi int) bool {
	//can we do this more effectively?
	var x1 []byte
	var y1 []byte
	copy(x[:], x1)
	copy(y[:], y1)
	return vn(x1, xi, y1, yi, 32)
}

func add(p *[4][128]byte, q *[4][128]byte) {
	a := gf(nil)
	b := gf(nil)
	c := gf(nil)
	d := gf(nil)
	e := gf(nil)
	f := gf(nil)
	g := gf(nil)
	h := gf(nil)
	t := gf(nil)
	Z(&a, p[1], p[0])
	Z(&t, q[1], q[0])
	M(&a, a, t)
	B(&b, p[0], p[1])
	B(&t, q[0], q[1])
	M(&b, b, t)
	M(&c, p[3], q[3])
	M(&c, c, D2)
	M(&d, p[2], q[2])
	B(&d, d, d)
	Z(&e, b, a)
	Z(&f, d, c)
	B(&g, d, c)
	B(&h, b, a)

	M(&p[0], e, f)
	M(&p[1], h, g)
	M(&p[2], g, f)
	M(&p[3], e, h)
}

func pack(r *[32]byte, p [4][16 * 8]byte) {
	tx := gf(nil)
	ty := gf(nil)
	zi := gf(nil)
	inv25519(&zi, p[0])
	M(&tx, p[0], zi)
	M(&ty, p[1], zi)
	pack25519(r, ty)
	r[31] ^= par25519(tx) << 7
}

func scalarmult(p *[4][128]byte, q *[4][128]byte, s *[32]byte) {
	var b uint64
	set25519(&p[0], gf0)
	set25519(&p[1], gf1)
	set25519(&p[2], gf1)
	set25519(&p[3], gf0)
	for i := 254; i >= 0; i-- { //Note(remember to remove this): per bit operation
		//assuming | or 0 is math floor in js?
		//Note: for each 8 bits on every s byte we will fill an uint64
		//(i & 7) means we will ignore any numbers to the left of first binary digits, cycle through 0-7 infinitely as i increments
		//Do we ever only work with the last byte?? VERIFY!!!
		emptyByte64 := make([]byte, 8)
		emptyByte64[7] = (s[i/8] >> (i & 7)) & 1
		binary.LittleEndian.PutUint64(emptyByte64, b)
		//b = (s[(i/8)|0] >> (i & 7)) & 1
		cswap(p, q, b)
		add(q, p)
		add(p, p)
		cswap(p, q, b)
	}
}

func unpack(r *[4][16 * 8]byte, p [32]byte) int {
	t := gf(nil)
	chk := gf(nil)
	num := gf(nil)
	den := gf(nil)
	den2 := gf(nil)
	den4 := gf(nil)
	den6 := gf(nil)
	set25519(&r[2], gf1)
	unpack25519(&r[1], p)

	// num = u = y^2 - 1
	// den = v = d * y^2 + 1
	S(&num, r[1])
	M(&den, num, D)
	Z(&num, num, r[2])
	B(&den, r[2], den)

	// r[0] = x = sqrt(u / v)
	S(&den2, den)
	S(&den4, den2)
	M(&den6, den4, den2)
	M(&t, den6, num)
	M(&t, t, den)

	pow2523(&t, t)
	M(&t, t, num)
	M(&t, t, den)
	M(&t, t, den)
	M(&r[0], t, den)

	S(&chk, r[0])
	M(&chk, chk, den)
	if neq25519(chk, num) {
		M(&r[0], r[0], I)
	}

	S(&chk, r[0])
	M(&chk, chk, den)
	if neq25519(chk, num) {
		return -1
	}

	if par25519(r[0]) != p[31]>>7 {
		Z(&r[0], gf0, r[0])
	}

	M(&r[3], r[0], r[1])
	return 0

}
