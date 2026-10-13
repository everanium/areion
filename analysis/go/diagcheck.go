package main

// Section B4: exhaustive linear-part check. Bytes of one column (after
// ShiftRows) that each vary over a 2-point set {p, p ^ alpha} pass the
// first S-box layer with output directions beta_j (any nonzero byte is
// reachable). After MixColumns, row i varies over the span of
// m_ij * beta_j. The next S-box maps that row affinely only if the span
// has dimension <= 1 or is an F_4-line or an F_16-line (B1); offsets
// and round constants cannot change the span. Count the direction
// tuples (up to a common scalar, beta at the first used row set to 1)
// for which every row qualifies.

import "fmt"

func gmulB(a, b byte) byte {
	var r byte
	for b != 0 {
		if b&1 == 1 {
			r ^= a
		}
		if a&0x80 != 0 {
			a = a<<1 ^ 0x1b
		} else {
			a <<= 1
		}
		b >>= 1
	}
	return r
}

func spanMask(vs []byte) (set256, int) {
	var s set256
	s.add(0)
	dim := 0
	for _, v := range vs {
		if s.has(int(v)) {
			continue
		}
		dim++
		var t set256
		for x := 0; x < 256; x++ {
			if s.has(x) {
				t.add(x)
				t.add(x ^ int(v))
			}
		}
		s = t
	}
	return s, dim
}

func diagMain() {
	m := [4]byte{2, 3, 1, 1}
	pw := func(a byte, e int) byte {
		r := byte(1)
		for i := 0; i < e; i++ {
			r = gmulB(r, a)
		}
		return r
	}
	lines := map[set256]int{}
	for _, d := range []int{2, 4} {
		var F []byte
		for x := 0; x < 256; x++ {
			if pw(byte(x), 1<<d) == byte(x) {
				F = append(F, byte(x))
			}
		}
		for l := 1; l < 256; l++ {
			var s set256
			for _, f := range F {
				s.add(int(gmulB(byte(l), f)))
			}
			lines[s] = d
		}
	}
	ok := func(J []int, beta []byte) bool {
		for i := 0; i < 4; i++ {
			vs := make([]byte, len(J))
			for k, j := range J {
				vs[k] = gmulB(m[(j-i+4)%4], beta[k])
			}
			s, dim := spanMask(vs)
			if dim <= 1 {
				continue
			}
			if d, isLine := lines[s]; !isLine || d != dim {
				return false
			}
		}
		return true
	}
	for mask := 3; mask < 16; mask++ {
		var J []int
		for j := 0; j < 4; j++ {
			if mask>>j&1 == 1 {
				J = append(J, j)
			}
		}
		if len(J) < 2 {
			continue
		}
		count, total := 0, 0
		beta := make([]byte, len(J))
		beta[0] = 1
		var rec func(k int)
		rec = func(k int) {
			if k == len(J) {
				total++
				if ok(J, beta) {
					count++
				}
				return
			}
			for b := 1; b < 256; b++ {
				beta[k] = byte(b)
				rec(k + 1)
			}
		}
		rec(1)
		fmt.Printf("rows used %v: direction tuples %d, passing all four rows: %d\n", J, total, count)
	}
}
