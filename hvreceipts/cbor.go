// SPDX-License-Identifier: Apache-2.0
// Package hvreceipts is the Go SDK and offline verifier for Hivemind
// Receipts. Standard library only; runs the same conformance vectors as the
// TypeScript, Rust and Python verifiers (conformance/receipts/vectors.json).
package hvreceipts

import (
	"bytes"
	"fmt"
	"sort"
)

// Tag wraps a CBOR semantic tag (18 = COSE_Sign1).
type Tag struct {
	Tag   uint64
	Value any
}

func head(buf *bytes.Buffer, major byte, n uint64) {
	m := major << 5
	switch {
	case n < 24:
		buf.WriteByte(m | byte(n))
	case n <= 0xff:
		buf.WriteByte(m | 24)
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(m | 25)
		buf.Write([]byte{byte(n >> 8), byte(n)})
	case n <= 0xffffffff:
		buf.WriteByte(m | 26)
		for _, s := range []int{24, 16, 8, 0} {
			buf.WriteByte(byte(n >> uint(s)))
		}
	default:
		buf.WriteByte(m | 27)
		for _, s := range []int{56, 48, 40, 32, 24, 16, 8, 0} {
			buf.WriteByte(byte(n >> uint(s)))
		}
	}
}

func encodeInto(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteByte(0xf6)
	case bool:
		if x {
			buf.WriteByte(0xf5)
		} else {
			buf.WriteByte(0xf4)
		}
	case int64:
		if x >= 0 {
			head(buf, 0, uint64(x))
		} else {
			head(buf, 1, uint64(-1-x))
		}
	case int:
		return encodeInto(buf, int64(x))
	case string:
		head(buf, 3, uint64(len(x)))
		buf.WriteString(x)
	case []byte:
		head(buf, 2, uint64(len(x)))
		buf.Write(x)
	case []any:
		head(buf, 4, uint64(len(x)))
		for _, e := range x {
			if err := encodeInto(buf, e); err != nil {
				return err
			}
		}
	case map[any]any:
		type entry struct {
			kb  []byte
			val any
		}
		entries := make([]entry, 0, len(x))
		for k, val := range x {
			var kb bytes.Buffer
			if err := encodeInto(&kb, k); err != nil {
				return err
			}
			entries = append(entries, entry{kb.Bytes(), val})
		}
		sort.Slice(entries, func(i, j int) bool {
			if len(entries[i].kb) != len(entries[j].kb) {
				return len(entries[i].kb) < len(entries[j].kb)
			}
			return bytes.Compare(entries[i].kb, entries[j].kb) < 0
		})
		head(buf, 5, uint64(len(entries)))
		for _, e := range entries {
			buf.Write(e.kb)
			if err := encodeInto(buf, e.val); err != nil {
				return err
			}
		}
	case Tag:
		head(buf, 6, x.Tag)
		return encodeInto(buf, x.Value)
	default:
		return fmt.Errorf("cbor: unsupported %T", v)
	}
	return nil
}

// Marshal encodes deterministic CBOR (RFC 8949 core deterministic encoding).
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeInto(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type decoder struct {
	b   []byte
	pos int
}

func (d *decoder) byte() (byte, error) {
	if d.pos >= len(d.b) {
		return 0, fmt.Errorf("cbor: unexpected end")
	}
	v := d.b[d.pos]
	d.pos++
	return v, nil
}

func (d *decoder) take(n int) ([]byte, error) {
	if d.pos+n > len(d.b) {
		return nil, fmt.Errorf("cbor: unexpected end")
	}
	v := d.b[d.pos : d.pos+n]
	d.pos += n
	return v, nil
}

func (d *decoder) arg(ai byte) (uint64, error) {
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		v, err := d.byte()
		if err != nil {
			return 0, err
		}
		if v < 24 {
			return 0, fmt.Errorf("cbor: non-shortest form")
		}
		return uint64(v), nil
	case ai == 25 || ai == 26 || ai == 27:
		w := map[byte]int{25: 2, 26: 4, 27: 8}[ai]
		data, err := d.take(w)
		if err != nil {
			return 0, err
		}
		var v uint64
		for _, b := range data {
			v = v<<8 | uint64(b)
		}
		min := map[int]uint64{2: 256, 4: 65536, 8: 4294967296}[w]
		if v < min {
			return 0, fmt.Errorf("cbor: non-shortest form")
		}
		return v, nil
	default:
		return 0, fmt.Errorf("cbor: indefinite/reserved")
	}
}

func (d *decoder) value(depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("cbor: nesting too deep")
	}
	ib, err := d.byte()
	if err != nil {
		return nil, err
	}
	major, ai := ib>>5, ib&0x1f
	switch major {
	case 0:
		n, err := d.arg(ai)
		return int64(n), err
	case 1:
		n, err := d.arg(ai)
		return -1 - int64(n), err
	case 2:
		n, err := d.arg(ai)
		if err != nil {
			return nil, err
		}
		return d.take(int(n))
	case 3:
		n, err := d.arg(ai)
		if err != nil {
			return nil, err
		}
		b, err := d.take(int(n))
		return string(b), err
	case 4:
		n, err := d.arg(ai)
		if err != nil {
			return nil, err
		}
		out := make([]any, n)
		for i := range out {
			out[i], err = d.value(depth + 1)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	case 5:
		n, err := d.arg(ai)
		if err != nil {
			return nil, err
		}
		out := make(map[any]any, n)
		var prev []byte
		for i := uint64(0); i < n; i++ {
			start := d.pos
			k, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			kb := d.b[start:d.pos]
			if prev != nil {
				if bytes.Equal(prev, kb) {
					return nil, fmt.Errorf("cbor: duplicate key")
				}
				if len(prev) > len(kb) || (len(prev) == len(kb) && bytes.Compare(prev, kb) > 0) {
					return nil, fmt.Errorf("cbor: keys out of order")
				}
			}
			prev = append([]byte{}, kb...)
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case 6:
		t, err := d.arg(ai)
		if err != nil {
			return nil, err
		}
		v, err := d.value(depth + 1)
		return Tag{Tag: t, Value: v}, err
	case 7:
		switch ai {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
		return nil, fmt.Errorf("cbor: floats not in profile")
	}
	return nil, fmt.Errorf("cbor: bad major type")
}

// Unmarshal decodes strict deterministic CBOR.
func Unmarshal(data []byte) (any, error) {
	d := &decoder{b: data}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	if d.pos != len(data) {
		return nil, fmt.Errorf("cbor: trailing bytes")
	}
	return v, nil
}
