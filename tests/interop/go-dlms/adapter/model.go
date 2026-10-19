package main

// The JSON model of tests/interop/PROTOCOL.md for gosem's axdr.DlmsData,
// the A-XDR type github.com/cB-Sigma/dlms uses everywhere.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/cosem"
)

var tagNames = map[byte]string{
	0: "null-data", 1: "array", 2: "structure", 3: "boolean", 4: "bit-string",
	5: "double-long", 6: "double-long-unsigned", 7: "floating-point", 9: "octet-string",
	10: "visible-string", 12: "utf8-string", 13: "bcd", 15: "integer", 16: "long",
	17: "unsigned", 18: "long-unsigned", 19: "compact-array", 20: "long64",
	21: "long64-unsigned", 22: "enum", 23: "float32", 24: "float64", 25: "date-time",
	26: "date", 27: "time", 255: "dont-care",
}

func nameOf(d *axdr.DlmsData) string {
	if n, ok := tagNames[byte(d.Tag)]; ok {
		return n
	}
	return fmt.Sprintf("tag-%d", d.Tag)
}

type tree = map[string]any

// toTree maps a decoded value to the protocol's data tree. Date, time and
// date-time are what gosem made of them (a time.Time), written back with
// gosem's own encoder: the library keeps no octets for them.
func toTree(d *axdr.DlmsData) (tree, error) {
	if d == nil {
		return nil, fmt.Errorf("nil value")
	}
	name := nameOf(d)
	switch d.Tag {
	case axdr.TagNull:
		return tree{"t": name, "v": nil}, nil
	case axdr.TagArray, axdr.TagStructure, axdr.TagCompactArray:
		items, ok := d.Value.([]*axdr.DlmsData)
		if !ok {
			return nil, fmt.Errorf("%s holds %T", name, d.Value)
		}
		out := make([]any, 0, len(items))
		for _, it := range items {
			t, err := toTree(it)
			if err != nil {
				return nil, err
			}
			out = append(out, t)
		}
		if d.Tag == axdr.TagCompactArray {
			// gosem keeps no type description, only the items.
			return tree{"t": name, "v": tree{"items": out}}, nil
		}
		return tree{"t": name, "v": out}, nil
	case axdr.TagFloat32, axdr.TagFloatingPoint:
		f, _ := d.Value.(float32)
		return tree{"t": name, "v": fmt.Sprintf("%08x", math.Float32bits(f))}, nil
	case axdr.TagFloat64:
		f, _ := d.Value.(float64)
		return tree{"t": name, "v": fmt.Sprintf("%016x", math.Float64bits(f))}, nil
	case axdr.TagOctetString:
		s, _ := d.Value.(string)
		return tree{"t": name, "v": strings.ToLower(s)}, nil
	case axdr.TagVisibleString:
		// gosem keeps the octets in a Go string; one code point per octet
		// (ISO 8859-1) is how the JSON model carries them.
		s, _ := d.Value.(string)
		return tree{"t": name, "v": latin1(s)}, nil
	case axdr.TagDateTime, axdr.TagDate, axdr.TagTime:
		b, err := d.Encode()
		if err != nil {
			return nil, err
		}
		return tree{"t": name, "v": hex.EncodeToString(b[1:])}, nil
	}
	return tree{"t": name, "v": d.Value}, nil
}

// fromTree builds a gosem value from a data tree.
func fromTree(obj map[string]any) (*axdr.DlmsData, error) {
	name, _ := obj["t"].(string)
	v := obj["v"]
	num := func() (json.Number, error) {
		n, ok := v.(json.Number)
		if !ok {
			return "", fmt.Errorf("%s: not a number", name)
		}
		return n, nil
	}
	i64 := func() (int64, error) {
		n, err := num()
		if err != nil {
			return 0, err
		}
		return n.Int64()
	}
	switch name {
	case "null-data":
		return axdr.CreateAxdrNull(), nil
	case "array", "structure":
		list, _ := v.([]any)
		items := make([]*axdr.DlmsData, 0, len(list))
		for _, x := range list {
			m, _ := x.(map[string]any)
			it, err := fromTree(m)
			if err != nil {
				return nil, err
			}
			items = append(items, it)
		}
		if name == "array" {
			return axdr.CreateAxdrArray(items), nil
		}
		return axdr.CreateAxdrStructure(items), nil
	case "boolean":
		b, _ := v.(bool)
		return axdr.CreateAxdrBoolean(b), nil
	case "bit-string":
		s, _ := v.(string)
		return &axdr.DlmsData{Tag: axdr.TagBitString, Value: s}, nil
	case "octet-string":
		s, _ := v.(string)
		return axdr.CreateAxdrOctetString(s), nil
	case "visible-string":
		s, _ := v.(string)
		b, err := octetsOf(s)
		if err != nil {
			return nil, err
		}
		return axdr.CreateAxdrVisibleString(string(b)), nil
	case "utf8-string":
		s, _ := v.(string)
		return axdr.CreateAxdrUTF8String(s), nil
	case "long64-unsigned":
		n, err := num()
		if err != nil {
			return nil, err
		}
		var u uint64
		if _, err := fmt.Sscan(string(n), &u); err != nil {
			return nil, err
		}
		return axdr.CreateAxdrLong64Unsigned(u), nil
	case "float32", "float64":
		s, _ := v.(string)
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		var bits uint64
		for _, x := range b {
			bits = bits<<8 | uint64(x)
		}
		if name == "float32" {
			return axdr.CreateAxdrFloat32(math.Float32frombits(uint32(bits))), nil
		}
		return axdr.CreateAxdrFloat64(math.Float64frombits(bits)), nil
	case "date-time", "date", "time":
		// gosem takes a time.Time: the octets go through its own decoder.
		s, _ := v.(string)
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		var tag axdr.DlmsData
		switch name {
		case "date-time":
			_, t, err := axdr.DecodeDateTime(&b)
			if err != nil {
				return nil, err
			}
			tag = *axdr.CreateAxdrDateTime(t)
		case "date":
			_, t, err := axdr.DecodeDate(&b)
			if err != nil {
				return nil, err
			}
			tag = *axdr.CreateAxdrDate(t)
		default:
			_, t, err := axdr.DecodeTime(&b)
			if err != nil {
				return nil, err
			}
			tag = *axdr.CreateAxdrTime(t)
		}
		return &tag, nil
	case "compact-array":
		return nil, errUnsupported("gosem cannot encode compact-array (axdr.go: not yet implemented)")
	}
	n, err := i64()
	if err != nil {
		return nil, err
	}
	switch name {
	case "double-long":
		return axdr.CreateAxdrDoubleLong(int32(n)), nil
	case "double-long-unsigned":
		return axdr.CreateAxdrDoubleLongUnsigned(uint32(n)), nil
	case "bcd":
		return axdr.CreateAxdrBCD(int8(n)), nil
	case "integer":
		return axdr.CreateAxdrInteger(int8(n)), nil
	case "long":
		return axdr.CreateAxdrLong(int16(n)), nil
	case "unsigned":
		return axdr.CreateAxdrUnsigned(uint8(n)), nil
	case "long-unsigned":
		return axdr.CreateAxdrLongUnsigned(uint16(n)), nil
	case "long64":
		return axdr.CreateAxdrLong64(n), nil
	case "enum":
		return axdr.CreateAxdrEnum(uint8(n)), nil
	}
	return nil, fmt.Errorf("unknown type %q", name)
}

// encode is the library's encoder (cosem.EncodeAXDR, which the server uses
// for every answer); EncodeAXDR drops gosem's errors, so each leaf is
// encoded once more to surface them.
func encode(d *axdr.DlmsData) ([]byte, error) {
	if err := checkLeaves(d); err != nil {
		return nil, err
	}
	r, _, _ := cosem.EncodeAXDR(d)
	return r, nil
}

func checkLeaves(d *axdr.DlmsData) error {
	switch d.Tag {
	case axdr.TagNull:
		return nil
	case axdr.TagArray, axdr.TagStructure:
		items, _ := d.Value.([]*axdr.DlmsData)
		for _, it := range items {
			if err := checkLeaves(it); err != nil {
				return err
			}
		}
		return nil
	}
	_, err := d.Encode()
	return err
}

// decodeOne decodes one value that must fill b exactly.
func decodeOne(b []byte) (*axdr.DlmsData, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	src := b
	d, err := axdr.NewDataDecoder(&src).Decode(&src)
	if err != nil {
		return nil, err
	}
	if len(src) != 0 {
		return nil, fmt.Errorf("%d trailing octets", len(src))
	}
	return &d, nil
}

func latin1(s string) string {
	r := make([]rune, len(s))
	for i := 0; i < len(s); i++ {
		r[i] = rune(s[i])
	}
	return string(r)
}

func octetsOf(s string) ([]byte, error) {
	var b []byte
	for _, r := range s {
		if r > 0xFF {
			return nil, fmt.Errorf("visible-string code point %U is not one octet", r)
		}
		b = append(b, byte(r))
	}
	return b, nil
}
