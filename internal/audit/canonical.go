package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Canonical encoding
//
// Every audit line is a JSON object written in canonical form, and the hash
// is computed over the same canonical form, so a verifier can recompute it
// from the parsed line alone:
//
//   - values are first normalised through encoding/json (Marshal, then Decode
//     with UseNumber), so only objects, arrays, strings, json.Number, bools
//     and null remain;
//   - objects: keys sorted by byte-wise string comparison, no whitespace,
//     "{" key ":" value ("," key ":" value)* "}";
//   - strings: encoding/json's encoding with HTML escaping disabled;
//   - numbers: the json.Number literal text exactly as produced by
//     encoding/json when the value was first marshalled (and as read back);
//   - arrays: "[" v ("," v)* "]"; true/false/null as literals.
//
// The record hash is hex(SHA-256(prevHashBytes || canonical(record without
// the "hash" key))), where prevHashBytes is the raw 32 bytes of the previous
// record's hash (empty for the very first record).

// normalize converts v into the JSON data model with json.Number numbers.
func normalize(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return decodeValue(b)
}

func decodeValue(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("trailing data")
	}
	return out, nil
}

// canonical appends the canonical encoding of a normalised value to buf.
func canonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(x.String())
	case string:
		writeString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := canonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("audit: non-canonical value of type %T", v)
	}
	return nil
}

func writeString(buf *bytes.Buffer, s string) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // strings always encode
	buf.Write(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
}
