package zng

import (
	"github.com/brimsec/zq/ast"
)

//XXX
type Port uint32
type Bstring []byte

func ParseLiteral(literal ast.Literal) (interface{}, error) {
	// String literals inside zql are parsed as zng bstrings
	// (since bstrings can represent a wider range of values,
	// specifically arrays of bytes that do not correspond to
	// UTF-8 encoded strings).
	if literal.Type == "string" {
		literal = ast.Literal{ast.Node{"Literal"}, "bstring", literal.Value}
	}
	v, err := Parse(literal)
	if err != nil {
		return nil, err
	}
	switch v.Type.(type) {
	default:
		return v.Type.Marshal(v.Bytes)
	case nil:
		return nil, nil
	case *TypeOfIP:
		// marshal doesn't work for addr
		return DecodeIP(v.Bytes)
	case *TypeOfNet:
		// marshal doesn't work for subnet
		return DecodeNet(v.Bytes)
	case *TypeOfBstring:
		s, err := DecodeString(v.Bytes)
		return Bstring(s), err
	case *TypeOfPort:
		// return as a native Port
		p, err := DecodePort(v.Bytes)
		return Port(p), err
	}
}
