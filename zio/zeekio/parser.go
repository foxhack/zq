package zeekio

import (
	"errors"
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zcode"
	"github.com/brimsec/zq/zng"
	"github.com/brimsec/zq/zng/resolver"
)

type header struct {
	separator    string
	setSeparator string
	emptyField   string
	unsetField   string
	Path         string
	open         string
	close        string
	columns      []zng.Column
}

type Parser struct {
	header
	zctx       *resolver.Context
	unknown    int // Count of unknown directives
	needfields bool
	needtypes  bool
	addpath    bool
	// descriptor is a lazily-allocated Descriptor corresponding
	// to the contents of the #fields and #types directives.
	descriptor *zng.TypeRecord
	builder    *zcode.Builder
}

var (
	ErrBadRecordDef = errors.New("bad types/fields definition in zeek header")
	ErrBadEscape    = errors.New("bad escape sequence") //XXX
)

func NewParser(r *resolver.Context) *Parser {
	return &Parser{
		header:  header{separator: " "},
		zctx:    r,
		builder: zcode.NewBuilder(),
	}
}

func badfield(field string) error {
	return fmt.Errorf("encountered bad header field %s parsing zeek log", field)
}

func (p *Parser) parseFields(fields []string) error {
	if len(p.columns) != len(fields) {
		p.columns = make([]zng.Column, len(fields))
		p.needtypes = true
	}
	for k, field := range fields {
		//XXX check that string conforms to a field name syntax
		p.columns[k].Name = field
	}
	p.needfields = false
	p.descriptor = nil
	return nil
}

func (p *Parser) parseTypes(types []string) error {
	if len(p.columns) != len(types) {
		p.columns = make([]zng.Column, len(types))
		p.needfields = true
	}
	for k, name := range types {
		typ, err := zeekTypeToZng(name, p.zctx)
		if err != nil {
			return err
		}
		p.columns[k].Type = typ
	}
	p.needtypes = false
	p.descriptor = nil
	return nil
}

func (p *Parser) ParseDirective(line []byte) error {
	if line[0] == '#' {
		line = line[1:]
	}
	tokens := strings.Split(string(line), p.separator)
	switch tokens[0] {
	case "separator":
		if len(tokens) != 2 {
			return badfield("separator")
		}
		// zng.UnescapeBstring handles \x format escapes
		p.separator = string(zng.UnescapeBstring([]byte(tokens[1])))
	case "set_separator":
		if len(tokens) != 2 {
			return badfield("set_separator")
		}
		p.setSeparator = tokens[1]
	case "empty_field":
		if len(tokens) != 2 {
			return badfield("empty_field")
		}
		//XXX this should be ok now as we process on ingest
		if tokens[1] != "(empty)" {
			return badfield(fmt.Sprintf("#empty_field (non-standard value '%s')", tokens[1]))
		}
		p.emptyField = tokens[1]
	case "unset_field":
		if len(tokens) != 2 {
			return badfield("unset_field")
		}
		//XXX this should be ok now as we process on ingest
		if tokens[1] != "-" {
			return badfield(fmt.Sprintf("#unset_field (non-standard value '%s')", tokens[1]))
		}
		p.unsetField = tokens[1]
	case "path":
		if len(tokens) != 2 {
			return badfield("path")
		}
		p.Path = tokens[1]
		if p.Path == "-" {
			p.Path = ""
		}
	case "open":
		if len(tokens) != 2 {
			return badfield("open")
		}
		p.open = tokens[1]
	case "close":
		if len(tokens) > 2 {
			return badfield("close")
		}
		if len(tokens) == 1 {
			p.close = ""
		} else {
			p.close = tokens[1]
		}

	case "fields":
		if len(tokens) < 2 {
			return badfield("fields")
		}
		if err := p.parseFields(tokens[1:]); err != nil {
			return err
		}
	case "types":
		if len(tokens) < 2 {
			return badfield("types")
		}
		if err := p.parseTypes(tokens[1:]); err != nil {
			return err
		}
	default:
		// XXX return an error?
		p.unknown++
	}
	return nil
}

// Unflatten() turns a set of columns from legacy zeek logs into a
// zng-compatible format by creating nested records for any dotted
// field names. If addpath is true, a _path column is added if not
// already present. The columns are returned as a slice along with a
// bool indicating if a _path column was added.
// Note that according to the zng spec, all the fields for a nested
// record must be adjacent which simplifies the logic here.
func Unflatten(zctx *resolver.Context, columns []zng.Column, addPath bool) ([]zng.Column, bool) {
	hasPath := false
	cols := make([]zng.Column, 0)
	var nestedCols []zng.Column
	var nestedField string
	for _, col := range columns {
		// XXX could validate field names here...
		if col.Name == "_path" {
			hasPath = true
		}

		var fld string
		dot := strings.IndexByte(col.Name, '.')
		if dot >= 0 {
			fld = col.Name[:dot]
		}

		// Check if we're entering or leaving a nested record.
		if fld != nestedField {
			if len(nestedField) > 0 {
				// We've reached the end of a nested record.
				recType := zctx.LookupTypeRecord(nestedCols)
				newcol := zng.NewColumn(nestedField, recType)
				cols = append(cols, newcol)
			}

			if len(fld) > 0 {
				// We're entering a new nested record.
				nestedCols = make([]zng.Column, 0)
			}
			nestedField = fld
		}

		if len(fld) == 0 {
			// Just a regular field.
			cols = append(cols, col)
		} else {
			// Add to the nested record.
			newcol := zng.NewColumn(col.Name[dot+1:], col.Type)
			nestedCols = append(nestedCols, newcol)
		}
	}

	// If we were in the midst of a nested record, make sure we
	// account for it.
	if len(nestedField) > 0 {
		recType := zctx.LookupTypeRecord(nestedCols)
		newcol := zng.NewColumn(nestedField, recType)
		cols = append(cols, newcol)
	}

	var needpath bool
	if addPath && !hasPath {
		pathcol := zng.NewColumn("_path", zng.TypeString)
		cols = append([]zng.Column{pathcol}, cols...)
		needpath = true
	}
	return cols, needpath
}

func (p *Parser) setDescriptor() error {
	// add descriptor and _path, form the columns, and lookup the td
	// in the space's descriptor table.
	if len(p.columns) == 0 || p.needfields || p.needtypes {
		debug.PrintStack()
		return ErrBadRecordDef
	}

	cols, addpath := Unflatten(p.zctx, p.columns, p.Path != "")
	p.descriptor = p.zctx.LookupTypeRecord(cols)
	p.addpath = addpath
	return nil
}

// Descriptor returns the current descriptor (from the most recently
// seen #types and #fields lines) and a bool indicating whether _path
// was added to the descriptor. If no descriptor is present, nil and
// and false are returned.
func (p *Parser) Descriptor() (*zng.TypeRecord, bool) {
	if p.descriptor != nil {
		return p.descriptor, p.addpath
	}
	if err := p.setDescriptor(); err != nil {
		return nil, false
	}
	return p.descriptor, p.addpath

}

func (p *Parser) ParseValue(line []byte) (*zng.Record, error) {
	if p.descriptor == nil {
		err := p.setDescriptor()
		if err != nil {
			return nil, err
		}
	}
	var path []byte
	if p.Path != "" && p.addpath {
		//XXX should store path as a byte slice so it doens't get copied
		// each time here
		path = []byte(p.Path)
	}
	zv, err := zbuf.NewRawFromZeekTSV(p.builder, p.descriptor, path, line)
	if err != nil {
		return nil, err
	}
	return zng.NewRecord(p.descriptor, zv)
}
