// Package ast declares the types used to represent syntax trees for zql
// queries.
package ast

// This module is derived from the GO ast design pattern
// https://golang.org/pkg/go/ast/
//
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import "encoding/json"

// A Node is shared by all the AST type nodes.  Currently, this contains the
// op field, as every node type is defined by its op name.
type Node struct {
	Op string `json:"op"`
}

// Proc is the interface implemented by all AST processor nodes.
type Proc interface {
	ProcNode()
	Copy() Proc
}

// BooleanExpr is the interface implement by all AST boolean expression nodes.
type BooleanExpr interface {
	booleanExprNode()
	Copy() BooleanExpr
}

// FieldExpr is the interface implemented by expressions that reference fields.
type FieldExpr interface {
	fieldExprNode()
	Copy() FieldExpr
}

// A TypedValue is a string representation of a literal value where the
// type field indicated the underlying data type (of the set of all supported
// boom data types, derived from the zeek type system and not to be confused with
// the native Go types) and value is a string representation of that value that
// must conform to the provided type.
// XXX these should be broken out into different native Go types but for now
// we'll keep them as strings.
type TypedValue struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ----------------------------------------------------------------------------
// Boolean expressions (aka search expressions or filters)

// A boolean expression is represented by a tree consisting of one
// or more of the following concrete expression nodes.
//
type (
	// A LogicalAnd node represents a logical and of two subexpressions.
	LogicalAnd struct {
		Node
		Left  BooleanExpr `json:"left"`
		Right BooleanExpr `json:"right"`
	}
	// A LogicalOr node represents a logical or of two subexpressions.
	LogicalOr struct {
		Node
		Left  BooleanExpr `json:"left"`
		Right BooleanExpr `json:"right"`
	}
	// A LogicalNot node represents a logical not of a subexpression.
	LogicalNot struct {
		Node
		Expr BooleanExpr `json:"expr"`
	}
	// A BooleanLiteral node represents the constant true of false.
	BooleanLiteral struct {
		Node
		Value bool `json:"value"`
	}
	// A CompareAny node represents a comparison operator with all of
	// the fields in a record.
	CompareAny struct {
		Node
		Comparator string `json:"comparator"`
		Value      TypedValue
	}
	// A CompareField node represents a comparison operator with a specific
	// field in a record.
	CompareField struct {
		Node
		Comparator string    `json:"comparator"`
		Field      FieldExpr `json:"field"`
		Value      TypedValue
	}
	// A SearchString node represents a string match against the raw
	// record info.
	SearchString struct {
		Node
		Value TypedValue `json:"value"`
	}
)

// booleanEpxrNode() ensures that only boolean expression nodes can be
// assigned to a BooleanExpr.
//
func (e *LogicalAnd) booleanExprNode()     {}
func (e *LogicalOr) booleanExprNode()      {}
func (e *LogicalNot) booleanExprNode()     {}
func (e *BooleanLiteral) booleanExprNode() {}
func (e *CompareAny) booleanExprNode()     {}
func (e *CompareField) booleanExprNode()   {}
func (e *SearchString) booleanExprNode()   {}

// A FieldExpr is any expression that refers to a field.
type (
	// A FieldRead is a direct reference to a particular field.
	FieldRead struct {
		Node
		Field string `json:"field"`
	}

	// A FieldCall is an operation performed on the value in some field,
	// e.g., len(some_set) or some_vector[1].
	FieldCall struct {
		Node
		Fn    string `json:"fn"`
		Field string `json:"field"`
		Param string `json:"param"`
	}
)

func (e *FieldRead) fieldExprNode() {}
func (e *FieldCall) fieldExprNode() {}

// ----------------------------------------------------------------------------
// Procs

// A proc is a node in the flowgraph that takes records in, processes them,
// and produces records as output.
//
type (
	// A SequentialProc node represents a set of procs that receive
	// a stream of records from their parent into the first proc
	// and each subsequent proc processes the output records from the
	// previous proc.
	SequentialProc struct {
		Node
		Procs []Proc `json:"procs"`
	}
	// A ParallelProc node represents a set of procs that each get
	// a stream of records from their parent.
	ParallelProc struct {
		Node
		Procs []Proc `json:"procs"`
	}
	// A SortProc node represents a proc that sorts records.
	SortProc struct {
		Node
		Limit   int      `json:"limit,omitempty"`
		Fields  []string `json:"fields"`
		SortDir int      `json:"sortdir"`
	}
	// A CutProc node represents a proc that removes fields from each
	// input record where each removed field matches one of the named fields
	// sending each such modified record to its output in the order received.
	CutProc struct {
		Node
		Fields []string `json:"fields"`
	}
	// A HeadProc node represents a proc that forwards the indicated number
	// of records then terminates.
	HeadProc struct {
		Node
		Count int `json:"count"`
	}
	// A TailProc node represents a proc that reads all its records from its
	// input transmits the final number of records indicated by the count.
	TailProc struct {
		Node
		Count int `json:"count"`
	}
	// A FilterProc node represents a proc that discards all records that do
	// not match the indicfated filter and forwards all that match to its output.
	FilterProc struct {
		Node
		Filter BooleanExpr `json:"filter"`
	}
	// A PassProc node represents a passthrough proc that mirrors
	// incoming Pull()s on its parent and returns the result.
	PassProc struct {
		Node
	}
	// A UniqProc node represents a proc that discards any record that matches
	// the previous record transmitted.  The Cflag causes the output records
	// to contain a new field called count that contains the number of matched
	// records in that set, similar to the unix shell command uniq.
	UniqProc struct {
		Node
		Cflag bool `json:"cflag"`
	}
	// A ReducerProc node represents a proc that consumes all the records
	// in its input and processes each record with one or more reducers.
	// After all the records have been consumed, the proc generates a single
	// record that contains each reducer's result as a field in that record.
	ReducerProc struct {
		Node
		UpdateInterval Duration  `json:"update_interval"`
		Reducers       []Reducer `json:"reducers"`
	}
	// A GroupByProc node represents a proc that consumes all the records
	// in its input, partitions the records into groups based on the values
	// of the fields specified in the keys paramater, and applies one or
	// more reducers to each group.  If the duration parameter is non-zero,
	// then the groups further partioned by time according to the time interval
	// equal to the duration.  In this case, the proc transmits to its output
	// the reducer results from each time interval as they complete so that
	// large time ranges are processed and streamed efficiently.
	// The limit parameter specifies the number of different groups that can
	// be aggregated over. When absent, the runtime defaults to an appropriate value.
	GroupByProc struct {
		Node
		Duration       Duration  `json:"duration"`
		UpdateInterval Duration  `json:"update_interval"`
		Limit          int       `json:"limit,omitempty"`
		Keys           []string  `json:"keys"`
		Reducers       []Reducer `json:"reducers"`
	}
)

//XXX TBD: chance to nano.Duration
type Duration struct {
	Seconds int
}

type DurationNode struct {
	Type    string `json:"type"`
	Seconds int    `json:"seconds"`
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v DurationNode
	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}
	d.Seconds = v.Seconds
	return err
}

func (p *SequentialProc) ProcNode() {}
func (p *ParallelProc) ProcNode()   {}
func (p *SortProc) ProcNode()       {}
func (p *CutProc) ProcNode()        {}
func (p *HeadProc) ProcNode()       {}
func (p *TailProc) ProcNode()       {}
func (p *PassProc) ProcNode()       {}
func (p *FilterProc) ProcNode()     {}
func (p *UniqProc) ProcNode()       {}
func (p *ReducerProc) ProcNode()    {}
func (p *GroupByProc) ProcNode()    {}

// A Reducer is an AST node that represents any of the boom reducers.  The Op
// parameter indicates the specific reducer while the Field parameter indicates
// which field of the incoming records should be operated upon by the reducer.
// The result is given the field name specified by the Var parameter.
type Reducer struct {
	Node
	Var   string `json:"var"`
	Field string `json:"field,omitempty"`
}