// Package search provides an implementation for launching zq searches and performing
// analytics on bzng files stored in the server's root directory.
package search

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/brimsec/zq/ast"
	"github.com/brimsec/zq/driver"
	"github.com/brimsec/zq/pkg/nano"
	"github.com/brimsec/zq/scanner"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/zqd/api"
	"github.com/brimsec/zq/zqd/space"
	"go.uber.org/zap"
)

// This mtu is pretty small but it keeps the JSON object size below 64kb or so
// so the recevier can do reasonable, interactive streaming updates.
const DefaultMTU = 100

const StatsInterval = time.Millisecond * 500

type Search struct {
	mux *driver.MuxOutput
	io.Closer
}

func NewSearch(ctx context.Context, s *space.Space, req api.SearchRequest) (*Search, error) {
	if req.Span.Ts < 0 {
		return nil, errors.New("time span must have non-negative timestamp")
	}
	if req.Span.Dur < 0 {
		return nil, errors.New("time span must have non-negative duration")
	}
	// XXX allow either direction even through we do forward only right now
	if req.Dir != 1 && req.Dir != -1 {
		return nil, errors.New("time direction must be 1 or -1")
	}
	query, err := UnpackQuery(req)
	if err != nil {
		return nil, err
	}

	zngReader, err := s.OpenZng(query.Span)
	if err != nil {
		return nil, err
	}
	zctx := resolver.NewContext()
	mapper := scanner.NewMapper(zngReader, zctx)
	mux, err := launch(ctx, query, mapper, zctx)
	if err != nil {
		zngReader.Close()
		return nil, err
	}
	return &Search{mux, zngReader}, nil
}

func (s *Search) Run(output Output) error {
	d := &searchdriver{
		output:    output,
		startTime: nano.Now(),
	}
	d.start(0)
	if err := driver.Run(s.mux, d, StatsInterval); err != nil {
		d.abort(0, err)
		return err
	}
	return d.end(0)
}

type Output interface {
	SendBatch(int, zbuf.Batch) error
	SendControl(interface{}) error
	End(interface{}) error
}

// A Query is the internal representation of search query describing a source
// of tuples, a "search" applied to the tuples producing a set of matched
// tuples, and a proc to the process the tuples
type Query struct {
	Space string
	Dir   int
	Span  nano.Span
	Proc  ast.Proc
}

// UnpackQuery transforms a api.SearchRequest into a Query.
func UnpackQuery(req api.SearchRequest) (*Query, error) {
	proc, err := ast.UnpackProc(nil, req.Proc)
	if err != nil {
		return nil, err
	}
	return &Query{
		Space: req.Space,
		Dir:   req.Dir,
		Span:  req.Span,
		Proc:  proc,
	}, nil
}

// searchdriver implements driver.Driver.
type searchdriver struct {
	output    Output
	startTime nano.Ts
}

func (d *searchdriver) start(id int64) error {
	return d.output.SendControl(&api.TaskStart{"TaskStart", id})
}

func (d *searchdriver) end(id int64) error {
	return d.output.End(&api.TaskEnd{"TaskEnd", id, nil})
}

func (d *searchdriver) abort(id int64, err error) error {
	verr := &api.Error{Type: "INTERNAL", Message: err.Error()}
	return d.output.SendControl(&api.TaskEnd{"TaskEnd", id, verr})
}

func (d *searchdriver) Warn(warning string) error {
	v := api.SearchWarning{
		Type:    "SearchWarning",
		Warning: warning,
	}
	return d.output.SendControl(v)
}

func (d *searchdriver) Write(cid int, batch zbuf.Batch) error {
	return d.output.SendBatch(cid, batch)
}

func (d *searchdriver) Stats(stats api.ScannerStats) error {
	v := api.SearchStats{
		Type:         "SearchStats",
		StartTime:    d.startTime,
		UpdateTime:   nano.Now(),
		ScannerStats: stats,
	}
	return d.output.SendControl(v)
}

func (d *searchdriver) ChannelEnd(cid int, stats api.ScannerStats) error {
	if err := d.Stats(stats); err != nil {
		return err
	}
	v := &api.SearchEnd{
		Type:      "SearchEnd",
		ChannelID: cid,
		Reason:    "eof",
	}
	return d.output.SendControl(v)
}

func launch(ctx context.Context, query *Query, reader zbuf.Reader, zctx *resolver.Context) (*driver.MuxOutput, error) {
	span := query.Span
	if span == (nano.Span{}) {
		span = nano.MaxSpan
	}
	reverse := query.Dir < 0
	return driver.Compile(context.Background(), query.Proc, reader, reverse, span, zap.NewNop())
}
