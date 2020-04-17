package detector

import (
	"fmt"
	"io"

	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zio/bzngio"
	"github.com/brimsec/zq/zio/ndjsonio"
	"github.com/brimsec/zq/zio/zeekio"
	"github.com/brimsec/zq/zio/zjsonio"
	"github.com/brimsec/zq/zio/zngio"
	"github.com/brimsec/zq/zng/resolver"
)

func NewReader(r io.Reader, zctx *resolver.Context) (zbuf.Reader, error) {
	recorder := NewRecorder(r)
	track := NewTrack(recorder)

	var zngErr, zeekErr, ndjsonErr, zjsonErr, bzngErr error

	zngErr = match(zngio.NewReader(track, resolver.NewContext()))
	if zngErr == nil {
		return zngio.NewReader(recorder, zctx), nil
	}
	track.Reset()

	zr, err := zeekio.NewReader(track, resolver.NewContext())
	if err != nil {
		return nil, err
	}

	zeekErr = match(zr)
	if zeekErr == nil {
		return zeekio.NewReader(recorder, zctx)
	}
	track.Reset()

	// zjson must come before ndjson since zjson is a subset of ndjson
	zjsonErr = match(zjsonio.NewReader(track, resolver.NewContext()))
	if zjsonErr == nil {
		return zjsonio.NewReader(recorder, zctx), nil
	}
	track.Reset()

	// ndjson must come after zjson since zjson is a subset of ndjson
	nr, err := ndjsonio.NewReader(track, resolver.NewContext())
	if err != nil {
		return nil, err
	}
	ndjsonErr = match(nr)
	if ndjsonErr == nil {
		return ndjsonio.NewReader(recorder, zctx)
	}
	track.Reset()

	bzngErr = match(bzngio.NewReader(track, resolver.NewContext()))
	if bzngErr == nil {
		return bzngio.NewReader(recorder, zctx), nil
	}
	return nil, joinErrs([]error{zngErr, zeekErr, ndjsonErr, zjsonErr, bzngErr})
}

func joinErrs(errs []error) error {
	var s string
	for _, e := range errs {
		s += "\n" + e.Error()
	}
	return fmt.Errorf(s)
}
func match(r zbuf.Reader) error {
	_, err := r.Read()
	return err
}
