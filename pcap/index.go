package pcap

import (
	"errors"
	"io"
	"sync"

	"github.com/brimsec/zq/pkg/nano"
	"github.com/brimsec/zq/pkg/ranger"
)

type Index struct {
	Sections []Section
}

// Section indicates the seek offset of a pcap section.  For legacy pcaps,
// there is just one section at the beginning of the file.  For nextgen pcaps,
// there can be multiple sections.
type Section struct {
	Blocks []Slice
	Index  ranger.Envelope
}

// CreateIndex creates an index for a legacy pcap file.  If the file isn't
// a legacy pcap file, an error is returned allowing the caller to try reading
// the file as a legacy pcap then revert to nextgen pcap on error.
func CreateIndex(r io.Reader, limit int) (*Index, error) {
	reader, err := NewReader(r)
	if err != nil {
		return nil, err
	}
	var offsets []ranger.Point
	for {
		off := reader.Offset
		data, info, err := reader.ReadPacketData()
		if err != nil {
			return nil, err
		}
		if data == nil {
			break
		}
		ts := nano.TimeToTs(info.Timestamp)
		offsets = append(offsets, ranger.Point{X: off, Y: uint64(ts)})
	}
	n := len(offsets)
	if n == 0 {
		return nil, errors.New("no packets found")
	}
	// legacy pcap file has just the file header at the start of the file
	blocks := []Slice{{0, fileHeaderLen}}
	return &Index{
		Sections: []Section{{
			Blocks: blocks,
			Index:  ranger.NewEnvelope(offsets, limit)},
		},
	}, nil
}

type IndexWriter struct {
	io.WriteCloser
	err error
	idx *Index
	wg  sync.WaitGroup
}

func (w *IndexWriter) run(r *io.PipeReader, limit int) {
	w.idx, w.err = CreateIndex(r, limit)
	if w.err != nil {
		r.CloseWithError(w.err)
	}
	w.wg.Done()
}

func NewIndexWriter(limit int) *IndexWriter {
	pr, pw := io.Pipe()
	i := &IndexWriter{WriteCloser: pw}
	i.wg.Add(1)
	go i.run(pr, limit)
	return i
}

func (w *IndexWriter) Close() (*Index, error) {
	w.WriteCloser.Close()
	w.wg.Wait()
	return w.idx, w.err
}
