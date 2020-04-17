// Package ztest runs formulaic tests ("ztests") that apply a ZQL query to an
// input and check for an expected output.
//
// A ztest is defined in a YAML file.
//
//    zql: count()
//
//    input: |
//      #0:record[i:int64]
//      0:[1;]
//      0:[2;]
//
//    output: |
//      #0:record[count:uint64]
//      0:[2;]
//
// Input format is detected automatically and can be anything recognized by
// "zq -i auto" (including optional gzip compression).  Output format defaults
// to zng but can be set to anything accepted by "zq -f".
//
//    zql: count()
//
//    input: |
//      #0:record[i:int64]
//      0:[1;]
//      0:[2;]
//
//    output-format: table
//
//    output: |
//      COUNT
//      2
//
// In the "shell" variation, arbitrary bash scripts can run chaining together
// any of zq/cmd tools in addition to zq.  Here, the yaml sets up a collection
// of input files and stdin, the script runs, and the test driver compares expected
// output files, stdout, and stderr with data in the yaml spec.  In this case,
// instead of specifying, "zql", "input", "output", you specify the yaml arrays
// "inputs" and "outputs" --- where each array element defines a file, stdin,
// stdout, or stderr --- and a "script" that specifies a multi-line yaml string
// defining the script, e.g.,
//
// inputs:
//    - name: in1.zng
//      data: |
//         #0:record[i:int64]
//         0:[1;]
//    - name: stdin
//      data: |
//         #0:record[i:int64]
//         0:[2;]
// script: |
//    zq -o out.zng in1.zng -
//    zq -o count.zng "count()" out.zng
// outputs:
//    - name: out.zng
//      data: |
//         #0:record[i:int64]
//         0:[1;]
//         0:[2;]
//    - name: count.zng
//      data: |
//         #0:record[count:uint64]
//         0:[2;]
//
// Ztest YAML files for a package should reside in a subdirectory named
// testdata/ztest.
//
//     pkg/
//       pkg.go
//       pkg_test.go
//       testdata/
//         ztest/
//           test-1.yaml
//           test-2.yaml
//           ...
//
// Name YAML files descriptively since each ztest runs as a subtest
// named for the file that defines it.
//
// pkg_test.go should contain a Go test named TestZTest that calls Run.
//
//     func TestZTest(t *testing.T) { ztest.Run(t, "testdata/ztest") }
//
// If the ZTEST_ZQ environment variable is unset or empty and the test
// is not a script test, Run runs ztests in
// the current process.  Otherwise, Run runs each ztest in a separate process
// using the zq executable specified by ZTEST_ZQ.
package ztest

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/brimsec/zq/driver"
	"github.com/brimsec/zq/emitter"
	"github.com/brimsec/zq/pkg/nano"
	"github.com/brimsec/zq/scanner"
	"github.com/brimsec/zq/zbuf"
	"github.com/brimsec/zq/zio"
	"github.com/brimsec/zq/zio/detector"
	"github.com/brimsec/zq/zng/resolver"
	"github.com/brimsec/zq/zql"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Run runs the ztests in the directory named dirname.  For each file f.yaml in
// the directory, Run calls FromYAMLFile to load a ztest and then runs it in
// subtest named f.
func Run(t *testing.T, dirname string) {
	zq := os.Getenv("ZTEST_ZQ")
	if zq != "" {
		if out, _, err := runzq(zq, "help", "", ""); err != nil {
			if out != "" {
				out = fmt.Sprintf(" with output %q", out)
			}
			t.Fatalf("bad ZTEST_ZQ value %s: %s%s", zq, err, out)
		}
	}
	fileinfos, err := ioutil.ReadDir(dirname)
	if err != nil {
		t.Fatal(err)
	}
	for _, fi := range fileinfos {
		filename := fi.Name()
		const dotyaml = ".yaml"
		if !strings.HasSuffix(filename, dotyaml) {
			continue
		}
		t.Run(strings.TrimSuffix(filename, dotyaml), func(t *testing.T) {
			t.Parallel()
			// An absolute path in errors makes the offending file easier to find.
			filename, err := filepath.Abs(filepath.Join(dirname, filename))
			if err != nil {
				t.Fatal(err)
			}
			zt, err := FromYAMLFile(filename)
			if err != nil {
				t.Fatalf("%s: %s", filename, err)
			}
			run(t, filename, zq, zt)
		})
	}
}

type File struct {
	Name   string `yaml:"name"`
	Data   Inputs `yaml:"data,omitempty"`
	Hex    string `yaml:"hex,omitempty"`
	Source string `yaml:"source,omitempty"`
}

func (f *File) check() error {
	cnt := 0
	if f.Data != nil {
		cnt++
	}
	if f.Hex != "" {
		cnt++
	}
	if f.Source != "" {
		cnt++
	}
	if cnt != 1 {
		return fmt.Errorf("%s: must specify exactly one of data, hex, or source", f.Name)
	}
	return nil
}

// ZTest defines a ztest.
type ZTest struct {
	ZQL          string `yaml:"zql,omitempty"`
	Input        Inputs `yaml:"input,omitempty"`
	OutputFormat string `yaml:"output-format,omitempty"`
	Output       string `yaml:"output,omitempty"`
	OutputHex    string `yaml:"outputHex,omitempty"`
	OutputFlags  string `yaml:"output-flags,omitempty"`
	ErrorRE      string `yaml:"errorRE"`
	errRegex     *regexp.Regexp
	Warnings     string `yaml:"warnings",omitempty"`
	// shell mode params
	Script  string `yaml:"script,omitempty"`
	Inputs  []File `yaml:"inputs,omitempty"`
	Outputs []File `yaml:"outputs,omitempty"`
}

func (z *ZTest) check() error {
	if z.ZQL != "" {
		if z.Input == nil {
			return errors.New("missing input field")
		}
	} else if z.Script != "" {
		if z.Outputs == nil {
			return errors.New("missing outputs field script mode")
		}
		for _, f := range z.Inputs {
			if err := f.check(); err != nil {
				return err
			}
		}
		for _, f := range z.Outputs {
			if err := f.check(); err != nil {
				return err
			}
		}
	} else {
		return errors.New("a zql or script field must be defined")
	}
	return nil
}

// Inputs is an array of strings. Its only purpose is to support parsing of
// both single string and array yaml values for the field ZTest.Input.
type Inputs []string

func (i *Inputs) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.SequenceNode {
		var inputs []string
		err := value.Decode(&inputs)
		*i = inputs
		return err
	}
	var input string
	if err := value.Decode(&input); err != nil {
		return err
	}
	*i = append(*i, input)
	return nil
}

// Try to decode a yaml-friendly way of representing binary data in hex:
// each line is either a comment explaining the contents (denoted with
// a leading # character), or a sequence of hex digits.
func decodeHex(in string) (string, error) {
	var raw string
	for _, line := range strings.Split(in, "\n") {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		raw += strings.ReplaceAll(line, " ", "")
	}
	out := make([]byte, hex.DecodedLen(len(raw)))
	_, err := hex.Decode(out, []byte(raw))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func encodeHex(in string) string {
	var buf bytes.Buffer
	dumper := hex.Dumper(&buf)
	dumper.Write([]byte(in))
	return buf.String()
}

func (z *ZTest) getOutput() (string, error) {
	outlen := len(z.Output)
	hexlen := len(z.OutputHex)
	if outlen > 0 && hexlen > 0 {
		return "", errors.New("Cannot specify both output and outputHex")
	}
	if outlen == 0 && hexlen == 0 {
		return "", nil
	}
	if outlen > 0 {
		return z.Output, nil
	}
	return decodeHex(z.OutputHex)
}

// FromYAMLFile loads a ZTest from the YAML file named filename.
func FromYAMLFile(filename string) (*ZTest, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	d := yaml.NewDecoder(bytes.NewReader(buf))
	d.KnownFields(true)
	var z ZTest
	if err := d.Decode(&z); err != nil {
		return nil, err
	}
	var v interface{}
	if d.Decode(&v) != io.EOF {
		return nil, errors.New("found multiple YAML documents or garbage after first document")
	}
	if z.OutputFormat == "" {
		z.OutputFormat = "zng"
	}
	if z.ErrorRE != "" {
		z.errRegex, err = regexp.Compile(z.ErrorRE)
		if err != nil {
			return nil, err
		}
	}
	return &z, nil
}

func run(t *testing.T, filename, zq string, zt *ZTest) {
	if err := zt.check(); err != nil {
		t.Fatalf("%s: bad yaml format: %s", filename, err)
	}
	out, errout, err := runzq(zq, zt.ZQL, zt.OutputFormat, zt.OutputFlags, zt.Input...)
	if err != nil {
		if zt.errRegex != nil {
			if !zt.errRegex.Match([]byte(errout)) {
				t.Fatalf("%s: error doesn't match expected error regex: %s %s", filename, zt.ErrorRE, errout)
			}
		} else {
			if out != "" {
				out = "\noutput:\n" + out
			}
			t.Fatalf("%s: %s%s", filename, err, out)
		}
	} else if zt.errRegex != nil {
		t.Fatalf("%s: no error when expecting error regex: %s", filename, zt.ErrorRE)
	}
	expectedOut, oerr := zt.getOutput()
	require.NoError(t, oerr)
	if out != expectedOut {
		a := expectedOut
		b := out

		if !utf8.ValidString(a) {
			a = encodeHex(a)
			b = encodeHex(b)
		}

		diff, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
			A:        difflib.SplitLines(a),
			FromFile: "expected",
			B:        difflib.SplitLines(b),
			ToFile:   "actual",
			Context:  5,
		})
		t.Fatalf("%s: expected and actual outputs differ:\n%s", filename, diff)
	}
	if err == nil && errout != zt.Warnings {
		diff, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
			A:        difflib.SplitLines(zt.Warnings),
			FromFile: "expected",
			B:        difflib.SplitLines(errout),
			ToFile:   "actual",
			Context:  5,
		})
		t.Fatalf("%s: expected and actual warnings differ:\n%s", filename, diff)
	}
}

// Run runs the query in ZQL over inputs and returns the output formatted
// according to outputFormat. inputs may be in any format recognized by "zq -i
// auto" and maybe be gzip-compressed.  outputFormat may be any string accepted
// by "zq -f".  If zq is empty, the query runs in the current process.  If zq is
// not empty, it specifies a zq executable that will be used to run the query.
func runzq(zq, ZQL, outputFormat, outputFlags string, inputs ...string) (out string, warnOrError string, err error) {
	var outbuf bytes.Buffer
	var errbuf bytes.Buffer
	if zq != "" {
		tmpdir, files, err := tmpInputFiles(inputs)
		if err != nil {
			return "", "", err
		}
		defer os.RemoveAll(tmpdir)
		cmd := exec.Command(zq, "-f", outputFormat)
		if len(outputFlags) > 0 {
			flags := strings.Split(outputFlags, " ")
			cmd.Args = append(cmd.Args, flags...)
		}
		cmd.Args = append(cmd.Args, ZQL)
		cmd.Args = append(cmd.Args, files...)
		cmd.Stdout = &outbuf
		cmd.Stderr = &errbuf
		err = cmd.Run()
		// If there was an error, errbuf could potentially hold both warnings
		// and error messages, but that's not currently an issue with existing
		// tests.
		return string(outbuf.Bytes()), string(errbuf.Bytes()), err
	}
	proc, err := zql.ParseProc(ZQL)
	if err != nil {
		return "", "", err
	}
	zctx := resolver.NewContext()
	zr, err := loadInputs(inputs, zctx)
	if err != nil {
		return "", "", err
	}
	defer zr.Close()
	if outputFormat == "types" {
		outputFormat = "null"
		zctx.SetLogger(&emitter.TypeLogger{WriteCloser: &nopCloser{&outbuf}})
	}
	muxOutput, err := driver.Compile(context.Background(), proc, zr, false, nano.MaxSpan, zap.NewNop())
	if err != nil {
		return "", "", err
	}
	var flags flag.FlagSet
	var zflags zio.Flags
	zflags.SetFlags(&flags)
	err = flags.Parse(strings.Split(outputFlags, " "))
	if err != nil {
		return "", "", err
	}
	zw := detector.LookupWriter(outputFormat, &nopCloser{&outbuf}, &zflags)
	if zw == nil {
		return "", "", fmt.Errorf("%s: unknown output format", outputFormat)
	}
	d := driver.NewCLI(zw)
	d.SetWarningsWriter(&errbuf)
	err = driver.Run(muxOutput, d, 0)
	if err2 := zw.Flush(); err == nil {
		err = err2
	}
	if err != nil {
		return string(outbuf.Bytes()), err.Error(), err
	}
	return string(outbuf.Bytes()), string(errbuf.Bytes()), nil
}

func loadInputs(inputs []string, zctx *resolver.Context) (*scanner.Combiner, error) {
	var readers []zbuf.Reader
	for _, input := range inputs {
		zr, err := detector.NewReader(detector.GzipReader(strings.NewReader(input)), zctx)
		if err != nil {
			return nil, err
		}
		readers = append(readers, zr)
	}
	return scanner.NewCombiner(readers), nil
}

func tmpInputFiles(inputs []string) (string, []string, error) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		return "", nil, err
	}
	var files []string
	for i, input := range inputs {
		name := fmt.Sprintf("input%d", i+1)
		file := filepath.Join(dir, name)
		err := ioutil.WriteFile(file, []byte(input), 0644)
		if err != nil {
			os.RemoveAll(dir)
			return "", nil, err
		}
		files = append(files, file)
	}
	return dir, files, nil
}

type nopCloser struct{ io.Writer }

func (*nopCloser) Close() error { return nil }
