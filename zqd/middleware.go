package zqd

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

const requestIDKey = "X-Request-ID"

func getRequestID(ctx context.Context) string {
	if v := ctx.Value(requestIDKey); v != nil {
		return v.(string)
	}
	return ""
}

// requestIDMiddleware adds the unique identifier of the request to the request
// context. If the header "X-Request-ID" exists this will be used, otherwise
// one will be generated.
func requestIDMiddleware() mux.MiddlewareFunc {
	var count int64
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := r.Header.Get(requestIDKey)
			if reqID == "" {
				reqID = strconv.FormatInt(atomic.AddInt64(&count, 1), 10)
			}
			w.Header().Add(requestIDKey, reqID)
			ctx := context.WithValue(r.Context(), requestIDKey, reqID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func accessLogMiddleware(logger *zap.Logger) mux.MiddlewareFunc {
	logger = logger.Named("http.access")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := logger.With(zap.String("request_id", getRequestID(r.Context())))
			detailedLogger := logger.With(
				zap.String("host", r.Host),
				zap.String("method", r.Method),
				zap.String("proto", r.Proto),
				zap.String("remote_addr", r.RemoteAddr),
				zap.Int64("request_content_length", r.ContentLength),
				zap.Stringer("url", r.URL),
			)
			recorder := newRecordingResponseWriter(w)
			w = recorder
			detailedLogger.Debug("Request started")
			defer func(start time.Time) {
				detailedLogger.Info("Request completed",
					zap.Duration("elapsed", time.Since(start)),
					zap.Int("response_content_length", recorder.contentLength),
					zap.Int("status_code", recorder.statusCode),
				)
			}(time.Now())

			next.ServeHTTP(w, r)
		})
	}
}

func panicCatchMiddleware(logger *zap.Logger) mux.MiddlewareFunc {
	logger = logger.Named("zqd")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				r := recover()
				if r == nil {
					return
				}
				rstr := fmt.Sprint(r)
				logger.DPanic("panic", zap.String("error", rstr))
				http.Error(w, rstr, http.StatusInternalServerError)
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// recordingResponseWriter wraps an http.ResponseWriter to record the content
// length and status code of the response.
type recordingResponseWriter struct {
	http.ResponseWriter
	contentLength int
	statusCode    int
}

func newRecordingResponseWriter(w http.ResponseWriter) *recordingResponseWriter {
	return &recordingResponseWriter{
		ResponseWriter: w,
		statusCode:     200, // Default status code is 200.
	}
}

func (r *recordingResponseWriter) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *recordingResponseWriter) Write(data []byte) (int, error) {
	r.contentLength += len(data)
	return r.ResponseWriter.Write(data)
}

func (r *recordingResponseWriter) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}
