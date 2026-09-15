package moroz

import (
	"encoding"

	"github.com/go-kit/kit/log"
)

type Middleware func(Service) Service

// LoggingMiddleware logs one line per service call. Full client payloads
// contain personal data and are only included when logPayloads is set.
func LoggingMiddleware(logger log.Logger, logPayloads bool) Middleware {
	return func(next Service) Service {
		return logmw{logger, logPayloads, next}
	}
}

type logmw struct {
	logger      log.Logger
	logPayloads bool
	next        Service
}

// textOf renders an enum through its MarshalText form for log output.
func textOf(v encoding.TextMarshaler) string {
	text, err := v.MarshalText()
	if err != nil {
		return err.Error()
	}
	return string(text)
}
