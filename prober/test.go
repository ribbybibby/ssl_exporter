package prober

import (
	"os"

	"github.com/go-kit/log"
)

func newTestLogger() log.Logger {
	return log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
}
