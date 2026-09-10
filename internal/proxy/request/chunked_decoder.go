package request

import (
	"github.com/sirupsen/logrus"
)

// ChunkedDecoderBase provides common functionality for chunked decoders
type ChunkedDecoderBase struct {
	logger *logrus.Entry
}

// NewChunkedDecoderBase creates a new base decoder
func NewChunkedDecoderBase(logger *logrus.Entry) *ChunkedDecoderBase {
	return &ChunkedDecoderBase{
		logger: logger,
	}
}
