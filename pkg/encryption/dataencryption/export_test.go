package dataencryption

// The raw segment atoms are unexported so that no caller can seal a short middle
// segment — an object that writes cleanly and never reads. The tamper tests need
// them.

func (c *Codec) SealSegmentForTest(dst, plaintext []byte, index uint64) ([]byte, error) {
	return c.sealSegment(dst, plaintext, index)
}

func (c *Codec) OpenSegmentForTest(dst, sealed []byte, index uint64) ([]byte, error) {
	return c.openSegment(dst, sealed, index)
}

func (c *Codec) AADForTest(index uint64) []byte { return c.aad(index) }

const TrailerIndexForTest = trailerIndex

func (c *Codec) SealTrailerForTest(sum Checksum) ([]byte, error) {
	return c.sealTrailer(nil, sum)
}
