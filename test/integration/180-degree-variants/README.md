### Individual Test Execution

```bash
# Run only the upload test
go test -count=1 -v -tags integration ./test/integration/180-degree-variants/ -run TestLargeMultipartUpload500MB

# Run only the download test
go test -count=1 -v -tags integration ./test/integration/180-degree-variants/ -run TestLargeMultipartDownload500MB

# Run both tests
go test -v -tags integration ./test/integration/180-degree-variants/
```
