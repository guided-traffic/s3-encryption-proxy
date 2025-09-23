### Individual Test Execution

```bash
# Run only the upload test
INTEGRATION_TEST=1 go test -count=1 -v -tags integration ./test/integration/180-degree-variants/ -run TestLargeMultipartUpload500MB

# Run only the download test
INTEGRATION_TEST=1 go test -count=1 -v -tags integration ./test/integration/180-degree-variants/ -run TestLargeMultipartDownload500MB

# Run both tests
INTEGRATION_TEST=1 go test -v ./test/integration/180-degree-variants/
```
