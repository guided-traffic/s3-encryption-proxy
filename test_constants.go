package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func main() {
	fmt.Printf("BucketCannedACLPrivate: %s\n", types.BucketCannedACLPrivate)
	fmt.Printf("BucketCannedACLPublicRead: %s\n", types.BucketCannedACLPublicRead)
	fmt.Printf("BucketCannedACLPublicReadWrite: %s\n", types.BucketCannedACLPublicReadWrite)
	fmt.Printf("BucketCannedACLAuthenticatedRead: %s\n", types.BucketCannedACLAuthenticatedRead)
}
