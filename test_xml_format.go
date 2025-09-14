package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func main() {
	// Create a sample ListBucketsOutput
	output := &s3.ListBucketsOutput{
		Buckets: []types.Bucket{
			{
				Name:         &[]string{"bucket1"}[0],
				CreationDate: &[]time.Time{time.Now()}[0],
			},
			{
				Name:         &[]string{"bucket2"}[0],
				CreationDate: &[]time.Time{time.Now()}[0],
			},
		},
		Owner: &types.Owner{
			DisplayName: &[]string{"test"}[0],
			ID:          &[]string{"12345"}[0],
		},
	}

	// Marshal to XML to see the expected format
	xmlData, err := xml.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("AWS SDK ListBucketsOutput XML:\n%s\n", xmlData)
}
