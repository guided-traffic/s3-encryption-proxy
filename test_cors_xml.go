package main

import (
	"encoding/xml"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func main() {
	// Test basic CORS XML structure
	corsXML := `<CORSConfiguration>
		<CORSRule>
			<AllowedOrigin>*</AllowedOrigin>
			<AllowedMethod>GET</AllowedMethod>
		</CORSRule>
	</CORSConfiguration>`

	var corsConfig types.CORSConfiguration
	err := xml.Unmarshal([]byte(corsXML), &corsConfig)
	if err != nil {
		fmt.Printf("Error parsing CORS XML: %v\n", err)
	} else {
		fmt.Printf("Successfully parsed CORS config with %d rules\n", len(corsConfig.CORSRules))
		if len(corsConfig.CORSRules) > 0 {
			rule := corsConfig.CORSRules[0]
			fmt.Printf("Rule 0: Origins=%v, Methods=%v\n", rule.AllowedOrigins, rule.AllowedMethods)
		}
	}
}
