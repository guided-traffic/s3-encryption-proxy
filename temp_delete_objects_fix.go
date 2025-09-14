// Temporary file to understand DeleteObjects XML structure
package main

import (
	"encoding/xml"
	"fmt"
)

// DeleteRequest represents the XML structure for bulk delete requests
type DeleteRequest struct {
	XMLName xml.Name `xml:"Delete"`
	Objects []Object `xml:"Object"`
	Quiet   bool     `xml:"Quiet"`
}

// Object represents an object to be deleted
type Object struct {
	Key       string `xml:"Key"`
	VersionId string `xml:"VersionId,omitempty"`
}

func main() {
	// Example XML that S3 expects
	xmlData := `<Delete>
    <Object>
        <Key>object1.txt</Key>
    </Object>
    <Object>
        <Key>object2.txt</Key>
    </Object>
    <Quiet>false</Quiet>
</Delete>`

	var deleteReq DeleteRequest
	err := xml.Unmarshal([]byte(xmlData), &deleteReq)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Parsed: %+v\n", deleteReq)
}
