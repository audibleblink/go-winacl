# Go-WinACL

## Usage

```go
package main

import (
	"fmt"
	"os"
	"github.com/audibleblink/go-winacl"
)

func main() {
	rawNTSD, _ := os.ReadFile("testdata.bin")
	ntsd, _ := winacl.NewNtSecurityDescriptor(rawNTSD)
	fmt.Println(ntsd.ToSDDL())
}
```

## Credit

This repo was forked from https://github.com/rvazarkar/go-winacl, who did the hard work of figuring out the models and parsers.
