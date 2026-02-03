# pdfsigner

`pdfsigner` is a Go library for digitally signing PDF documents using PFX certificates.  
It adds a visible watermark and creates a cryptographically signed PDF.

---

## Features

- Add visible text watermark
- Load PFX (PKCS#12) certificate
- Digitally sign PDF using SHA256
- Pure Go library (no HTTP, no main function)
- Reusable in any Go project (API, CLI, background jobs)

---

## Installation

```bash
go get github.com/aratipawar245/pdfsigner


## Usage 

package main

import (
    "github.com/aratipawar245/pdfsigner"
    "time"
    "log"
)

func main() 
{
    err := signer.SignPDF(
        "input.pdf",                 // Input PDF path
        "signed.pdf",                // Output signed PDF path
        "cert.pfx",                  // PFX certificate path
        "pfx-password",              // PFX password
        "Digitally signed by ACME",  // Visible watermark text
        time.Now(),                  // Signing date/time
    )
    if err != nil 
    {
        log.Fatal(err)
    }
    log.Println("PDF signed successfully!")
}

## Function Signature

func SignPDF(
    inputPDF string,
    outputPDF string,
    pfxPath string,
    pfxPassword string,
    visibleText string,
    signTime time.Time,
) error

Parameters:

inputPDF – path to the PDF file to sign

outputPDF – path to save the signed PDF

pfxPath – path to the PFX certificate file

pfxPassword – password for the PFX certificate

visibleText – text to add as a visible watermark

signTime – time of signature

Returns:
error if signing fails, nil on success

