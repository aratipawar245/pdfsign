package signer

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/sign"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
	"software.sslmate.com/src/go-pkcs12"
)

func SignPDF(
	inputPDF string,
	outputPDF string,
	pfxPath string,
	pfxPassword string,
	visibleText string,
	signTime time.Time,
) error {

	// ---------- 1. Add visible watermark ----------
	tempPDF := inputPDF + ".visible.pdf"

	wm, err := api.TextWatermark(
		visibleText,
		"pos:br,scale:0.45,rot:0,op:1,font:Helvetica,align:left,col:#000000",
		true,
		false,
		types.POINTS,
	)
	if err != nil {
		return err
	}

	if err := api.AddWatermarksFile(inputPDF, tempPDF, []string{"1"}, wm, nil); err != nil {
		return err
	}
	defer os.Remove(tempPDF)

	// ---------- 2. Load PFX certificate ----------
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		return err
	}

	blocks, err := pkcs12.ToPEM(pfxData, pfxPassword)
	if err != nil {
		return err
	}

	var key *rsa.PrivateKey
	var cert *x509.Certificate

	for _, b := range blocks {
		switch b.Type {
		case "PRIVATE KEY", "RSA PRIVATE KEY":
			if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
				key = k.(*rsa.PrivateKey)
			} else if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
				key = k
			}
		case "CERTIFICATE":
			if c, err := x509.ParseCertificate(b.Bytes); err == nil {
				cert = c
			}
		}
	}

	if key == nil || cert == nil {
		return fmt.Errorf("private key or certificate not found in PFX")
	}

	// ---------- 3. Digitally sign PDF ----------
	in, err := os.Open(tempPDF)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}

	reader, err := pdf.NewReader(in, info.Size())
	if err != nil {
		return err
	}

	out, err := os.Create(outputPDF)
	if err != nil {
		return err
	}
	defer out.Close()

	signData := sign.SignData{
		Signer:          key,
		Certificate:     cert,
		DigestAlgorithm: crypto.SHA256,
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Reason: "Digitally Signed",
				Date:   signTime,
			},
		},
	}

	return sign.Sign(in, out, reader, info.Size(), signData)
}
