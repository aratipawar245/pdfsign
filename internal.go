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

func istNow() time.Time {
	ist := time.FixedZone("IST", 5*3600+1800)
	return time.Now().In(ist)
}

func addVisibleSignature(input, output string, t time.Time) error {

	text := fmt.Sprintf(
		"Digitally signed by DS CHOICE EQUITY\nBROKING PRIVATE LIMITED\nDate: %s",
		t.Format("02-01-2006 15:04 IST"),
	)

	wm, err := api.TextWatermark(
		text,
		"pos:br,scale:0.45,rot:0,op:1,font:Helvetica,align:left,col:#000000",
		true,
		false,
		types.POINTS,
	)
	if err != nil {
		return fmt.Errorf("watermark creation failed: %w", err)
	}

	if err := api.AddWatermarksFile(input, output, []string{"1"}, wm, nil); err != nil {
		return fmt.Errorf("adding watermark failed: %w", err)
	}

	return nil
}

func loadPFXCertificate(
	pfxPath string,
	password string,
) (*rsa.PrivateKey, *x509.Certificate, error) {

	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read PFX file: %w", err)
	}

	privateKey, cert, _, err := pkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid PFX password or file: %w", err)
	}

	key, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not RSA")
	}

	return key, cert, nil
}

func applyDigitalSignature(
	input string,
	output string,
	key *rsa.PrivateKey,
	cert *x509.Certificate,
	t time.Time,
	signer string,
) error {

	in, err := os.Open(input)
	if err != nil {
		return err
	}
	defer in.Close()

	info, _ := in.Stat()
	reader, _ := pdf.NewReader(in, info.Size())

	out, err := os.Create(output)
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
				Name:   signer,
				Reason: "Digitally Signed",
				Date:   t,
			},
		},
	}

	return sign.Sign(in, out, reader, info.Size(), signData)
}
