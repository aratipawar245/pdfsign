package signer

import "os"

// SignPDF is the only public function exposed by this library.
// It adds visible text + digitally signs the PDF.
func SignPDF(
	inputPDF string,
	outputPDF string,
	pfxPath string,
	pfxPassword string,
	signerName string,
) error {

	signTime := istNow()

	// Temporary file for visible signature
	tempPDF := inputPDF + ".visible.pdf"
	defer os.Remove(tempPDF)

	// 1. Add visible signature text
	if err := addVisibleSignature(inputPDF, tempPDF, signTime, signerName); err != nil {
		return err
	}

	// 2. Load certificate
	key, cert, err := loadPFXCertificate(pfxPath, pfxPassword)
	if err != nil {
		return err
	}

	// 3. Apply digital signature
	return applyDigitalSignature(tempPDF, outputPDF, key, cert, signTime, signerName)
}
