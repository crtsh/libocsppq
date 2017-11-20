package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io"
	"net/http"
)

func Ocsp_check(b64_cert string, b64_issuer string) string {
	der_cert, err := base64.StdEncoding.DecodeString(b64_cert)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	cert, err := x509.ParseCertificate(der_cert)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}

	der_issuer, err := base64.StdEncoding.DecodeString(b64_issuer)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	issuer, err := x509.ParseCertificate(der_issuer)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}

	if len(cert.OCSPServer) == 0 {
		return "No OCSP URL available"
	}

	ocsp_req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	req, err := http.NewRequest("POST", cert.OCSPServer[0], bytes.NewReader(ocsp_req))
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	http_client := &http.Client{}
	resp, err := http_client.Do(req)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	defer resp.Body.Close()

	buf := new(bytes.Buffer)
	io.Copy(buf, resp.Body)

	ocsp_resp, err := ocsp.ParseResponse(buf.Bytes(), issuer)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}

	if ocsp_resp.Status == ocsp.Good {
		return "Good"
	} else if ocsp_resp.Status == ocsp.Unknown {
		return "Unknown"
	} else {
		return fmt.Sprintf("Revoked|%v|%d", ocsp_resp.RevokedAt, ocsp_resp.RevocationReason)
	}
}
