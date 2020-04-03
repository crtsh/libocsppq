/* libocsppq - perform OCSP checks from a PostgreSQL function
 * Written by Rob Stradling
 * Copyright (C) 2017-2020 Sectigo Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"
)

func do_ocsp(ocsp_req_bytes []byte, ocsp_url string, issuer *x509.Certificate) string {
	req, err := http.NewRequest("POST", ocsp_url, bytes.NewReader(ocsp_req_bytes))
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Connection", "close")
	http_client := &http.Client{Timeout: time.Second * 30}
	resp, err := http_client.Do(req)
	if err != nil && resp == nil {
		return fmt.Sprintf("%v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}

	ocsp_resp, err := ocsp.ParseResponse(body, issuer)
	if err != nil {
		if resp.StatusCode != 200 {
			return fmt.Sprintf("HTTP %d", resp.StatusCode);
		} else {
			return fmt.Sprintf("%v", err)
		}
	}

	if ocsp_resp.Status == ocsp.Good {
		return "Good"
	} else if ocsp_resp.Status == ocsp.Unknown {
		return "Unknown"
	} else {
		return fmt.Sprintf("Revoked|%v|%d", ocsp_resp.RevokedAt, ocsp_resp.RevocationReason)
	}
}

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

	return do_ocsp(ocsp_req, cert.OCSPServer[0], issuer)
}

func Ocsp_randomserial_check(b64_issuer string, ocsp_url string) string {
	der_issuer, err := base64.StdEncoding.DecodeString(b64_issuer)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	issuer, err := x509.ParseCertificate(der_issuer)
	if err != nil {
		return fmt.Sprintf("%v", err)
	}

	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return fmt.Sprintf("%v", err)
	}

	var ocsp_req ocsp.Request
	ocsp_req.HashAlgorithm = crypto.Hash(crypto.SHA1)
	h := ocsp_req.HashAlgorithm.New()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	ocsp_req.IssuerKeyHash = h.Sum(nil)

	h.Reset()
	h.Write(issuer.RawSubject)
	ocsp_req.IssuerNameHash = h.Sum(nil)

	random_serial := [20]byte{}
	copy(random_serial[:], "crt.sh")
	_, err = rand.Read(random_serial[6:])
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	ocsp_req.SerialNumber = big.NewInt(0)
	ocsp_req.SerialNumber.SetBytes(random_serial[:])

	ocsp_req_bytes, err := ocsp_req.Marshal()
	if err != nil {
		return fmt.Sprintf("%v", err)
	}

	return do_ocsp(ocsp_req_bytes, ocsp_url, issuer)
}
