package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// RFC 3161 timestamp services. Each returns a receipt signed by the service,
// stating the time at which it saw a given fingerprint. Receipts can be
// checked with the free program openssl ("openssl ts -verify").
type tsaService struct{ Name, URL string }

var tsaServices = []tsaService{
	{"freetsa.org", "https://freetsa.org/tsr"},
	{"DigiCert", "http://timestamp.digicert.com"},
}

// OpenTimestamps calendars. A calendar collects fingerprints and records
// them in the Bitcoin blockchain within a few hours, so the receipt does not
// depend on any single organisation continuing to exist. One is enough;
// the others are used only when the first does not answer.
var otsCalendars = []string{
	"https://alice.btc.calendar.opentimestamps.org",
	"https://bob.btc.calendar.opentimestamps.org",
	"https://finney.calendar.eternitywall.com",
}

var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	Nonce          *big.Int
	CertReq        bool `asn1:"optional"`
}

// requestTimestamp asks an RFC 3161 service to timestamp a SHA-256
// fingerprint. withCerts asks the service to include its certificates in the
// receipt, so it can be checked later without fetching them elsewhere.
func requestTimestamp(url string, digest []byte, withCerts bool) ([]byte, time.Time, error) {
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, time.Time{}, err
	}
	der, err := asn1.Marshal(timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
			HashedMessage: digest,
		},
		Nonce:   nonce,
		CertReq: withCerts,
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(der))
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, time.Time{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("answered with status %d", resp.StatusCode)
	}
	gen, err := checkTimestampReply(body, digest, nonce)
	if err != nil {
		return nil, time.Time{}, err
	}
	return body, gen, nil
}

// checkTimestampReply confirms that the receipt was granted, covers the
// fingerprint that was sent and answers this request, and returns the time
// it states. Checking the signature is left to the verifier.
func checkTimestampReply(reply, digest []byte, nonce *big.Int) (time.Time, error) {
	var zero time.Time
	bad := func(what string) (time.Time, error) {
		return zero, fmt.Errorf("the receipt could not be read (%s)", what)
	}
	top, err := derSequence(reply)
	if err != nil || len(top) < 1 {
		return bad("outer structure")
	}
	status, err := derSequence(top[0].FullBytes)
	if err != nil || len(status) < 1 {
		return bad("status")
	}
	var code int
	if _, err := asn1.Unmarshal(status[0].FullBytes, &code); err != nil {
		return bad("status code")
	}
	if code != 0 && code != 1 {
		return zero, fmt.Errorf("the service refused the request (status %d)", code)
	}
	if len(top) < 2 {
		return bad("no timestamp token")
	}
	contentInfo, err := derSequence(top[1].FullBytes)
	if err != nil || len(contentInfo) < 2 {
		return bad("content info")
	}
	signedData, err := derSequence(contentInfo[1].Bytes)
	if err != nil || len(signedData) < 3 {
		return bad("signed data")
	}
	encap, err := derSequence(signedData[2].FullBytes)
	if err != nil || len(encap) < 2 {
		return bad("encapsulated content")
	}
	var tstDER []byte
	if _, err := asn1.Unmarshal(encap[1].Bytes, &tstDER); err != nil {
		return bad("timestamp info")
	}
	tst, err := derSequence(tstDER)
	if err != nil || len(tst) < 5 {
		return bad("timestamp fields")
	}
	imprint, err := derSequence(tst[2].FullBytes)
	if err != nil || len(imprint) < 2 {
		return bad("fingerprint field")
	}
	var hashed []byte
	if _, err := asn1.Unmarshal(imprint[1].FullBytes, &hashed); err != nil {
		return bad("fingerprint value")
	}
	if !bytes.Equal(hashed, digest) {
		return zero, errors.New("the receipt is for a different fingerprint than the one sent")
	}
	var gen time.Time
	if _, err := asn1.UnmarshalWithParams(tst[4].FullBytes, &gen, "generalized"); err != nil {
		return bad("time")
	}
	for _, el := range tst[5:] {
		if el.Class == asn1.ClassUniversal && el.Tag == asn1.TagInteger {
			var n *big.Int
			if _, err := asn1.Unmarshal(el.FullBytes, &n); err != nil {
				return bad("nonce")
			}
			if n.Cmp(nonce) != 0 {
				return zero, errors.New("the receipt answers a different request than the one sent")
			}
		}
	}
	return gen, nil
}

func derSequence(der []byte) ([]asn1.RawValue, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("unexpected data after the structure")
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, errors.New("not a sequence")
	}
	var out []asn1.RawValue
	b := seq.Bytes
	for len(b) > 0 {
		var v asn1.RawValue
		b, err = asn1.Unmarshal(b, &v)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// submitOTS sends a fingerprint to an OpenTimestamps calendar and returns its
// reply, which is the first part of the proof. The calendar completes the
// proof once its Bitcoin transaction is confirmed.
func submitOTS(calendar string, digest []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", calendar+"/digest", bytes.NewReader(digest))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10000))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("answered with status %d", resp.StatusCode)
	}
	if len(body) == 0 {
		return nil, errors.New("answered with an empty reply")
	}
	return body, nil
}

var otsHeader = []byte("\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

// otsProof builds a standard .ots proof file for a file whose SHA-256 is
// digest, from a calendar's reply. Such files can be checked and completed
// with the OpenTimestamps client or at opentimestamps.org.
func otsProof(digest, calendarReply []byte) []byte {
	out := append([]byte{}, otsHeader...)
	out = append(out, 0x01) // proof format version 1
	out = append(out, 0x08) // the file fingerprint is SHA-256
	out = append(out, digest...)
	return append(out, calendarReply...)
}
