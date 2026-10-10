package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const userAgent = toolName + "/" + toolVersion

var (
	httpClient   = &http.Client{Timeout: 15 * time.Second}
	beaconClient = &http.Client{Timeout: 5 * time.Second}
	uploadClient = &http.Client{Timeout: 5 * time.Minute}
)

// NISTPulse is one value from the NIST Randomness Beacon (one per minute).
// It can be looked up later at URI.
type NISTPulse struct {
	URI         string `json:"uri"`
	ChainIndex  int64  `json:"chain_index"`
	PulseIndex  int64  `json:"pulse_index"`
	Time        string `json:"time"`
	OutputValue string `json:"output_value"`
}

// DrandRound is one value from the League of Entropy drand network (one per
// 30 seconds). The signature can be checked with the network's public key.
type DrandRound struct {
	Chain             string `json:"chain"`
	Round             uint64 `json:"round"`
	Time              string `json:"time"`
	Randomness        string `json:"randomness"`
	Signature         string `json:"signature"`
	PreviousSignature string `json:"previous_signature,omitempty"`
}

const (
	nistLatestURL   = "https://beacon.nist.gov/beacon/2.0/pulse/last"
	drandChainHash  = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
	drandGenesis    = 1595431050
	drandPeriodSecs = 30
)

var drandURLs = []string{
	"https://api.drand.sh/" + drandChainHash + "/public/latest",
	"https://drand.cloudflare.com/" + drandChainHash + "/public/latest",
}

// beaconSource keeps the most recent values for a short time, so that a burst
// of file changes does not cause a burst of requests. A value that is a few
// seconds old is still a correct lower bound on when an entry was written.
type beaconSource struct {
	maxAge     time.Duration
	nist       *NISTPulse
	nistTried  time.Time
	nistErr    error
	drand      *DrandRound
	drandTried time.Time
	drandErr   error
}

func (b *beaconSource) current() (*NISTPulse, *DrandRound, string) {
	now := time.Now()
	if now.Sub(b.nistTried) > b.maxAge {
		b.nistTried = now
		p, err := fetchNIST()
		b.nistErr = err
		if err == nil {
			b.nist = p
		}
	}
	if now.Sub(b.drandTried) > b.maxAge {
		b.drandTried = now
		d, err := fetchDrand()
		b.drandErr = err
		if err == nil {
			b.drand = d
		}
	}
	var problems []string
	if b.nistErr != nil {
		problems = append(problems, "NIST beacon: "+b.nistErr.Error())
	}
	if b.drandErr != nil {
		problems = append(problems, "drand: "+b.drandErr.Error())
	}
	return b.nist, b.drand, strings.Join(problems, "; ")
}

func getJSON(client *http.Client, url string, out any) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered with status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func fetchNIST() (*NISTPulse, error) {
	var r struct {
		Pulse struct {
			URI         string `json:"uri"`
			ChainIndex  int64  `json:"chainIndex"`
			PulseIndex  int64  `json:"pulseIndex"`
			TimeStamp   string `json:"timeStamp"`
			OutputValue string `json:"outputValue"`
		} `json:"pulse"`
	}
	if err := getJSON(beaconClient, nistLatestURL, &r); err != nil {
		return nil, err
	}
	if r.Pulse.OutputValue == "" || r.Pulse.URI == "" {
		return nil, fmt.Errorf("the answer did not contain a pulse")
	}
	t, err := time.Parse(time.RFC3339, r.Pulse.TimeStamp)
	if err != nil {
		return nil, fmt.Errorf("the pulse has an unreadable time %q", r.Pulse.TimeStamp)
	}
	if age := time.Since(t); age > 5*time.Minute {
		return nil, fmt.Errorf("the newest pulse is %s old, so the beacon appears to have stopped", age.Round(time.Minute))
	}
	return &NISTPulse{
		URI:         r.Pulse.URI,
		ChainIndex:  r.Pulse.ChainIndex,
		PulseIndex:  r.Pulse.PulseIndex,
		Time:        r.Pulse.TimeStamp,
		OutputValue: r.Pulse.OutputValue,
	}, nil
}

func fetchDrand() (*DrandRound, error) {
	var lastErr error
	for _, url := range drandURLs {
		var r struct {
			Round             uint64 `json:"round"`
			Randomness        string `json:"randomness"`
			Signature         string `json:"signature"`
			PreviousSignature string `json:"previous_signature"`
		}
		if err := getJSON(beaconClient, url, &r); err != nil {
			lastErr = err
			continue
		}
		if r.Round == 0 || r.Randomness == "" {
			lastErr = fmt.Errorf("the answer from %s did not contain a round", url)
			continue
		}
		t := time.Unix(drandGenesis+int64(r.Round-1)*drandPeriodSecs, 0).UTC()
		return &DrandRound{
			Chain:             drandChainHash,
			Round:             r.Round,
			Time:              t.Format(time.RFC3339),
			Randomness:        r.Randomness,
			Signature:         r.Signature,
			PreviousSignature: r.PreviousSignature,
		}, nil
	}
	return nil, lastErr
}
