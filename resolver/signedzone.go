package resolver

import (
	"github.com/miekg/dns"
	"strings"
	"time"
)

// SignedZone represents a DNSSEC-enabled Zone, its DNSKEY and DS records
type SignedZone struct {
	Zone         string                 `json:"zone"`
	Dnskey       *RRSet                 `json:"dnskey"`
	Ds           *RRSet                 `json:"ds"`
	ParentZone   *SignedZone            `json:"parentZone"`
	PubKeyLookup map[uint16]*dns.DNSKEY `json:"pkLookup"`
}

// lookupPubkey returns a DNSKEY by its keytag
func (z SignedZone) lookupPubKey(keyTag uint16) *dns.DNSKEY {
	return z.PubKeyLookup[keyTag]
}

// addPubkey stores a DNSKEY in the keytag lookup table.
func (z SignedZone) addPubKey(k *dns.DNSKEY) {
	z.PubKeyLookup[k.KeyTag()] = k
}

// verifyRRSIG verifies the signature on a signed
// RRSET, and checks the validity period on the RRSIG.
// It returns nil if the RRSIG verifies and the signature
// is valid, and the appropriate error value in case
// of validation failure.
func (z SignedZone) verifyRRSIG(signedRRset *RRSet) (err error) {

	if !signedRRset.IsSigned() {
		return ErrRRSigNotAvailable
	}

	// Verify the RRSIG of the DNSKEY RRset
	key := z.lookupPubKey(signedRRset.RrSig.KeyTag)
	if key == nil {
		//log.Printf("DNSKEY keytag %d not found", signedRRset.RrSig.KeyTag)
		return ErrDnskeyNotAvailable
	}

	err = signedRRset.RrSig.Verify(key, signedRRset.RrSet)
	if err != nil {
		//log.Println("DNSKEY verification", err)
		return err
	}

	if !signedRRset.RrSig.ValidityPeriod(time.Now()) {
		//log.Println("invalid validity period", err)
		return ErrRrsigValidityPeriod
	}
	return nil
}

// verifyDS validates the DS record against the KSK
// (key signing key) of the Zone.
// Return nil if the DS record matches the digest of
// the KSK.
func (z SignedZone) verifyDS(dsRrset []dns.RR) (err error) {

	for _, rr := range dsRrset {

		ds := rr.(*dns.DS)

		if ds.DigestType != dns.SHA256 {
			//log.Printf("Unknown digest type (%d) on DS RR", ds.DigestType)
			continue
		}

		parentDsDigest := strings.ToUpper(ds.Digest)
		key := z.lookupPubKey(ds.KeyTag)
		if key == nil {
			//log.Printf("DNSKEY keytag %d not found", ds.KeyTag)
			return ErrDnskeyNotAvailable
		}
		dsDigest := strings.ToUpper(key.ToDS(ds.DigestType).Digest)
		if parentDsDigest == dsDigest {
			return nil
		}

		//log.Printf("DS does not match DNSKEY\n")
		return ErrDsInvalid
	}
	return ErrUnknownDsDigestType
}

// checkHasDnskeys returns true if the SignedZone has a DNSKEY
// record, false otherwise.
func (z *SignedZone) checkHasDnskeys() bool {
	return len(z.Dnskey.RrSet) > 0
}

// NewSignedZone initializes a new SignedZone and returns it.
func NewSignedZone(domainName string) *SignedZone {
	return &SignedZone{
		Zone:   domainName,
		Ds:     &RRSet{},
		Dnskey: &RRSet{},
	}
}
