package resolver

import (
	"encoding/json"
	"github.com/miekg/dns"
	"log"
	"strconv"
	"strings"
)

// AuthenticationChain represents the DNSSEC chain of trust from the
// queried Zone to the root (.) Zone.  In order for a Zone to validate,
// it is required that each Zone in the chain validate against its
// parent using the DS record.
//
// https://www.ietf.org/rfc/rfc4033.txt
type AuthenticationChain struct {
	DelegationChain []SignedZone `json:"chain"`
}

func (authChain *AuthenticationChain) Serialize() (string, error) {
	data, err := json.MarshalIndent(authChain, "", "  ")
	return string(data), err
}

func (authChain *AuthenticationChain) SerializeKeyAlgorithmsUsed() ([]string, []string, []string, error) {
	KeyAlgorithms := make([]string, 0)
	ProtocolsUsed := make([]string, 0)
	KeySizes := make([]string, 0)

	for _, sz := range authChain.DelegationChain {
		if sz.checkHasDnskeys() {
			rr := sz.Dnskey.RrSet
			for _, rrEntry := range rr {
				dnskey := rrEntry.(*dns.DNSKEY)
				algString := strconv.Itoa(int(dnskey.Algorithm))
				KeyAlgorithms = append(KeyAlgorithms, algString)

				protocol := strconv.Itoa(int(dnskey.Protocol))
				ProtocolsUsed = append(ProtocolsUsed, protocol)

				keySize := strconv.Itoa(len(dnskey.PublicKey))
				KeySizes = append(KeySizes, keySize)
			}
		}
	}

	return KeyAlgorithms, ProtocolsUsed, KeySizes, nil
}

// Populate queries the RRs required for the Zone validation
// It begins the queries at the *domainName* Zone and then walks
// up the delegation tree all the way up to the root Zone, thus
// populating a linked list of SignedZone objects.
func (authChain *AuthenticationChain) Populate(domainName string) error {

	qnameComponents := strings.Split(domainName, ".")
	zonesToVerify := len(qnameComponents)
	// TODO add test case
	if zonesToVerify < 0 {
		zonesToVerify = 0
	}

	authChain.DelegationChain = make([]SignedZone, 0, zonesToVerify)
	for i := 0; i < zonesToVerify; i++ {
		zoneName := dns.Fqdn(strings.Join(qnameComponents[i:], "."))
		delegation, err := queryDelegation(zoneName)
		if err != nil {
			return err
		}
		if i > 0 {
			authChain.DelegationChain[i-1].ParentZone = delegation
		}
		authChain.DelegationChain = append(authChain.DelegationChain, *delegation)
	}
	return nil
}

// Verify uses the Zone data in DelegationChain to validate the DNSSEC
// chain of trust.
// It starts the verification in the RRSet supplied as parameter (verifies
// the RRSIG on the answer RRs), and, assuming a signature is correct and
// valid, it walks through the DelegationChain checking the RRSIGs on
// the DNSKEY and DS resource record sets, as well as correctness of each
// delegation using the lower level methods in SignedZone.
func (authChain *AuthenticationChain) Verify(answerRRset *RRSet) error {

	zones := authChain.DelegationChain
	if len(zones) == 0 {
		return ErrDelegationChain
	}

	signedZone := authChain.DelegationChain[0]
	if !signedZone.checkHasDnskeys() {
		return ErrDnskeyNotAvailable
	}

	err := signedZone.verifyRRSIG(answerRRset)
	if err != nil {
		//log.Println("RRSIG didn't verify", err)
		return ErrInvalidRRsig
	}

	for _, signedZone := range authChain.DelegationChain {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("[AuthChain] panic occurred: %v", err)
			}
		}()

		if signedZone.Dnskey.IsEmpty() {
			//log.Printf("DNSKEY RR does not exist on %s\n", signedZone.Zone)
			return ErrDnskeyNotAvailable
		}

		// Verify the RRSIG of the DNSKEY RRset with the public KSK.
		err := signedZone.verifyRRSIG(signedZone.Dnskey)
		if err != nil {
			//log.Printf("validation DNSKEY: %s\n", err)
			return ErrRrsigValidationError
		}

		if signedZone.ParentZone != nil {

			if signedZone.Ds.IsEmpty() {
				//log.Printf("DS RR is not available on zoneName %s\n", signedZone.Zone)
				return ErrDsNotAvailable
			}

			err := signedZone.ParentZone.verifyRRSIG(signedZone.Ds)
			if err != nil {
				//log.Printf("DS on %s doesn't validate against RRSIG %d\n", signedZone.Zone, signedZone.Ds.RrSig.KeyTag)
				return ErrRrsigValidationError
			}
			err = signedZone.verifyDS(signedZone.Ds.RrSet)
			if err != nil {
				//log.Printf("DS does not validate: %s", err)
				return ErrDsInvalid
			}
		}
	}
	return nil
}

// NewAuthenticationChain initializes an AuthenticationChain object and
// returns a reference to it.
func NewAuthenticationChain() *AuthenticationChain {
	return &AuthenticationChain{}
}
