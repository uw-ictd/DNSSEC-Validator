package resolver

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"time"
)

const (
	DefaultTimeout = 5 * time.Second
)

// Resolver contains the client configuration for github.com/miekg/dns,
// the instantiated client and the func that performs the actual queries.
// queryFn can be used for mocking the actual DNS lookups in the test suite.
type Resolver struct {
	queryFn   func(string, uint16) (*dns.Msg, error)
	dnsClient *dns.Client
}

// Errors returned by the verification/validation methods at all levels.
var (
	ErrResourceNotSigned    = errors.New("resource is not signed with RRSIG")
	ErrNoResult             = errors.New("requested RR not found")
	ErrNsNotAvailable       = errors.New("no name server to answer the question")
	ErrDnskeyNotAvailable   = errors.New("DNSKEY RR does not exist")
	ErrDsNotAvailable       = errors.New("DS RR does not exist")
	ErrInvalidRRsig         = errors.New("invalid RRSIG")
	ErrRrsigValidationError = errors.New("RR doesn't validate against RRSIG")
	ErrRrsigValidityPeriod  = errors.New("invalid RRSIG validity period")
	ErrUnknownDsDigestType  = errors.New("unknown DS digest type")
	ErrDsInvalid            = errors.New("DS RR does not match DNSKEY")
	ErrInvalidQuery         = errors.New("invalid query input")
	ErrDelegationChain      = errors.New("AuthChain has no Delegations")
)

var resolver *Resolver

// NewDNSMessage creates and initializes a dns.Msg object, with EDNS enabled
// and the DO (DNSSEC OK) flag set.  It returns a pointer to the created
// object.
func NewDNSMessage() *dns.Msg {
	dnsMessage := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
	}
	dnsMessage.SetEdns0(4096, true)
	return dnsMessage
}

// localQuery takes a query name (qname) and query type (qtype) and
// performs a DNS lookup by calling dnsClient.Exchange.
// It returns the answer in a *dns.Msg (or nil in case of an error, in which
// case err will be set accordingly.)
func localQuery(qname string, qtype uint16) (*dns.Msg, error) {
	dnsMessage := NewDNSMessage()
	dnsMessage.SetQuestion(qname, qtype)

	servers := []string{CloudflareDNS, GoogleDNS, NextDNS}

	for _, server := range servers {
		r, _, err := resolver.dnsClient.Exchange(dnsMessage, fmt.Sprintf("%s:%d", server, DNSPort))
		if err != nil {
			return nil, err
		}
		if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
			return r, err
		}
	}
	return nil, ErrNsNotAvailable
}

// queryDelegation takes a domain name and fetches the DS and DNSKEY records
// in that Zone.  Returns a SignedZone or nil in case of error.
func queryDelegation(domainName string) (signedZone *SignedZone, err error) {

	signedZone = NewSignedZone(domainName)

	signedZone.Dnskey, err = queryRRset(domainName, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	signedZone.PubKeyLookup = make(map[uint16]*dns.DNSKEY)
	for _, rr := range signedZone.Dnskey.RrSet {
		signedZone.addPubKey(rr.(*dns.DNSKEY))
	}

	signedZone.Ds, _ = queryRRset(domainName, dns.TypeDS)

	return signedZone, nil
}

// NewResolver initializes the package Resolver instance using the default
// dnsClientConfig.
func NewResolver() (res *Resolver, err error) {
	resolver = &Resolver{}
	resolver.dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	if err != nil {
		return nil, err
	}
	resolver.queryFn = localQuery
	return resolver, nil
}
