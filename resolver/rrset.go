package resolver

import (
	"github.com/miekg/dns"
	"log"
)

type RRSet struct {
	RrSet []dns.RR   `json:"RrSet"`
	RrSig *dns.RRSIG `json:"RrSig"`
}

func queryRRset(qname string, qtype uint16) (*RRSet, error) {

	r, err := resolver.queryFn(qname, qtype)

	if err != nil {
		log.Printf("cannot lookup %v", err)
		return nil, err
	}

	if r.Rcode == dns.RcodeNameError {
		log.Printf("no such domain %s\n", qname)
		return nil, ErrNoResult
	}

	result := NewSignedRRSet()

	if r.Answer == nil {
		return result, nil
	}

	result.RrSet = make([]dns.RR, 0, len(r.Answer))

	for _, rr := range r.Answer {
		switch t := rr.(type) {
		case *dns.RRSIG:
			result.RrSig = t
		default:
			if rr != nil {
				result.RrSet = append(result.RrSet, rr)
			}
		}
	}
	return result, nil
}

func (sRRset *RRSet) IsSigned() bool {
	return sRRset.RrSig != nil
}

func (sRRset *RRSet) IsEmpty() bool {
	return len(sRRset.RrSet) < 1
}

func (sRRset *RRSet) SignerName() string {
	return sRRset.RrSig.SignerName
}

func NewSignedRRSet() *RRSet {
	return &RRSet{
		RrSet: make([]dns.RR, 0),
	}
}
