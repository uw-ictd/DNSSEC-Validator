package main

type Record struct {
	Domain       string
	DNSSECExists bool
	DNSSECValid  bool
	reason       string
	ProtocolsUsed string
	AlgorithmsUsed string
	PublicKeySizes string
}
