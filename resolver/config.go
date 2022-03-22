package resolver

// Order of preference of DNS Resolvers to speak to in case of Failures

const CloudflareDNS = "1.1.1.1"
const GoogleDNS = "8.8.8.8"
const NextDNS = "9.9.9.9"
const DNSPort = 53
