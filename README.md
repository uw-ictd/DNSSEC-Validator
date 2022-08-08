# DNSSEC Validator

Measurement tool to:

- Identify the existence of DNSSEC records (`DNSSECExists`)
    - These include existence of `DNSKEY`, `DS` RRs
- Verify the returned DNSSEC records (`DNSSECValid`)
    - Validates the `AuthenticationChain`.

## Build & Usage:

```shell
git clone <URL>
go build -o validator
```

The tool `validator` provides two subcommands:

- `query`: Performs a DNSSEC existence check and validation on a single FQDN by looking at the DNS `A` Record (`0x01`)
    - A default query is made to `sudheesh.info.`
    - query -d FQDN.   #trailing . required for a proper FQDN
    - query --help
- `measure`: Performs a DNSSEC existence check and validation as a batch
    - Valid FQDN list provided as `--inputlist` (default: `test.csv`)
    - Output directory for the results `--outdir` (default: `results/`)
    - Writes the output of the scan to `results-<UnixTimeStamp>.csv` in the `--outdir`

The tool uses the public open recursive resolvers to lookup the records and uses them in the following order:

```go
CloudflareDNS = "1.1.1.1" (1)
GoogleDNS = "8.8.8.8" (2) if (1) fails
NextDNS = "9.9.9.9" (3) if (2) fails
```

### Execution Example

```
./validator query -d sudheesh.info.
Valid DNS Record Answer for sudheesh.info. (1)
sudheesh.info.  300     IN      A       104.21.61.113
sudheesh.info.  300     IN      A       172.67.209.154
containing the chain...
-----------------------CHAIN-----------------------
[Chain Level 1]
        Zone      : sudheesh.info.
        DNSKEY    : (RRSET)
                sudheesh.info.  1668    IN      DNSKEY  256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==
                sudheesh.info.  1668    IN      DNSKEY  257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==
        DNSKEY    : (RRSIG)
                sudheesh.info.  1668    IN      RRSIG   DNSKEY 13 2 3600 20220429071856 20220227071856 2371 sudheesh.info. 0YVQKI8OUXAKeMAKdw+TzkKaLqFcse40kZO8KxtGf1BqUtuMkrDCwrY2XQ/tq1Hc4iGKyajQzCNIiBby+Iq66Q==
        DS        : (RRSET)
                sudheesh.info.  1954    IN      DS      2371 13 2 B9EF26CD8794C7A5F84DF8E41BFDEC92BF19FFEAA86928482A2CA3AAA15E818E
        DS        : (RRSIG)
                sudheesh.info.  1954    IN      RRSIG   DS 8 2 3600 20220407153416 20220317143416 58251 info. cBRoYj3K1C7cPNBuVePS4teM0taSeetG7/xF7mz0e0DnijuiUEJ6ARNcwytErOM5WyOcpdb20kxBj/o5UvKoK2SoInewQtsu/4P5eHxSFd4B95BZRban4McVcXHcqarvehKjzfgLmag6XYUe/Kfu1K5vv3FYe6HaIRwyEVau1WM=
        Keys      :
                 34505 : sudheesh.info. 1668    IN      DNSKEY  256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==
                 2371 : sudheesh.info.  1668    IN      DNSKEY  257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==

    [Chain Level 2]
        Zone      : info.
        DNSKEY    : (RRSET)
                info.   541     IN      DNSKEY  256 3 8 AwEAAcUtJi8qRxdmzyOCgt8D+bXgckLc96zPxT19OwBYhXzJjUoZwUq4KnxGNVNiJC6p9uWoehFXMpZY9YXGCzFfXVh/PyD0O80AX6GnprmgvDvskrfMxcz3HjgSD7F2lolQc7KHg4BbeddbptFlmLUPZ9zl61+J8K9uLp+hDqb66qJx
                info.   541     IN      DNSKEY  256 3 8 AwEAAdmBS+dIT6GZm6Xsp2vDn8Gp7EwTlxuW2yohpBfl/PwOmVhybV/338AimC0t7hDQAGhAqNsvDTYFKTNFjwwAlWlY/1x/+oKIyyYvDE+7jFFt5M3J0BC1OAzLsw9FhdWUSdjwU9rUY9n9ZL1A78kTN3NTGj5N5kX+So/DW6rii1th
                info.   541     IN      DNSKEY  257 3 8 AwEAAcIehVsobEPI8p8hMt9q+pYk2Ba6jynDojqiJ+6tfEcg9jOCAKB/uHwSqgae2+9KV29CmuQcHv0UwU0V9IQFEy1lI98RozFfbsD7qWR+F4OWbxgMWEHmJtJExKbqviw2AGjMbGuwNbIayLzXWPNKz6WlVrm6XxTrznGn9baVG5PDi8hgKSUmTiTJoSCgu8S9CRE6+rjdRWs/E3YzOo7MuaaJ24qJCOMbCtC/UKNTgS5UaJ3Oz3UE3LYosMU7XI1O+yFElCHB8DQkcsGpeJcv+J6wJwErwN2c7c4K9n5pwgrsn3fZX2nTxzzcsoDMPZEtTr137tBzwubxxtRUYuD33kE=
        DNSKEY    : (RRSIG)
                info.   541     IN      RRSIG   DNSKEY 8 1 3600 20220407153416 20220317143416 5104 info. u+eAnkdq4eSve+Q2DwYtU0LNwcHVhnDbkzCOURqo0lPEj662SAmHQtzKhmZChFmcUMet9ll7lCkOKYTj2MofmHI2AFQxRZZSa6xzaVYmMQN7UZFCf06g75vUPVpvn8qj2fL/OhUfljIIHPvabdFNytVCSdc/sYFOKawWzWGa6PWo6gOgYb7OQnSsYjnnfghVGAUqJFyC2i28ebijPl7VSEAn9t0kPE1Pof8D3uO3IAkI5DLLczM4rXgpP0PWkXRaPxxloFOEy6NEBGUs7XfLNwXILylxTNKpU9SkzWKUBR4ev3QbDmErdsOT3wf3mFQeDKG/0yrsJMGlK68fT6BtoA==
        DS        : (RRSET)
                info.   86400   IN      DS      5104 8 2 1AF7548A8D3E2950C20303757DF9390C26CFA39E26C8B6A8F6C8B1E72DD8F744
        DS        : (RRSIG)
                info.   86400   IN      RRSIG   DS 8 1 86400 20220403220000 20220321210000 9799 . CdZOwRlqgbg8nEwjWfsnu1JpQaD14MS6/xl4P8tnfUGNNpbYYKsARf70Ln3g80vTTaKmb30Jq7HZSHgm9vbDGKyszg2ZEx4YtTb7N5Bz6ZkdxzD8otDXwEHtFEDOds77gW2DywEXzQACNuubaHay5BzRm4Hi+9N5RV6+Sy1I8rMnJ+H2+EKBCenDxMgj20eok7nfhEoPF+tlOGlkRmB5cbJ9MHSZ2TgzSTsITOPjrWPKgHSanhr0zM40phYCpceZVYCtEGmBM67mrtzKRXAgkqmeOZVT91odv2X7c2j5Uk3noQWjBdvpx1gPbNmES32JXnWa0alwW94FhtSx3uz6tA==
        Keys      :
                 11091 : info.  541     IN      DNSKEY  256 3 8 AwEAAcUtJi8qRxdmzyOCgt8D+bXgckLc96zPxT19OwBYhXzJjUoZwUq4KnxGNVNiJC6p9uWoehFXMpZY9YXGCzFfXVh/PyD0O80AX6GnprmgvDvskrfMxcz3HjgSD7F2lolQc7KHg4BbeddbptFlmLUPZ9zl61+J8K9uLp+hDqb66qJx
                 58251 : info.  541     IN      DNSKEY  256 3 8 AwEAAdmBS+dIT6GZm6Xsp2vDn8Gp7EwTlxuW2yohpBfl/PwOmVhybV/338AimC0t7hDQAGhAqNsvDTYFKTNFjwwAlWlY/1x/+oKIyyYvDE+7jFFt5M3J0BC1OAzLsw9FhdWUSdjwU9rUY9n9ZL1A78kTN3NTGj5N5kX+So/DW6rii1th
                 5104 : info.   541     IN      DNSKEY  257 3 8 AwEAAcIehVsobEPI8p8hMt9q+pYk2Ba6jynDojqiJ+6tfEcg9jOCAKB/uHwSqgae2+9KV29CmuQcHv0UwU0V9IQFEy1lI98RozFfbsD7qWR+F4OWbxgMWEHmJtJExKbqviw2AGjMbGuwNbIayLzXWPNKz6WlVrm6XxTrznGn9baVG5PDi8hgKSUmTiTJoSCgu8S9CRE6+rjdRWs/E3YzOo7MuaaJ24qJCOMbCtC/UKNTgS5UaJ3Oz3UE3LYosMU7XI1O+yFElCHB8DQkcsGpeJcv+J6wJwErwN2c7c4K9n5pwgrsn3fZX2nTxzzcsoDMPZEtTr137tBzwubxxtRUYuD33kE=

        [Chain Level 3]
                Zone      : .
                DNSKEY    : (RRSET)
                        .       169026  IN      DNSKEY  256 3 8 AwEAAZym4HCWiTAAl2Mv1izgTyn9sKwgi5eBxpG29bVlefq/r+TGCtmUElvFyBWHRjvf9mBglIlTBRse22dvzNOI+cYrkjD6LOHuxMoc/d4WtXWKdviNmrtWF2GpjmDOI98gLd4BZ0U/lY847mJP9LypFABZcEn3zM3vce4Ee1A3upSlFQ2TFyJSD9HvMnP4XneFexBxV96RpLcy2O+u2W6ChIiDCjlrowPCcU3zXfXxyWy/VKM6TOa8gNf+aKaVkcv/eIh5er8rrsqAi9KT8O5hmhzYLkUOQEXVSRORV0RMt9l3JSwWxT1MebEDvtfBag3uo+mZwWSFlpc9kuzyWBd72Ec=
                        .       169026  IN      DNSKEY  257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
                DNSKEY    : (RRSIG)
                        .       169026  IN      RRSIG   DNSKEY 8 0 172800 20220402000000 20220312000000 20326 . Da/6ruIbLmJUTwsBiu1PH8OG6aEIgA2Tgbtrj+v3XP5Y3pZHwZAtqEzPMaXTV+7u68CzPvxCIgTr9qX/BC4lpkk6t4sdFNa61gW3dvvc3SvuFv7PbtTUPiiSu0u9MWK0srrkVRxBZu2uGKWSkDoSPjLTGI6n9URVj69VhrRut9ffCIGb6ZhmBHG7xf7pxo+G6NFgGmC2VRL6gBxFejXaJM4TJZELW6ua887DaTSV+gWL1NrxRw86Zzlb45TebJHgszLOb76LI8WKSiboyie1iPMHl4RAD7e7WKWTqaHRY3W1qqcPN3+L9pV8Bpf7q47pxkWMBOzFmecrMBPRxsuFTQ==
                DS        : (RRSET)
                DS        : (RRSIG)
                        <nil>
                Keys      :
                         9799 : .       169026  IN      DNSKEY  256 3 8 AwEAAZym4HCWiTAAl2Mv1izgTyn9sKwgi5eBxpG29bVlefq/r+TGCtmUElvFyBWHRjvf9mBglIlTBRse22dvzNOI+cYrkjD6LOHuxMoc/d4WtXWKdviNmrtWF2GpjmDOI98gLd4BZ0U/lY847mJP9LypFABZcEn3zM3vce4Ee1A3upSlFQ2TFyJSD9HvMnP4XneFexBxV96RpLcy2O+u2W6ChIiDCjlrowPCcU3zXfXxyWy/VKM6TOa8gNf+aKaVkcv/eIh5er8rrsqAi9KT8O5hmhzYLkUOQEXVSRORV0RMt9l3JSwWxT1MebEDvtfBag3uo+mZwWSFlpc9kuzyWBd72Ec=
                         20326 : .      169026  IN      DNSKEY  257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=

-------------------END CHAIN-----------------------
```

## Misc:

Latest root at the time of writing this application downloaded from
IANA [here](https://data.iana.org/root-anchors/root-anchors.xml):

```xml

<TrustAnchor id="380DC50D-484E-40D0-A3AE-68F2B18F61C7" source="http://data.iana.org/root-anchors/root-anchors.xml">
    <Zone>.</Zone>
    <KeyDigest id="Kjqmt7v" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
        <KeyTag>19036</KeyTag>
        <Algorithm>8</Algorithm>
        <DigestType>2</DigestType>
        <Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
    </KeyDigest>
    <KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00">
        <KeyTag>20326</KeyTag>
        <Algorithm>8</Algorithm>
        <DigestType>2</DigestType>
        <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
    </KeyDigest>
</TrustAnchor>
```

# Credits

This tool builds on the original [goresolver](https://github.com/peterzen/goresolver) tool written by peterzen and is
further implemented on top of the popular [dns](https://github.com/miekg/dns) by Miek Gieben.
