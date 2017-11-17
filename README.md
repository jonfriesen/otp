# HOTP

This package is an implementation of [RFC 4226: HOTP: An HMAC-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc4226) with slight deviations from the RFC based on the algorithmic reference implementation and tested using the RFC test values to ensure comaptibility with other HOTP systems. 

## Installation

Clone this repository into your Go src directory or pull it automatically with:

```
$ go get github.com/jonfriesen/otp
```


## Usage
```
import "github.com/jonfriesen/otp"

otp := hotp.GenerateOTP(...)
```

## Considerations and Variations from RFC
### Checksum
The checksum option is not included in this implementation as I feel most real world implementations don't use it or account for it. 

### Truncation Offset
The truncation offset is intended to give the entire hash digest the opportunity to contribute to the truncated portion of the hash. Removing this section does not make the algorithm more or less secure.

## Motivation
The OTP package was created to offer a simple, close implementation of RFC 4226 for easy consumption in Go.

## Contributions
Pull Requests are welcome, please include tests covering your contributions. 


<sub>[MIT License Copyright (c) 2017 Jonathan Friesen](./LICENSE)</sub>