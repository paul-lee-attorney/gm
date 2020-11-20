package gmx509

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/paul-lee-attorney/gm/sm2"
)

// ignoreCN disables interpreting Common Name as a hostname. See issue 24151.
var ignoreCN = strings.Contains(os.Getenv("GODEBUG"), "x509ignoreCN=1")

// ===========================================================================

// sm2Signature 代表SM2算法的数字签名类。
type sm2Signature struct {
	R, S *big.Int
}

type InvalidReason int

const (
	// NotAuthorizedToSign results when a certificate is signed by another
	// which isn't marked as a CA certificate.
	NotAuthorizedToSign InvalidReason = iota
	// Expired results when a certificate has expired, based on the time
	// given in the VerifyOptions.
	Expired // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>
	// CANotAuthorizedForThisName results when an intermediate or root
	// certificate has a name constraint which doesn't permit a DNS or
	// other name (including IP address) in the leaf certificate.
	CANotAuthorizedForThisName
	// TooManyIntermediates results when a path length constraint is
	// violated.
	TooManyIntermediates
	// IncompatibleUsage results when the certificate's key usage indicates
	// that it may only be used for a different purpose.
	IncompatibleUsage
	// NameMismatch results when the subject name of a parent certificate
	// does not match the issuer name in the child.
	NameMismatch
	// NameConstraintsWithoutSANs results when a leaf certificate doesn't
	// contain a Subject Alternative Name extension, but a CA certificate
	// contains name constraints, and the Common Name can be interpreted as
	// a hostname.
	//
	// You can avoid this error by setting the experimental GODEBUG environment
	// variable to "x509ignoreCN=1", disabling Common Name matching entirely.
	// This behavior might become the default in the future.
	NameConstraintsWithoutSANs
	// UnconstrainedName results when a CA certificate contains permitted
	// name constraints, but leaf certificate contains a name of an
	// unsupported or unconstrained type.
	UnconstrainedName
	// TooManyConstraints results when the number of comparison operations
	// needed to check a certificate exceeds the limit set by
	// VerifyOptions.MaxConstraintComparisions. This limit exists to
	// prevent pathological certificates can consuming excessive amounts of
	// CPU time to verify.
	TooManyConstraints
	// CANotAuthorizedForExtKeyUsage results when an intermediate or root
	// certificate does not permit a requested extended key usage.
	CANotAuthorizedForExtKeyUsage
)

type UnhandledCriticalExtension struct{}

func (h UnhandledCriticalExtension) Error() string {
	return "x509: unhandled critical extension"
}

// CertificateInvalidError results when an odd error occurs. Users of this
// library probably want to handle all these errors uniformly.
type CertificateInvalidError struct {
	Cert   *x509.Certificate
	Reason InvalidReason
	Detail string
}

func (e CertificateInvalidError) Error() string {
	switch e.Reason {
	case NotAuthorizedToSign:
		return "x509: certificate is not authorized to sign other certificates"
	case Expired:
		return "x509: certificate has expired or is not yet valid: " + e.Detail
	case CANotAuthorizedForThisName:
		return "x509: a root or intermediate certificate is not authorized to sign for this name: " + e.Detail
	case CANotAuthorizedForExtKeyUsage:
		return "x509: a root or intermediate certificate is not authorized for an extended key usage: " + e.Detail
	case TooManyIntermediates:
		return "x509: too many intermediates for path length constraint"
	case IncompatibleUsage:
		return "x509: certificate specifies an incompatible key usage"
	case NameMismatch:
		return "x509: issuer name does not match subject from issuing certificate"
	case NameConstraintsWithoutSANs:
		return "x509: issuer has name constraints but leaf doesn't have a SAN extension"
	case UnconstrainedName:
		return "x509: issuer has name constraints but leaf contains unknown or unconstrained name: " + e.Detail
	}
	return "x509: unknown error"
}

// ConstraintViolationError results when a requested usage is not permitted by
// a certificate. For example: checking a signature when the public key isn't a
// certificate signing key.
type ConstraintViolationError struct{}

func (ConstraintViolationError) Error() string {
	return "x509: invalid signature: parent certificate cannot sign this kind of certificate"
}

// ErrUnsupportedAlgorithm results from attempting to perform an operation that
// involves algorithms that are not currently implemented.
var ErrUnsupportedAlgorithm = errors.New("x509: cannot verify signature: algorithm unimplemented")

// UnknownAuthorityError results when the certificate issuer is unknown
type UnknownAuthorityError struct {
	Cert *x509.Certificate
	// hintErr contains an error that may be helpful in determining why an
	// authority wasn't found.
	hintErr error
	// hintCert contains a possible authority certificate that was rejected
	// because of the error in hintErr.
	hintCert *x509.Certificate
}

func (e UnknownAuthorityError) Error() string {
	s := "x509: certificate signed by unknown authority"
	if e.hintErr != nil {
		certName := e.hintCert.Subject.CommonName
		if len(certName) == 0 {
			if len(e.hintCert.Subject.Organization) > 0 {
				certName = e.hintCert.Subject.Organization[0]
			} else {
				certName = "serial:" + e.hintCert.SerialNumber.String()
			}
		}
		s += fmt.Sprintf(" (possibly because of %q while trying to verify candidate authority certificate %q)", e.hintErr, certName)
	}
	return s
}

// VerifyOptions contains parameters for Certificate.Verify. It's a structure
// because other PKIX verification APIs have ended up needing many options.
type VerifyOptions struct {
	DNSName       string
	Intermediates *CertPool
	Roots         *CertPool // if nil, the system roots are used
	CurrentTime   time.Time // if zero, the current time is used
	// KeyUsage specifies which Extended Key Usage values are acceptable. A leaf
	// certificate is accepted if it contains any of the listed values. An empty
	// list means ExtKeyUsageServerAuth. To accept any key usage, include
	// ExtKeyUsageAny.
	//
	// Certificate chains are required to nest these extended key usage values.
	// (This matches the Windows CryptoAPI behavior, but not the spec.)
	KeyUsages []x509.ExtKeyUsage
	// MaxConstraintComparisions is the maximum number of comparisons to
	// perform when checking a given certificate's name constraints. If
	// zero, a sensible default is used. This limit prevents pathological
	// certificates from consuming excessive amounts of CPU time when
	// validating.
	MaxConstraintComparisions int
}

const (
	leafCertificate = iota
	intermediateCertificate
	rootCertificate
)

func hasNameConstraints(c *x509.Certificate) bool {
	return oidInExtensions(oidExtensionNameConstraints, c.Extensions)
}

func hasSANExtension(c *x509.Certificate) bool {
	return oidInExtensions(oidExtensionSubjectAltName, c.Extensions)
}

func getSANExtension(c *x509.Certificate) []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtensionSubjectAltName) {
			return e.Value
		}
	}
	return nil
}

// CheckSignatureFrom verifies that the signature on c is a valid signature
// from parent.
func CheckSignatureFrom(c *x509.Certificate, parent *x509.Certificate) error {
	// RFC 5280, 4.2.1.9:
	// "If the basic constraints extension is not present in a version 3
	// certificate, or the extension is present but the cA boolean is not
	// asserted, then the certified public key MUST NOT be used to verify
	// certificate signatures."
	if parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA {
		return ConstraintViolationError{}
	}

	if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
		return ConstraintViolationError{}
	}

	// 验证母证书的签名算法和公钥算法
	if err := checkCertAlgo(parent); err != nil {
		return err
	}

	// if parent.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
	// 	return errors.New("the publickey algorithm is not SM2")
	// }

	// TODO(agl): don't ignore the path length constraint.

	return CheckSignature(parent, c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
}

// CheckSignature verifies that signature is a valid signature over signed from
// c's public key.
func CheckSignature(c *x509.Certificate, algo x509.SignatureAlgorithm, signed, signature []byte) error {
	// 验证母证书的签名算法和公钥算法
	if err := checkCertAlgo(c); err != nil {
		return err
	}

	// 验证子证书的签名算法和公钥算法
	if err := checkRawTBSCertAlgo(signed); err != nil {
		return err
	}
	return checkSignature(algo, signed, signature, c.PublicKey)
}

// checkAlgo 解析x509.Certificate后核验证书签字算法和公钥签字算法, 返回nil为通过
func checkCertAlgo(c *x509.Certificate) error {
	return checkRawTBSCertAlgo(c.RawTBSCertificate)
}

// checkRawTBSCertAlgo 核验RAW格式TBS证书的算法
func checkRawTBSCertAlgo(raw []byte) error {
	var tbsCert TBSCertificate

	rest, err := asn1.Unmarshal(raw, &tbsCert)
	if err != nil {
		return errors.New("failed to unmarshal tbsCertificate from x509.Certificate")
	} else if len(rest) > 0 {
		return errors.New("trailing data left after unmarshal x509.Certificate")
	}

	if !oidSignatureSM3WithSM2.Equal(tbsCert.SignatureAlgorithm.Algorithm) {
		return errors.New("x509: signature algorithm is not SM3WithSM2")
	}

	if !oidPublicKeySM2DSA.Equal(tbsCert.PublicKey.Algorithm.Algorithm) {
		return errors.New("x509: publick key algorithm is not SM2")
	}
	return nil
}

// CheckSignature verifies that signature is a valid signature over signed from
// a crypto.PublicKey.
func checkSignature(algo x509.SignatureAlgorithm, signed, signature []byte, publicKey crypto.PublicKey) (err error) {

	// if algo != x509.UnknownSignatureAlgorithm {
	// 	return errors.New("the Signature Algorithm is not SM3WithSM2")
	// }

	switch pub := publicKey.(type) {
	case *sm2.PublicKey:
		sm2Sig := new(sm2Signature)
		if rest, err := asn1.Unmarshal(signature, sm2Sig); err != nil {
			return err
		} else if len(rest) != 0 {
			return errors.New("x509: trailing data after SM2 signature")
		}
		if sm2Sig.R.Sign() <= 0 || sm2Sig.S.Sign() <= 0 {
			return errors.New("x509: SM2 signature contained zero or negative values")
		}
		if pass, err := sm2.VerifyByRS(pub, nil, signed, sm2Sig.R, sm2Sig.S); !pass || err != nil {
			return errors.New("x509: SM2 verification failure")
		}
		return
	}
	return errors.New("the Public Key Algorithm is not SM2")
}

//===================================================================

// // SystemRootsError results when we fail to load the system root certificates.
// type SystemRootsError struct {
// 	Err error
// }

// func (se SystemRootsError) Error() string {
// 	msg := "x509: failed to load system roots and no roots provided"
// 	if se.Err != nil {
// 		return msg + "; " + se.Err.Error()
// 	}
// 	return msg
// }

// errNotParsed is returned when a certificate without ASN.1 contents is
// verified. Platform-specific verification needs the ASN.1 contents.
// var errNotParsed = errors.New("x509: missing ASN.1 contents; use ParseCertificate")

func matchEmailConstraint(mailbox rfc2821Mailbox, constraint string) (bool, error) {
	// If the constraint contains an @, then it specifies an exact mailbox
	// name.
	if strings.Contains(constraint, "@") {
		constraintMailbox, ok := parseRFC2821Mailbox(constraint)
		if !ok {
			return false, fmt.Errorf("x509: internal error: cannot parse constraint %q", constraint)
		}
		return mailbox.local == constraintMailbox.local && strings.EqualFold(mailbox.domain, constraintMailbox.domain), nil
	}

	// Otherwise the constraint is like a DNS constraint of the domain part
	// of the mailbox.
	return matchDomainConstraint(mailbox.domain, constraint)
}

func matchURIConstraint(uri *url.URL, constraint string) (bool, error) {
	// From RFC 5280, Section 4.2.1.10:
	// “a uniformResourceIdentifier that does not include an authority
	// component with a host name specified as a fully qualified domain
	// name (e.g., if the URI either does not include an authority
	// component or includes an authority component in which the host name
	// is specified as an IP address), then the application MUST reject the
	// certificate.”

	host := uri.Host
	if len(host) == 0 {
		return false, fmt.Errorf("URI with empty host (%q) cannot be matched against constraints", uri.String())
	}

	if strings.Contains(host, ":") && !strings.HasSuffix(host, "]") {
		var err error
		host, _, err = net.SplitHostPort(uri.Host)
		if err != nil {
			return false, err
		}
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") ||
		net.ParseIP(host) != nil {
		return false, fmt.Errorf("URI with IP (%q) cannot be matched against constraints", uri.String())
	}

	return matchDomainConstraint(host, constraint)
}

func matchIPConstraint(ip net.IP, constraint *net.IPNet) (bool, error) {
	if len(ip) != len(constraint.IP) {
		return false, nil
	}

	for i := range ip {
		if mask := constraint.Mask[i]; ip[i]&mask != constraint.IP[i]&mask {
			return false, nil
		}
	}

	return true, nil
}

func matchDomainConstraint(domain, constraint string) (bool, error) {
	// The meaning of zero length constraints is not specified, but this
	// code follows NSS and accepts them as matching everything.
	if len(constraint) == 0 {
		return true, nil
	}

	domainLabels, ok := domainToReverseLabels(domain)
	if !ok {
		return false, fmt.Errorf("x509: internal error: cannot parse domain %q", domain)
	}

	// RFC 5280 says that a leading period in a domain name means that at
	// least one label must be prepended, but only for URI and email
	// constraints, not DNS constraints. The code also supports that
	// behaviour for DNS constraints.

	mustHaveSubdomains := false
	if constraint[0] == '.' {
		mustHaveSubdomains = true
		constraint = constraint[1:]
	}

	constraintLabels, ok := domainToReverseLabels(constraint)
	if !ok {
		return false, fmt.Errorf("x509: internal error: cannot parse domain %q", constraint)
	}

	if len(domainLabels) < len(constraintLabels) ||
		(mustHaveSubdomains && len(domainLabels) == len(constraintLabels)) {
		return false, nil
	}

	for i, constraintLabel := range constraintLabels {
		if !strings.EqualFold(constraintLabel, domainLabels[i]) {
			return false, nil
		}
	}

	return true, nil
}

// checkNameConstraints checks that c permits a child certificate to claim the
// given name, of type nameType. The argument parsedName contains the parsed
// form of name, suitable for passing to the match function. The total number
// of comparisons is tracked in the given count and should not exceed the given
// limit.
func checkNameConstraints(c *x509.Certificate, count *int,
	maxConstraintComparisons int,
	nameType string,
	name string,
	parsedName interface{},
	match func(parsedName, constraint interface{}) (match bool, err error),
	permitted, excluded interface{}) error {

	excludedValue := reflect.ValueOf(excluded)

	*count += excludedValue.Len()
	if *count > maxConstraintComparisons {
		return CertificateInvalidError{c, TooManyConstraints, ""}
	}

	for i := 0; i < excludedValue.Len(); i++ {
		constraint := excludedValue.Index(i).Interface()
		match, err := match(parsedName, constraint)
		if err != nil {
			return CertificateInvalidError{c, CANotAuthorizedForThisName, err.Error()}
		}

		if match {
			return CertificateInvalidError{c, CANotAuthorizedForThisName, fmt.Sprintf("%s %q is excluded by constraint %q", nameType, name, constraint)}
		}
	}

	permittedValue := reflect.ValueOf(permitted)

	*count += permittedValue.Len()
	if *count > maxConstraintComparisons {
		return CertificateInvalidError{c, TooManyConstraints, ""}
	}

	ok := true
	for i := 0; i < permittedValue.Len(); i++ {
		constraint := permittedValue.Index(i).Interface()

		var err error
		if ok, err = match(parsedName, constraint); err != nil {
			return CertificateInvalidError{c, CANotAuthorizedForThisName, err.Error()}
		}

		if ok {
			break
		}
	}

	if !ok {
		return CertificateInvalidError{c, CANotAuthorizedForThisName, fmt.Sprintf("%s %q is not permitted by any constraint", nameType, name)}
	}

	return nil
}

// isValid performs validity checks on c given that it is a candidate to append
// to the chain in currentChain.
// Fabric的证书体系为自签名证书，因此，删除了对系统证书的调用和核验。
func isValid(c *x509.Certificate, certType int, currentChain []*x509.Certificate, opts *VerifyOptions) error {
	if len(c.UnhandledCriticalExtensions) > 0 {
		return UnhandledCriticalExtension{}
	}

	if len(currentChain) > 0 {
		child := currentChain[len(currentChain)-1]
		if !bytes.Equal(child.RawIssuer, c.RawSubject) {
			return CertificateInvalidError{c, NameMismatch, ""}
		}
	}

	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	if now.Before(c.NotBefore) {
		return CertificateInvalidError{
			Cert:   c,
			Reason: Expired,
			Detail: fmt.Sprintf("current time %s is before %s", now.Format(time.RFC3339), c.NotBefore.Format(time.RFC3339)),
		}
	} else if now.After(c.NotAfter) {
		return CertificateInvalidError{
			Cert:   c,
			Reason: Expired,
			Detail: fmt.Sprintf("current time %s is after %s", now.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339)),
		}
	}

	maxConstraintComparisons := opts.MaxConstraintComparisions
	if maxConstraintComparisons == 0 {
		maxConstraintComparisons = 250000
	}
	comparisonCount := 0

	var leaf *x509.Certificate
	if certType == intermediateCertificate || certType == rootCertificate {
		if len(currentChain) == 0 {
			return errors.New("x509: internal error: empty chain when appending CA cert")
		}
		leaf = currentChain[0]
	}

	nameConstraints := (certType == intermediateCertificate || certType == rootCertificate) && hasNameConstraints(c)
	if nameConstraints && commonNameAsHostname(leaf) {
		// This is the deprecated, legacy case of depending on the commonName as
		// a hostname. We don't enforce name constraints against the CN, but
		// VerifyHostname will look for hostnames in there if there are no SANs.
		// In order to ensure VerifyHostname will not accept an unchecked name,
		// return an error here.
		return CertificateInvalidError{c, NameConstraintsWithoutSANs, ""}
	} else if nameConstraints && hasSANExtension(leaf) {
		err := forEachSAN(getSANExtension(leaf), func(tag int, data []byte) error {
			switch tag {
			case nameTypeEmail:
				name := string(data)
				mailbox, ok := parseRFC2821Mailbox(name)
				if !ok {
					return fmt.Errorf("x509: cannot parse rfc822Name %q", mailbox)
				}

				if err := checkNameConstraints(c, &comparisonCount, maxConstraintComparisons, "email address", name, mailbox,
					func(parsedName, constraint interface{}) (bool, error) {
						return matchEmailConstraint(parsedName.(rfc2821Mailbox), constraint.(string))
					}, c.PermittedEmailAddresses, c.ExcludedEmailAddresses); err != nil {
					return err
				}

			case nameTypeDNS:
				name := string(data)
				if _, ok := domainToReverseLabels(name); !ok {
					return fmt.Errorf("x509: cannot parse dnsName %q", name)
				}

				if err := checkNameConstraints(c, &comparisonCount, maxConstraintComparisons, "DNS name", name, name,
					func(parsedName, constraint interface{}) (bool, error) {
						return matchDomainConstraint(parsedName.(string), constraint.(string))
					}, c.PermittedDNSDomains, c.ExcludedDNSDomains); err != nil {
					return err
				}

			case nameTypeURI:
				name := string(data)
				uri, err := url.Parse(name)
				if err != nil {
					return fmt.Errorf("x509: internal error: URI SAN %q failed to parse", name)
				}

				if err := checkNameConstraints(c, &comparisonCount, maxConstraintComparisons, "URI", name, uri,
					func(parsedName, constraint interface{}) (bool, error) {
						return matchURIConstraint(parsedName.(*url.URL), constraint.(string))
					}, c.PermittedURIDomains, c.ExcludedURIDomains); err != nil {
					return err
				}

			case nameTypeIP:
				ip := net.IP(data)
				if l := len(ip); l != net.IPv4len && l != net.IPv6len {
					return fmt.Errorf("x509: internal error: IP SAN %x failed to parse", data)
				}

				if err := checkNameConstraints(c, &comparisonCount, maxConstraintComparisons, "IP address", ip.String(), ip,
					func(parsedName, constraint interface{}) (bool, error) {
						return matchIPConstraint(parsedName.(net.IP), constraint.(*net.IPNet))
					}, c.PermittedIPRanges, c.ExcludedIPRanges); err != nil {
					return err
				}

			default:
				// Unknown SAN types are ignored.
			}

			return nil
		})

		if err != nil {
			return err
		}
	}

	// KeyUsage status flags are ignored. From Engineering Security, Peter
	// Gutmann: A European government CA marked its signing certificates as
	// being valid for encryption only, but no-one noticed. Another
	// European CA marked its signature keys as not being valid for
	// signatures. A different CA marked its own trusted root certificate
	// as being invalid for certificate signing. Another national CA
	// distributed a certificate to be used to encrypt data for the
	// country’s tax authority that was marked as only being usable for
	// digital signatures but not for encryption. Yet another CA reversed
	// the order of the bit flags in the keyUsage due to confusion over
	// encoding endianness, essentially setting a random keyUsage in
	// certificates that it issued. Another CA created a self-invalidating
	// certificate by adding a certificate policy statement stipulating
	// that the certificate had to be used strictly as specified in the
	// keyUsage, and a keyUsage containing a flag indicating that the RSA
	// encryption key could only be used for Diffie-Hellman key agreement.

	if certType == intermediateCertificate && (!c.BasicConstraintsValid || !c.IsCA) {
		return CertificateInvalidError{c, NotAuthorizedToSign, ""}
	}

	if c.BasicConstraintsValid && c.MaxPathLen >= 0 {
		numIntermediates := len(currentChain) - 1
		if numIntermediates > c.MaxPathLen {
			return CertificateInvalidError{c, TooManyIntermediates, ""}
		}
	}

	return nil
}

// Verify attempts to verify c by building one or more chains from c to a
// certificate in opts.Roots, using certificates in opts.Intermediates if
// needed. If successful, it returns one or more chains where the first
// element of the chain is c and the last element is from opts.Roots.
//
// If opts.Roots is nil and system roots are unavailable the returned error
// will be of type SystemRootsError.
//
// Name constraints in the intermediates will be applied to all names claimed
// in the chain, not just opts.DNSName. Thus it is invalid for a leaf to claim
// example.com if an intermediate doesn't permit it, even if example.com is not
// the name being validated. Note that DirectoryName constraints are not
// supported.
//
// Extended Key Usage values are enforced down a chain, so an intermediate or
// root that enumerates EKUs prevents a leaf from asserting an EKU not in that
// list.
//
// WARNING: this function doesn't do any revocation checking.
func Verify(c *x509.Certificate, opts VerifyOptions) (chains [][]*x509.Certificate, err error) {
	// Platform-specific verification needs the ASN.1 contents so
	// this makes the behavior consistent across platforms.
	if len(c.Raw) == 0 {
		return nil, errors.New("x509: missing ASN.1 contents; use ParseCertificate")
	}
	if opts.Intermediates != nil {
		for _, intermediate := range opts.Intermediates.certs {
			if len(intermediate.Raw) == 0 {
				return nil, errors.New("x509: missing ASN.1 contents; use ParseCertificate")
			}
		}
	}

	// Fabric 为自签名CA系统，因此，不再调取系统根证书用于验证证书。
	// Use Windows's own verification and chain building.
	// if opts.Roots == nil && runtime.GOOS == "windows" {
	// 	return c.systemVerify(&opts)
	// }

	// if opts.Roots == nil {
	// 	opts.Roots = systemRootsPool()
	// 	if opts.Roots == nil {
	// 		return nil, SystemRootsError{systemRootsErr}
	// 	}
	// }

	if opts.Roots == nil {
		return nil, errors.New("at least one root certificate shall be provided to verify a certificate")
	}

	// 检测证书的时间、格式有效性信息，对于Fabric证书而言:
	// (1) 证书时间在检测前通过内部函数另行设置
	// (2) 证书格式通过FabricCA签发，因此，该项检测基本上没有太大意义。
	err = isValid(c, leafCertificate, nil, &opts)
	if err != nil {
		return
	}

	if len(opts.DNSName) > 0 {
		err = c.VerifyHostname(opts.DNSName)
		if err != nil {
			return
		}
	}

	var candidateChains [][]*x509.Certificate
	if opts.Roots.contains(c) {
		candidateChains = append(candidateChains, []*x509.Certificate{c})
	} else {
		if candidateChains, err = buildChains(c, nil, []*x509.Certificate{c}, nil, &opts); err != nil {
			return nil, err
		}
	}

	keyUsages := opts.KeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	// If any key usage is acceptable then we're done.
	for _, usage := range keyUsages {
		if usage == x509.ExtKeyUsageAny {
			return candidateChains, nil
		}
	}

	for _, candidate := range candidateChains {
		if checkChainForKeyUsage(candidate, keyUsages) {
			chains = append(chains, candidate)
		}
	}

	if len(chains) == 0 {
		return nil, CertificateInvalidError{c, IncompatibleUsage, ""}
	}

	return chains, nil
}

func appendToFreshChain(chain []*x509.Certificate, cert *x509.Certificate) []*x509.Certificate {
	n := make([]*x509.Certificate, len(chain)+1)
	copy(n, chain)
	n[len(chain)] = cert
	return n
}

// maxChainSignatureChecks is the maximum number of CheckSignatureFrom calls
// that an invocation of buildChains will (tranistively) make. Most chains are
// less than 15 certificates long, so this leaves space for multiple chains and
// for failed checks due to different intermediates having the same Subject.
const maxChainSignatureChecks = 100

func buildChains(c *x509.Certificate, cache map[*x509.Certificate][][]*x509.Certificate, currentChain []*x509.Certificate, sigChecks *int, opts *VerifyOptions) (chains [][]*x509.Certificate, err error) {
	var (
		hintErr  error
		hintCert *x509.Certificate
	)

	considerCandidate := func(certType int, candidate *x509.Certificate) {
		for _, cert := range currentChain {
			if cert.Equal(candidate) {
				return
			}
		}

		if sigChecks == nil {
			sigChecks = new(int)
		}
		*sigChecks++
		if *sigChecks > maxChainSignatureChecks {
			err = errors.New("x509: signature check attempts limit reached while verifying certificate chain")
			return
		}

		if err := CheckSignatureFrom(c, candidate); err != nil {
			if hintErr == nil {
				hintErr = err
				hintCert = candidate
			}
			return
		}

		err = isValid(candidate, certType, currentChain, opts)
		if err != nil {
			return
		}

		switch certType {
		case rootCertificate:
			chains = append(chains, appendToFreshChain(currentChain, candidate))
		case intermediateCertificate:
			if cache == nil {
				cache = make(map[*x509.Certificate][][]*x509.Certificate)
			}
			childChains, ok := cache[candidate]
			if !ok {
				childChains, err = buildChains(candidate, cache, appendToFreshChain(currentChain, candidate), sigChecks, opts)
				cache[candidate] = childChains
			}
			chains = append(chains, childChains...)
		}
	}

	for _, rootNum := range opts.Roots.findPotentialParents(c) {
		considerCandidate(rootCertificate, opts.Roots.certs[rootNum])
	}
	for _, intermediateNum := range opts.Intermediates.findPotentialParents(c) {
		considerCandidate(intermediateCertificate, opts.Intermediates.certs[intermediateNum])
	}

	if len(chains) > 0 {
		err = nil
	}
	if len(chains) == 0 && err == nil {
		err = UnknownAuthorityError{c, hintErr, hintCert}
	}

	return
}

// validHostname reports whether host is a valid hostname that can be matched or
// matched against according to RFC 6125 2.2, with some leniency to accommodate
// legacy values.
func validHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")

	if len(host) == 0 {
		return false
	}

	for i, part := range strings.Split(host, ".") {
		if part == "" {
			// Empty label.
			return false
		}
		if i == 0 && part == "*" {
			// Only allow full left-most wildcards, as those are the only ones
			// we match, and matching literal '*' characters is probably never
			// the expected behavior.
			continue
		}
		for j, c := range part {
			if 'a' <= c && c <= 'z' {
				continue
			}
			if '0' <= c && c <= '9' {
				continue
			}
			if 'A' <= c && c <= 'Z' {
				continue
			}
			if c == '-' && j != 0 {
				continue
			}
			if c == '_' || c == ':' {
				// Not valid characters in hostnames, but commonly
				// found in deployments outside the WebPKI.
				continue
			}
			return false
		}
	}

	return true
}

// commonNameAsHostname reports whether the Common Name field should be
// considered the hostname that the certificate is valid for. This is a legacy
// behavior, disabled if the Subject Alt Name extension is present.
//
// It applies the strict validHostname check to the Common Name field, so that
// certificates without SANs can still be validated against CAs with name
// constraints if there is no risk the CN would be matched as a hostname.
// See NameConstraintsWithoutSANs and issue 24151.
func commonNameAsHostname(c *x509.Certificate) bool {
	return !ignoreCN && !hasSANExtension(c) && validHostname(c.Subject.CommonName)
}

func checkChainForKeyUsage(chain []*x509.Certificate, keyUsages []x509.ExtKeyUsage) bool {
	usages := make([]x509.ExtKeyUsage, len(keyUsages))
	copy(usages, keyUsages)

	if len(chain) == 0 {
		return false
	}

	usagesRemaining := len(usages)

	// We walk down the list and cross out any usages that aren't supported
	// by each certificate. If we cross out all the usages, then the chain
	// is unacceptable.

NextCert:
	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]
		if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
			// The certificate doesn't have any extended key usage specified.
			continue
		}

		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageAny {
				// The certificate is explicitly good for any usage.
				continue NextCert
			}
		}

		const invalidUsage x509.ExtKeyUsage = -1

	NextRequestedUsage:
		for i, requestedUsage := range usages {
			if requestedUsage == invalidUsage {
				continue
			}

			for _, usage := range cert.ExtKeyUsage {
				if requestedUsage == usage {
					continue NextRequestedUsage
				} else if requestedUsage == x509.ExtKeyUsageServerAuth &&
					(usage == x509.ExtKeyUsageNetscapeServerGatedCrypto ||
						usage == x509.ExtKeyUsageMicrosoftServerGatedCrypto) {
					// In order to support COMODO
					// certificate chains, we have to
					// accept Netscape or Microsoft SGC
					// usages as equal to ServerAuth.
					continue NextRequestedUsage
				}
			}

			usages[i] = invalidUsage
			usagesRemaining--
			if usagesRemaining == 0 {
				return false
			}
		}
	}

	return true
}
