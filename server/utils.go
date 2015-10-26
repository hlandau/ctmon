package server

import "crypto/x509"
import "crypto/x509/pkix"
import "regexp"
import "strings"
import "bytes"
import "bufio"
import "fmt"

func getCertificateHostnames(cert *x509.Certificate) map[string]struct{} {
	hostnames := map[string]struct{}{}
	for _, name := range cert.DNSNames {
		if isValidDomain(name) {
			hostnames[normalizeDomain(name)] = struct{}{}
		}
	}

	if isValidDomain(cert.Subject.CommonName) {
		hostnames[normalizeDomain(cert.Subject.CommonName)] = struct{}{}
	}

	return hostnames
}

// allow * as a special case, even though that isn't really valid
var re_domain = regexp.MustCompilePOSIX(`^([a-zA-Z0-9_-]{1,63}\.|\*\.)*[a-zA-Z0-9_-]{1,63}$`)

func isValidDomain(s string) bool {
	s = strings.TrimSuffix(s, ".")
	return len(s) <= 255 && re_domain.MatchString(s)
}

func normalizeDomain(s string) string {
	return strings.TrimSuffix(strings.ToLower(s), ".")
}

func certString(cert *x509.Certificate) string {
	var b bytes.Buffer
	w := bufio.NewWriter(&b)

	fmt.Fprintf(w, "---------------------------------------------------\n")
	fmt.Fprintf(w, "Certificate\n")
	fmt.Fprintf(w, "  Version: %d\n", cert.Version)
	fmt.Fprintf(w, "  Serial:  %v\n", cert.SerialNumber)
	fmt.Fprintf(w, "  DNS SANs: %v\n", cert.DNSNames)
	fmt.Fprintf(w, "  IP SANs: %v\n", cert.IPAddresses)
	fmt.Fprintf(w, "  E. mail SANs: %v\n", cert.EmailAddresses)
	fmt.Fprintf(w, "  Subject: %v\n", nameString(&cert.Subject))
	fmt.Fprintf(w, "  Issuer: %v\n", nameString(&cert.Issuer))
	fmt.Fprintf(w, "  Not Before: %v\n", cert.NotBefore)
	fmt.Fprintf(w, "  Not After: %v\n", cert.NotAfter)
	fmt.Fprintf(w, "  Key Usage: %s\n", keyUsageString(cert.KeyUsage))
	fmt.Fprintf(w, "  Extended Key Usage:\n")
	for _, eku := range cert.ExtKeyUsage {
		fmt.Fprintf(w, "    %s\n", extendedKeyUsageString(eku))
	}
	if cert.BasicConstraintsValid {
		fmt.Fprintf(w, "  Basic Constraints:\n")
		fmt.Fprintf(w, "    CA: %v\n", cert.IsCA)
		if cert.MaxPathLenZero {
			fmt.Fprintf(w, "    Max. Path Len: 0\n")
		} else if cert.MaxPathLen == 0 {
			fmt.Fprintf(w, "    Max. Path Len: ???\n")
		} else {
			fmt.Fprintf(w, "    Max. Path Len: %v\n", cert.MaxPathLen)
		}
	}
	for _, ocsp := range cert.OCSPServer {
		fmt.Fprintf(w, "  OCSP Server: %s\n", ocsp)
	}
	for _, url := range cert.IssuingCertificateURL {
		fmt.Fprintf(w, "  Issuing Certificate URL: %s\n", url)
	}
	w.Flush()

	return b.String()
}

func extendedKeyUsageString(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageServerAuth:
		return "server-auth"
	case x509.ExtKeyUsageClientAuth:
		return "client-auth"
	case x509.ExtKeyUsageCodeSigning:
		return "code-signing"
	case x509.ExtKeyUsageEmailProtection:
		return "email-protection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "ipsec-end-system"
	case x509.ExtKeyUsageIPSECTunnel:
		return "ipsec-tunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "ipsec-user"
	case x509.ExtKeyUsageTimeStamping:
		return "timestamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "ocsp-signing"
	default:
		return "???"
	}
}

func nameString(name *pkix.Name) string {
	var parts []string
	for _, c := range name.Country {
		parts = append(parts, "C="+c)
	}
	for _, o := range name.Organization {
		parts = append(parts, "O="+o)
	}
	for _, ou := range name.OrganizationalUnit {
		parts = append(parts, "OU="+ou)
	}
	for _, l := range name.Locality {
		parts = append(parts, "L="+l)
	}
	for _, p := range name.Province {
		parts = append(parts, "P="+p)
	}
	for _, sa := range name.StreetAddress {
		parts = append(parts, "SA="+sa)
	}
	for _, pc := range name.PostalCode {
		parts = append(parts, "PC="+pc)
	}
	parts = append(parts, "CN="+name.CommonName)
	return strings.Join(parts, ", ")
}

func keyUsageString(ku x509.KeyUsage) string {
	s := ""
	if (ku & x509.KeyUsageDigitalSignature) != 0 {
		s += "ds "
	}
	if (ku & x509.KeyUsageContentCommitment) != 0 {
		s += "cc "
	}
	if (ku & x509.KeyUsageKeyEncipherment) != 0 {
		s += "ke "
	}
	if (ku & x509.KeyUsageDataEncipherment) != 0 {
		s += "de "
	}
	if (ku & x509.KeyUsageKeyAgreement) != 0 {
		s += "ka "
	}
	if (ku & x509.KeyUsageCertSign) != 0 {
		s += "certsign "
	}
	if (ku & x509.KeyUsageCRLSign) != 0 {
		s += "crlsign "
	}
	if (ku & x509.KeyUsageEncipherOnly) != 0 {
		s += "encipher-only "
	}
	if (ku & x509.KeyUsageDecipherOnly) != 0 {
		s += "decipher-only "
	}
	return s
}
