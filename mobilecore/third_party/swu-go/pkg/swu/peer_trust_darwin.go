//go:build darwin && cgo

package swu

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Use the system anchors with a basic X.509 policy: Go's standard Darwin
// verifier uses a TLS policy that rejects valid IKE-only EKUs. Network fetch
// is explicitly disabled, so certificate URLs never initiate a second path.
static int verifyIKEChain(const uint8_t *der, const size_t *lengths, int count, int peerCount, double date, long *detail, uint8_t **verified, size_t *verifiedLen) {
    int result = 1;
    CFMutableArrayRef certs = CFArrayCreateMutable(NULL, count, &kCFTypeArrayCallBacks);
    SecPolicyRef policy = NULL;
    SecTrustRef trust = NULL;
    CFDateRef verifyDate = NULL;
    CFErrorRef error = NULL;
    CFArrayRef chain = NULL;
    if (!certs) return 1;
    size_t offset = 0;
    for (int i = 0; i < count; i++) {
        CFDataRef data = CFDataCreate(NULL, der + offset, lengths[i]);
        if (!data) goto cleanup;
        SecCertificateRef cert = SecCertificateCreateWithData(NULL, data);
        CFRelease(data);
        if (!cert) goto cleanup;
        CFArrayAppendValue(certs, cert);
        CFRelease(cert);
        offset += lengths[i];
    }
    policy = SecPolicyCreateBasicX509();
    if (!policy) goto cleanup;
    if (SecTrustCreateWithCertificates(certs, policy, &trust) != errSecSuccess || !trust) goto cleanup;
    if (SecTrustSetNetworkFetchAllowed(trust, false) != errSecSuccess) goto cleanup;
    verifyDate = CFDateCreate(NULL, date);
    if (!verifyDate || SecTrustSetVerifyDate(trust, verifyDate) != errSecSuccess) goto cleanup;
    if (!SecTrustEvaluateWithError(trust, &error)) {
        if (error) *detail = CFErrorGetCode(error);
        result = 2;
        goto cleanup;
    }
    // Reject extraneous certificates even if the system can build another
    // valid chain from its own store. Peer-supplied roots are not anchors.
    // Optional local candidates are only building material and may be unused.
    chain = SecTrustCopyCertificateChain(trust);
    if (!chain) goto cleanup;
    for (int i = 0; i < peerCount; i++) {
        Boolean found = false;
        SecCertificateRef supplied = (SecCertificateRef)CFArrayGetValueAtIndex(certs, i);
        CFIndex chainCount = CFArrayGetCount(chain);
        for (CFIndex j = 0; j < chainCount; j++) {
            SecCertificateRef member = (SecCertificateRef)CFArrayGetValueAtIndex(chain, j);
            if (member && CFEqual(supplied, member)) { found = true; break; }
        }
        if (!found) { result = 3; goto cleanup; }
    }
    // Return the entire validated chain for application-purpose EKU checks,
    // including intermediates loaded from the system cache rather than CERT.
    if (CFArrayGetCount(chain) > 16) goto cleanup;
    size_t total = 0;
    for (CFIndex i = 0; i < CFArrayGetCount(chain); i++) {
        CFDataRef data = SecCertificateCopyData((SecCertificateRef)CFArrayGetValueAtIndex(chain, i));
        if (!data) goto cleanup;
        total += CFDataGetLength(data);
        CFRelease(data);
    }
    if (total == 0 || total > 1024 * 1024) goto cleanup;
    *verified = malloc(total);
    if (!*verified) goto cleanup;
    *verifiedLen = total;
    offset = 0;
    for (CFIndex i = 0; i < CFArrayGetCount(chain); i++) {
        CFDataRef data = SecCertificateCopyData((SecCertificateRef)CFArrayGetValueAtIndex(chain, i));
        if (!data) { free(*verified); *verified = NULL; *verifiedLen = 0; goto cleanup; }
        size_t size = CFDataGetLength(data);
        memcpy(*verified + offset, CFDataGetBytePtr(data), size);
        offset += size;
        CFRelease(data);
    }
    result = 0;
cleanup:
    if (chain) CFRelease(chain);
    if (error) CFRelease(error);
    if (verifyDate) CFRelease(verifyDate);
    if (trust) CFRelease(trust);
    if (policy) CFRelease(policy);
    CFRelease(certs);
    return result;
}
*/
import "C"

import (
	"crypto/x509"
	"time"
	"unsafe"
)

// iOS implies the darwin build tag. Callers independently check leaf naming,
// identity, EKU, key usage, validity and the IKE transcript signature.
func verifySystemIKECertificates(certs []*x509.Certificate, name string, now time.Time) error {
	return verifySystemPeerCertificates(certs, nil, name, now, CertificatePurposeIKE)
}

func verifySystemPeerCertificates(certs, local []*x509.Certificate, name string, now time.Time, purpose string) error {
	if len(certs) == 0 || len(certs) > 8 || len(local) > 8 {
		return certificateError("certificate_chain_limit", nil)
	}
	if purpose != CertificatePurposeIKE && purpose != CertificatePurposeServerAuth {
		return certificateError("certificate_expected_identity_invalid", nil)
	}
	// BasicX509 does not authorize DNS identities. Always check the configured
	// public certificate name ourselves, independently of any IDr aliases.
	if err := certs[0].VerifyHostname(name); err != nil {
		return certificateError("certificate_hostname_mismatch", err)
	}
	all := append(append([]*x509.Certificate(nil), certs...), local...)
	var data []byte
	lengths := make([]C.size_t, len(all))
	for i, cert := range all {
		data = append(data, cert.Raw...)
		lengths[i] = C.size_t(len(cert.Raw))
	}
	var detail C.long
	var verified *C.uint8_t
	var verifiedLen C.size_t
	// CFAbsoluteTime is seconds since 2001-01-01, not the Unix epoch.
	date := float64(now.Unix()-978307200) + float64(now.Nanosecond())/1e9
	code := C.verifyIKEChain((*C.uint8_t)(unsafe.Pointer(&data[0])), &lengths[0], C.int(len(all)), C.int(len(certs)), C.double(date), &detail, &verified, &verifiedLen)
	if verified != nil {
		defer C.free(unsafe.Pointer(verified))
	}
	if code != 0 {
		return appleCertificateError(int(code), int(detail))
	}
	chain, err := x509.ParseCertificates(C.GoBytes(unsafe.Pointer(verified), C.int(verifiedLen)))
	if err != nil {
		return certificateError("certificate_trust_internal", err)
	}
	return validatePeerCertificateChains([][]*x509.Certificate{chain}, certs, purpose)
}
