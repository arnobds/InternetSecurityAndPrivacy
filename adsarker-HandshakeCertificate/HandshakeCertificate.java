import java.io.InputStream;
import java.io.ByteArrayInputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {
    private final X509Certificate cert;
    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            this.cert = (X509Certificate) cf.generateCertificate(instream);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream bais = new ByteArrayInputStream(certbytes);
            this.cert = (X509Certificate) cf.generateCertificate(bais);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() {
        try {
            return cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return cert;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        cert.verify(cacert.getCertificate().getPublicKey());
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        String dn = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
        String[] n = dn.split(",");

        for (String i : n) {
            i = i.trim();
            if (i.startsWith("CN=")) {
                return i.substring(3);
            }
        }
        return null;
    }

    /*
     * return email address of subject
     */
    public String getEmail() {
    String dn = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
    String[] n = dn.split(",");

    for (String i : n) {
        i = i.trim();
        if (i.startsWith("1.2.840.113549.1.9.1=")) {
            String value = i.substring("1.2.840.113549.1.9.1=".length());

            if (value.startsWith("#")) {
                return decodeASN1Email(value.substring(1));
            } else {
                return value;
            }
        }
    }
    return null;
}

private String decodeASN1Email(String hex) {
    int len = hex.length();
    byte[] data = new byte[len / 2];

    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) (
            (Character.digit(hex.charAt(i), 16) << 4)
          +  Character.digit(hex.charAt(i + 1), 16)
        );
    }
    if (data.length > 2) {
        return new String(data, 2, data.length - 2);
    } else {
        return new String(data);
    }
    }
}