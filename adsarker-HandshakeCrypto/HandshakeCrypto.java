import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.GeneralSecurityException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

public class HandshakeCrypto {
	private final Key key;
	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
		try {
            PublicKey pKey = handshakeCertificate.getCertificate().getPublicKey();
            this.key = pKey;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */

	public HandshakeCrypto(byte[] keybytes) {
		try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keybytes);
            KeyFactory fKey = KeyFactory.getInstance("RSA");
            PrivateKey privKey = fKey.generatePrivate(spec);
            this.key = privKey;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) {
		try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte [] encrypt(byte[] plaintext) {
		try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}