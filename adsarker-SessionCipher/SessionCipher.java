import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SessionCipher {
    private Cipher encCipher;
    private Cipher decCipher;
    private byte[] iv;
    private SessionKey sessionKey;
    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) {
        try {
            this.sessionKey = key;
            SecretKey sk = key.getSecretKey();
            iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            encCipher = Cipher.getInstance("AES/CTR/NoPadding");
            encCipher.init(Cipher.ENCRYPT_MODE, sk, ivSpec);
            decCipher = Cipher.getInstance("AES/CTR/NoPadding");
            decCipher.init(Cipher.DECRYPT_MODE, sk, ivSpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */
    public SessionCipher(SessionKey key, byte[] ivbytes) {
        try {
            this.sessionKey = key;
            this.iv = ivbytes;
            SecretKey sk = key.getSecretKey();
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            encCipher = Cipher.getInstance("AES/CTR/NoPadding");
            encCipher.init(Cipher.ENCRYPT_MODE, sk, ivSpec);
            decCipher = Cipher.getInstance("AES/CTR/NoPadding");
            decCipher.init(Cipher.DECRYPT_MODE, sk, ivSpec);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return sessionKey;
    }
    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return iv;
    }
    /*
     * Attach OutputStream to which encrypted data will be written.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) {
        return new CipherOutputStream(os, encCipher);
    }
    /*
     * Attach InputStream from which decrypted data will be read.
     */
    CipherInputStream openDecryptedInputStream(InputStream inputstream) {
        return new CipherInputStream(inputstream, decCipher);
    }
}