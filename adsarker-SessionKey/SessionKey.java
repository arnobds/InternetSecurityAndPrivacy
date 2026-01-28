import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

class SessionKey {

    private SecretKey secretKey;

    /*
     * Constructor to create a secret key of a given length (in bits)
     */
    public SessionKey(Integer length) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(length);
            this.secretKey = keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
        this.secretKey = new SecretKeySpec(keybytes, "AES");
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return this.secretKey.getEncoded();
    }
}
