import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;


public class SessionCipher {

    private final SessionKey sessionKey;
    private final byte[] iv;

    private final Cipher encryptCipher;
    private final Cipher decryptCipher;

    public SessionCipher(SessionKey key) {
        this.sessionKey = key;
        this.iv = generateIV();
        this.encryptCipher = initCipher(Cipher.ENCRYPT_MODE, iv);
        this.decryptCipher = initCipher(Cipher.DECRYPT_MODE, iv);
    }

    public SessionCipher(SessionKey key, byte[] ivBytes) {
        this.sessionKey = key;
        this.iv = ivBytes.clone();
        this.encryptCipher = initCipher(Cipher.ENCRYPT_MODE, this.iv);
        this.decryptCipher = initCipher(Cipher.DECRYPT_MODE, this.iv);
    }

    private byte[] generateIV() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private Cipher initCipher(int mode, byte[] ivBytes) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(
                mode,
                sessionKey.getSecretKey(),
                new IvParameterSpec(ivBytes)
            );
            return cipher;
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize session cipher", e);
        }
    }

    public SessionKey getSessionKey() {
        return sessionKey;
    }

    public byte[] getIVBytes() {
        return iv.clone();
    }

    public OutputStream openEncryptedOutputStream(OutputStream out) {
        return new CipherOutputStream(out, encryptCipher);
    }

    public InputStream openDecryptedInputStream(InputStream in) {
        return new CipherInputStream(in, decryptCipher);
    }
}