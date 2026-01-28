import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {
    private final MessageDigest md;

    public HandshakeDigest() {
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public void update(byte[] input) {
        md.update(input);
    }

    public byte[] digest() {
        return md.digest();
    }
}
