import java.io.FileInputStream;
import java.io.IOException;
import java.util.Base64;

public class FileDigest {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java FileDigest <filename>");
            System.exit(1);
        }

        String filename = args[0];
        try (FileInputStream in = new FileInputStream(filename)) {
            HandshakeDigest hd = new HandshakeDigest();
            byte[] buffer = new byte[4096];
            int a;

            while ((a = in.read(buffer)) != -1) {
                // Only feed the bytes actually read
                hd.update(java.util.Arrays.copyOf(buffer, a));
            }
            byte[] digest = hd.digest();
            String encoded = Base64.getEncoder().encodeToString(digest);
            System.out.println(encoded);

        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
}
