import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class NetPipeServer {

    private static Arguments args;

    private static void exitUsage() {
        System.err.println("Usage: NetPipeServer --port=<port> --usercert=<file> --cacert=<file> --key=<file>");
        System.exit(1);
    }

    private static void parseArguments(String[] argv) {
        args = new Arguments();
        args.setArgumentSpec("port", "port number");
        args.setArgumentSpec("usercert", "server certificate");
        args.setArgumentSpec("cacert", "CA certificate");
        args.setArgumentSpec("key", "private key");

        try {
            args.loadArguments(argv);
        } catch (IllegalArgumentException e) {
            exitUsage();
        }
    }

    public static void main(String[] argv) {
        parseArguments(argv);

        int port = Integer.parseInt(args.get("port"));

        try (ServerSocket listener = new ServerSocket(port);
             Socket connection = listener.accept()) {

            InputStream netIn = connection.getInputStream();
            OutputStream netOut = connection.getOutputStream();


            HandshakeCertificate serverCert =
                new HandshakeCertificate(new FileInputStream(args.get("usercert")));
            HandshakeCertificate caCert =
                new HandshakeCertificate(new FileInputStream(args.get("cacert")));

            serverCert.verify(caCert);

            byte[] privateKeyBytes =
                Files.readAllBytes(Paths.get(args.get("key")));
            HandshakeCrypto serverCrypto =
                new HandshakeCrypto(privateKeyBytes);


            HandshakeMessage clientHello =
                HandshakeMessage.recv(connection);

            HandshakeCertificate clientCert =
                new HandshakeCertificate(
                    Base64.getDecoder().decode(
                        clientHello.getParameter("Certificate")
                    )
                );

            clientCert.verify(caCert);
            HandshakeCrypto clientCrypto =
                new HandshakeCrypto(clientCert);


            HandshakeMessage serverHello =
                new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);

            serverHello.putParameter(
                "Certificate",
                Base64.getEncoder().encodeToString(serverCert.getBytes())
            );

            serverHello.send(connection);


            HandshakeMessage sessionMsg =
                HandshakeMessage.recv(connection);

            byte[] encryptedKey =
                Base64.getDecoder().decode(
                    sessionMsg.getParameter("SessionKey")
                );
            byte[] encryptedIV =
                Base64.getDecoder().decode(
                    sessionMsg.getParameter("SessionIV")
                );

            byte[] keyBytes = serverCrypto.decrypt(encryptedKey);
            byte[] ivBytes  = serverCrypto.decrypt(encryptedIV);

            SessionKey sessionKey = new SessionKey(keyBytes);
            SessionCipher cipher  = new SessionCipher(sessionKey, ivBytes);


            HandshakeDigest serverDigest = new HandshakeDigest();
            serverDigest.update(serverHello.getBytes());

            byte[] signedDigest =
                serverCrypto.encrypt(serverDigest.digest());

            String timestamp =
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                    .format(new Date());

            byte[] signedTime =
                serverCrypto.encrypt(timestamp.getBytes("UTF-8"));

            HandshakeMessage serverFinished =
                new HandshakeMessage(
                    HandshakeMessage.MessageType.SERVERFINISHED
                );

            serverFinished.putParameter(
                "Signature",
                Base64.getEncoder().encodeToString(signedDigest)
            );
            serverFinished.putParameter(
                "TimeStamp",
                Base64.getEncoder().encodeToString(signedTime)
            );

            serverFinished.send(connection);


            HandshakeMessage clientFinished =
                HandshakeMessage.recv(connection);

            HandshakeDigest verifyClient = new HandshakeDigest();
            verifyClient.update(clientHello.getBytes());
            verifyClient.update(sessionMsg.getBytes());

            byte[] clientSignature =
                Base64.getDecoder().decode(
                    clientFinished.getParameter("Signature")
                );

            byte[] decryptedDigest =
                clientCrypto.decrypt(clientSignature);

            if (!Arrays.equals(
                    decryptedDigest,
                    verifyClient.digest())) {
                throw new IOException("ClientFinished verification failed");
            }

            clientCrypto.decrypt(
                Base64.getDecoder().decode(
                    clientFinished.getParameter("TimeStamp")
                )
            );


            InputStream secureIn =
                cipher.openDecryptedInputStream(netIn);
            OutputStream secureOut =
                cipher.openEncryptedOutputStream(netOut);

            Forwarder.forwardStreams(
                System.in,
                System.out,
                secureIn,
                secureOut,
                connection
            );

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}