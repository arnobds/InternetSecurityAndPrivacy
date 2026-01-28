import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class NetPipeClient {

    private static Arguments args;

    private static void showUsage() {
        System.err.println(
            "Usage: NetPipeClient --host=<host> --port=<port> " +
            "--usercert=<file> --cacert=<file> --key=<file>"
        );
        System.exit(1);
    }

    private static void loadArgs(String[] argv) {
        args = new Arguments();
        args.setArgumentSpec("host", "hostname");
        args.setArgumentSpec("port", "port");
        args.setArgumentSpec("usercert", "certificate");
        args.setArgumentSpec("cacert", "ca certificate");
        args.setArgumentSpec("key", "private key");

        try {
            args.loadArguments(argv);
        } catch (IllegalArgumentException e) {
            showUsage();
        }
    }

    public static void main(String[] argv) {
        loadArgs(argv);

        String host = args.get("host");
        int port = Integer.parseInt(args.get("port"));

        try (Socket socket = new Socket(host, port)) {

            InputStream netIn = socket.getInputStream();
            OutputStream netOut = socket.getOutputStream();


            HandshakeCertificate clientCert =
                new HandshakeCertificate(
                    new FileInputStream(args.get("usercert"))
                );
            HandshakeCertificate caCert =
                new HandshakeCertificate(
                    new FileInputStream(args.get("cacert"))
                );

            clientCert.verify(caCert);

            byte[] privateKeyBytes =
                Files.readAllBytes(Paths.get(args.get("key")));
            HandshakeCrypto clientCrypto =
                new HandshakeCrypto(privateKeyBytes);


            HandshakeMessage clientHello =
                new HandshakeMessage(
                    HandshakeMessage.MessageType.CLIENTHELLO
                );

            clientHello.putParameter(
                "Certificate",
                Base64.getEncoder().encodeToString(clientCert.getBytes())
            );

            clientHello.send(socket);


            HandshakeMessage serverHello =
                HandshakeMessage.recv(socket);

            HandshakeCertificate serverCert =
                new HandshakeCertificate(
                    Base64.getDecoder().decode(
                        serverHello.getParameter("Certificate")
                    )
                );

            serverCert.verify(caCert);

            HandshakeCrypto serverCrypto =
                new HandshakeCrypto(serverCert);


            SessionKey sessionKey = new SessionKey(128);
            SessionCipher cipher = new SessionCipher(sessionKey);

            byte[] encryptedKey =
                serverCrypto.encrypt(sessionKey.getKeyBytes());
            byte[] encryptedIV =
                serverCrypto.encrypt(cipher.getIVBytes());

            HandshakeMessage sessionMsg =
                new HandshakeMessage(
                    HandshakeMessage.MessageType.SESSION
                );

            sessionMsg.putParameter(
                "SessionKey",
                Base64.getEncoder().encodeToString(encryptedKey)
            );
            sessionMsg.putParameter(
                "SessionIV",
                Base64.getEncoder().encodeToString(encryptedIV)
            );

            sessionMsg.send(socket);


            HandshakeDigest clientDigest = new HandshakeDigest();
            clientDigest.update(clientHello.getBytes());
            clientDigest.update(sessionMsg.getBytes());

            byte[] signedDigest =
                clientCrypto.encrypt(clientDigest.digest());

            String timestamp =
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                    .format(new Date());

            byte[] signedTime =
                clientCrypto.encrypt(timestamp.getBytes("UTF-8"));

            HandshakeMessage clientFinished =
                new HandshakeMessage(
                    HandshakeMessage.MessageType.CLIENTFINISHED
                );

            clientFinished.putParameter(
                "Signature",
                Base64.getEncoder().encodeToString(signedDigest)
            );
            clientFinished.putParameter(
                "TimeStamp",
                Base64.getEncoder().encodeToString(signedTime)
            );

            clientFinished.send(socket);


            HandshakeMessage serverFinished =
                HandshakeMessage.recv(socket);

            byte[] serverSignature =
                Base64.getDecoder().decode(
                    serverFinished.getParameter("Signature")
                );

            byte[] decryptedDigest =
                serverCrypto.decrypt(serverSignature);

            HandshakeDigest verifyServer = new HandshakeDigest();
            verifyServer.update(serverHello.getBytes());

            if (!Arrays.equals(
                    decryptedDigest,
                    verifyServer.digest())) {
                throw new IOException("ServerFinished verification failed");
            }

            serverCrypto.decrypt(
                Base64.getDecoder().decode(
                    serverFinished.getParameter("TimeStamp")
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
                socket
            );

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}