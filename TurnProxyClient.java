import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TurnProxyClient {
    public static void main(String[] args) {
        try {
            InetSocketAddress turnServerAddress = new InetSocketAddress("stunturn.com", 3478);
            String username = "root";
            String password = "root";
            InetSocketAddress peerAddress = parseSocketAddress("192.168.1.4:5000"); // Replace with your value
            String script = "/bin/echo";
            InetSocketAddress forwardAddress = parseSocketAddress("192.168.1.2:5599"); // Replace with your value

            TurnClient turnClient = new TurnClient(turnServerAddress, username, password);
            InetSocketAddress relayAddress = turnClient.allocateRelayAddress();
            turnClient.addPermission(peerAddress);

            runScript(script, relayAddress);

            DatagramSocket turnSocket = new DatagramSocket();
            DatagramSocket forwardSocket = new DatagramSocket();

            new DataForwarder(turnSocket, forwardSocket, peerAddress, forwardAddress).start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddressString) {
        String[] parts = socketAddressString.split(":");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid socket address format: " + socketAddressString);
        }
        String host = parts[0];
        int port = Integer.parseInt(parts[1]);
        return new InetSocketAddress(host, port);
    }

    private static void runScript(String script, InetSocketAddress relayAddress)
            throws IOException, InterruptedException {
        String relayAddressString = relayAddress.getAddress().getHostAddress() + ":" + relayAddress.getPort();
        ProcessBuilder processBuilder = new ProcessBuilder(Arrays.asList(script, relayAddressString));
        Process process = processBuilder.start();
        process.waitFor();
    }

    private static class DataForwarder extends Thread {
        private final DatagramSocket turnSocket;
        private final DatagramSocket forwardSocket;
        private final InetSocketAddress peerAddress;
        private final InetSocketAddress forwardAddress;

        public DataForwarder(DatagramSocket turnSocket, DatagramSocket forwardSocket, InetSocketAddress peerAddress,
                InetSocketAddress forwardAddress) {
            this.turnSocket = turnSocket;
            this.forwardSocket = forwardSocket;
            this.peerAddress = peerAddress;
            this.forwardAddress = forwardAddress;
        }

        @Override
        public void run() {
            try {
                byte[] buffer = new byte[1024];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

                while (true) {
                    turnSocket.receive(packet);
                    byte[] data = Arrays.copyOf(packet.getData(), packet.getLength());
                    forwardSocket.send(new DatagramPacket(data, data.length, forwardAddress));

                    forwardSocket.receive(packet);
                    data = Arrays.copyOf(packet.getData(), packet.getLength());
                    turnSocket.send(new DatagramPacket(data, data.length, peerAddress));
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    // private static class TurnClient {
    // private final InetSocketAddress turnServerAddress;
    // private final String username;
    // private final String password;

    // public TurnClient(InetSocketAddress turnServerAddress, String username,
    // String password) {
    // this.turnServerAddress = turnServerAddress;
    // this.username = username;
    // this.password = password;
    // }

    // public InetSocketAddress allocateRelayAddress() {
    // // Implement TURN client logic to allocate a relay address

    // return new InetSocketAddress("127.0.0.1", 12345); // Replace with actual
    // relay address
    // }

    // public void addPermission(InetSocketAddress peerAddress) {
    // // Implement TURN client logic to add permission for the peer address
    // }
    // }

    private static class TurnClient {
        private final InetSocketAddress turnServerAddress;
        private final String username;
        private final String password;
        private InetSocketAddress relayAddress;

        public TurnClient(InetSocketAddress turnServerAddress, String username, String password) {
            this.turnServerAddress = turnServerAddress;
            this.username = username;
            this.password = password;
        }

        public InetSocketAddress allocateRelayAddress() throws IOException, NoSuchAlgorithmException, InvalidKeyException {
            if (relayAddress != null) {
                return relayAddress;
            }

            DatagramSocket socket = new DatagramSocket();
            byte[] requestData = createAllocateRequest();
            //print out the request data
            System.out.println("Request Data: " + new String(requestData, StandardCharsets.UTF_8));
            DatagramPacket requestPacket = new DatagramPacket(requestData, requestData.length, turnServerAddress);
            socket.send(requestPacket);

            byte[] buffer = new byte[1024];
            DatagramPacket responsePacket = new DatagramPacket(buffer, buffer.length);
            socket.receive(responsePacket);

            relayAddress = parseRelayAddressFromResponse(responsePacket.getData(), responsePacket.getLength());
            socket.close();

            return relayAddress;
        }

        // private byte[] createAllocateRequest() {
        // // Implement TURN request encoding logic here
        // // This should create a byte array containing the ALLOCATE request
        // // with appropriate headers and payload
        // return new byte[0]; // Replace with the actual request data
        // }

        private byte[] createAllocateRequest() throws NoSuchAlgorithmException, InvalidKeyException {
            // TURN message header
            short messageType = 0x0003; // ALLOCATE request
            short messageLength = 0; // Will be set later

            // Transaction ID
            byte[] transactionId = generateTransactionId();

            // Attribute header constants
            short attributeType = 0x0020; // REQUESTED-TRANSPORT attribute
            short attributeLength = 0x0004; // Length of the attribute value
            // int protocol = 0x0011000000; // UDP protocol
            int protocol = 0x0006000000; // TCP protocol

            // Authentication (if required)
            byte[] authenticationData = null;
            // if (username != null && password != null) {
            //     authenticationData = createAuthenticationData(transactionId);
            // }

            // Calculate the overall message length
            messageLength = (short) (20 + (authenticationData != null ? authenticationData.length : 0) + 8);

            // Build the ALLOCATE request message
            ByteBuffer buffer = ByteBuffer
                    .allocate(20 + (authenticationData != null ? authenticationData.length : 0) + 8);
            buffer.putShort(messageType);
            buffer.putShort(messageLength);
            buffer.put(transactionId);
            // if (authenticationData != null) {
            //     buffer.put(authenticationData);
            // }
            buffer.putShort(attributeType);
            buffer.putShort(attributeLength);
            buffer.putInt(protocol);

            return buffer.array();
        }

        private byte[] generateTransactionId() {
            byte[] transactionId = new byte[16];
            new Random().nextBytes(transactionId);
            return transactionId;
        }

        private byte[] createAuthenticationData(byte[] transactionId) throws NoSuchAlgorithmException, InvalidKeyException {
            byte[] key = calculateKey();
            byte[] data = Arrays.copyOf(transactionId, 28);
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(key);
            md.update(data);
            byte[] authenticationData = md.digest();
            return authenticationData;
        }

        // private byte[] calculateKey() {
        // // Implement key calculation logic based on username, password, and realm
        // return new byte[0]; // Replace with the actual key calculation logic
        // }

        private byte[] calculateKey() throws NoSuchAlgorithmException, InvalidKeyException {
            String realm = "example.com"; // Replace with the actual realm
            byte[] key = new byte[0];

            // Calculate the key as per RFC 5766
            if (username != null && password != null) {
                String input = username + ":" + realm + ":" + password;
                byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);

                Mac mac = Mac.getInstance("HmacSHA1");
                SecretKeySpec keySpec = new SecretKeySpec(new byte[16], "HmacSHA1");
                mac.init(keySpec);
                key = mac.doFinal(inputBytes);
            }

            return key;
        }

        // private InetSocketAddress parseRelayAddressFromResponse(byte[] responseData, int length) {
        //     // Implement TURN response decoding logic here
        //     // This should parse the relay address from the response data
        //     return new InetSocketAddress("127.0.0.1", 12345); // Replace with actual relay address parsing logic
        // }

        private InetSocketAddress parseRelayAddressFromResponse(byte[] responseData, int length) {
            ByteBuffer buffer = ByteBuffer.wrap(responseData, 0, length);
    
            // Skip the header (20 bytes)
            buffer.position(20);
    
            while (buffer.hasRemaining()) {
                short attributeType = buffer.getShort();
                short attributeLength = buffer.getShort();
                int valueLength = attributeLength & 0xFFFF;
    
                if (attributeType == 0x0020) { // RELAYED-ADDRESS attribute
                    int family = buffer.getShort() & 0xFFFF;
                    int port = buffer.getShort() & 0xFFFF;
                    byte[] addressBytes = new byte[valueLength - 4];
                    buffer.get(addressBytes);
    
                    String address = convertIPv4BytesToString(addressBytes);
                    return new InetSocketAddress(address, port);
                } else {
                    // Skip over unknown attributes
                    buffer.position(buffer.position() + valueLength);
                }
            }
    
            // Relay address not found
            return null;
        }
    
        private String convertIPv4BytesToString(byte[] addressBytes) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < addressBytes.length; i++) {
                sb.append(addressBytes[i] & 0xFF);
                if (i < addressBytes.length - 1) {
                    sb.append(".");
                }
            }
            return sb.toString();
        }

        // public void addPermission(InetSocketAddress peerAddress) {
        //     // Implement TURN client logic to add permission for the peer address
        // }
        public void addPermission(InetSocketAddress peerAddress) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
            if (relayAddress == null) {
                throw new IllegalStateException("Relay address not allocated");
            }
    
            DatagramSocket socket = new DatagramSocket();
            byte[] requestData = createCreatePermissionRequest(peerAddress);
            DatagramPacket requestPacket = new DatagramPacket(requestData, requestData.length, turnServerAddress);
            socket.send(requestPacket);
    
            byte[] buffer = new byte[1024];
            DatagramPacket responsePacket = new DatagramPacket(buffer, buffer.length);
            socket.receive(responsePacket);
    
            // Handle the response from the TURN server
            // You may need to add additional logic to handle errors or other response types
    
            socket.close();
        }
    
        private byte[] createCreatePermissionRequest(InetSocketAddress peerAddress) throws NoSuchAlgorithmException, InvalidKeyException {
            byte[] transactionId = generateTransactionId();
            byte[] authenticationData = createAuthenticationData(transactionId);
    
            short messageType = 0x0008; // CreatePermission request
            short messageLength = (short) (28 + authenticationData.length + 8);
    
            ByteBuffer buffer = ByteBuffer.allocate(messageLength);
            buffer.putShort(messageType);
            buffer.putShort(messageLength);
            buffer.put(transactionId);
            buffer.put(authenticationData);
            buffer.putShort((short) 0x0020); // XOR-RELAYED-ADDRESS attribute
            buffer.putShort((short) 8);
            buffer.putShort((short) 0x0001); // IPv4 address family
            buffer.putShort((short) peerAddress.getPort());
            buffer.putInt(peerAddress.getAddress().hashCode());
    
            return buffer.array();
        }
    }
}
