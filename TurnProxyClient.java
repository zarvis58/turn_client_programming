package tutorial;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TurnProxyClient {
    private static final String SERVER_IP = "128.199.182.239";
    private static final int SERVER_PORT = 3478;
    private static final String USERNAME = "root";
    private static final String PASSWORD = "root";
    private static final int XOR_MASK = 0x2112A442;

    // public static void main(String[] args) {
    // try {
    // // Create a socket to connect to the TURN server
    // Socket socket = new Socket(SERVER_IP, SERVER_PORT);
    // InputStream inputStream = socket.getInputStream();
    // OutputStream outputStream = socket.getOutputStream();

    // // Send initial allocate request to the TURN server
    // byte[] initialRequest = createAllocateRequest();
    // outputStream.write(initialRequest);

    // // Receive response from the TURN server
    // byte[] responseBuffer = new byte[512];
    // int bytesRead = inputStream.read(responseBuffer);

    // // Parse the response to check for 401 Unauthorized
    // if (isUnauthorizedResponse(responseBuffer, bytesRead)) {
    // System.out.println("Received 401 Unauthorized response. Extracting nonce and
    // realm...");

    // String nonce = extractNonce(responseBuffer);
    // String realm = extractRealm(responseBuffer);

    // System.out.println("Nonce: " + nonce);
    // System.out.println("Realm: " + realm);

    // // Send authenticated allocate request
    // byte[] authenticatedRequest = createAuthenticatedAllocateRequest(nonce,
    // realm);
    // outputStream.write(authenticatedRequest);

    // // Receive the final response
    // bytesRead = inputStream.read(responseBuffer);
    // printReadableResponse(responseBuffer, bytesRead);
    // } else {
    // printReadableResponse(responseBuffer, bytesRead);
    // //printResponse(responseBuffer);
    // }

    // socket.close();
    // } catch (Exception e) {
    // e.printStackTrace();
    // }
    // }

    public static void main(String[] args) {
        try {
            // Create a socket to connect to the TURN server
            Socket socket = new Socket(SERVER_IP, SERVER_PORT);
            InputStream inputStream = socket.getInputStream();
            OutputStream outputStream = socket.getOutputStream();

            // Send initial allocate request to the TURN server
            byte[] initialRequest = createAllocateRequest();
            outputStream.write(initialRequest);

            // Receive response from the TURN server
            byte[] responseBuffer = new byte[512];
            int bytesRead = inputStream.read(responseBuffer);

            // Parse the response to check for 401 Unauthorized
            if (isUnauthorizedResponse(responseBuffer, bytesRead)) {
                System.out.println("Received 401 Unauthorized response. Extracting nonce and realm...");

                String nonce = extractNonce(responseBuffer);
                String realm = extractRealm(responseBuffer);

                System.out.println("Nonce: " + nonce);
                System.out.println("Realm: " + realm);

                // Send authenticated allocate request
                byte[] authenticatedRequest = createAuthenticatedAllocateRequest(nonce, realm);
                outputStream.write(authenticatedRequest);

                // Receive the final response
                bytesRead = inputStream.read(responseBuffer);
                printResponse(responseBuffer, bytesRead);

                // Extract the allocated relay address
                InetSocketAddress relayAddress = extractRelayAddress(responseBuffer);
                // print the relay address as human readable
                System.out.println("Relay Address: " + relayAddress);

                // Send a message to the peer at 192.168.1.4:5963 through the TURN server
                String message = "Hello, Peer!";
                sendMessageToPeer(relayAddress, "192.168.1.4", 5963, message);
            } else {
                printResponse(responseBuffer, bytesRead);
                String nonce = extractNonce(responseBuffer);
                String realm = extractRealm(responseBuffer);

                System.out.println("Nonce: " + nonce);
                System.out.println("Realm: " + realm);



                // Extract the allocated relay address
                InetSocketAddress relayAddress = extractRelayAddress(responseBuffer);
                // get peerIp and peerPort from relayAddress
                String relayedIP = relayAddress.getAddress().getHostAddress();
                int relayedPort = relayAddress.getPort();

                // Extract the mapped address
                InetSocketAddress mappedAddress = extractMappedAddress(responseBuffer);
                String mappedIP = mappedAddress.getAddress().getHostAddress();
                int mappedPort = mappedAddress.getPort();
                //write them in a text file
                try {
                    FileWriter myWriter = new FileWriter("mappedAddress.txt");
                    myWriter.write("Mapped IP: " + relayedIP + "\n");
                    myWriter.write("Mapped Port: " + relayedPort + "\n");
                    myWriter.close();
                    System.out.println("Successfully wrote to the file.");
                } catch (IOException e) {
                    System.out.println("An error occurred.");
                    e.printStackTrace();
                }

                // system need to wait 10 sec so that the peer can connect to the TURN server
                // System.out.println("Waiting for peer to connect...");
                
                //Thread.sleep(20000); // 20 seconds    
                //sleep for 2 sec
                Thread.sleep(2000); // 2 seconds
                             


                // // Send a message to the peer at 192.168.1.4:5963 through the TURN server
                // String message = "Hello, Peer!";
                // sendMessageToPeer(relayAddress, "192.168.1.4", 5963, message);

                //3. Send Data to Peer via TURN Server
                String message = "Hello, peer (through TURN)!";
                byte[] data = message.getBytes();

                //Call createSendIndication without nonce and realm
                byte[] sendData = createSendIndication(relayedIP, relayedPort, data);
                outputStream.write(sendData);
                outputStream.flush();

            }

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] createSendIndication(String peerIp, int peerPort, byte[] data) throws UnknownHostException {
        ByteBuffer buffer = ByteBuffer.allocate(512);
        buffer.order(ByteOrder.BIG_ENDIAN);
        buffer.putShort((short) 0x0016); // Message Type: Send
        buffer.putShort((short) 0x0000); // Placeholder for Message Length
        buffer.putInt(0x2112A442); // Magic Cookie
        buffer.put(generateTransactionID()); // Transaction ID

        byte[] xorPeerAddress = createXorPeerAddress(peerIp, peerPort);
        addAttribute(buffer, (short) 0x0012, xorPeerAddress); // XOR-PEER-ADDRESS
        addAttribute(buffer, (short) 0x0013, data); // DATA

        // NO NEED to add USERNAME, REALM, NONCE, or MESSAGE-INTEGRITY

        int length = buffer.position() - 20;
        buffer.putShort(2, (short) length); // Update Message Length

        byte[] request = new byte[buffer.position()];
        buffer.rewind();
        buffer.get(request);

        return request;
    }

    private static byte[] createXorPeerAddress(String peerIp, int peerPort) throws UnknownHostException {
        byte[] xorPeerAddress = new byte[8];
        ByteBuffer buffer = ByteBuffer.wrap(xorPeerAddress);
        buffer.order(ByteOrder.BIG_ENDIAN);

        buffer.putShort((short) (peerPort ^ (0x2112A442 >>> 16)));
        byte[] ipAddress = InetAddress.getByName(peerIp).getAddress();
        for (int i = 0; i < ipAddress.length; i++) {
            buffer.put((byte) (ipAddress[i] ^ (0x2112A442 >>> (i * 8))));
        }

        return xorPeerAddress;
    }

    private static byte[] generateTransactionID() {
        byte[] transactionId = new byte[12];
        // You can use any method to generate a random transaction ID here.
        // For example, using java.util.Random:
        new java.util.Random().nextBytes(transactionId);
        return transactionId;
    }

    private static void printResponse(byte[] responseBuffer, int bytesRead) {
        ByteBuffer buffer = ByteBuffer.wrap(responseBuffer, 0, bytesRead);
        buffer.order(ByteOrder.BIG_ENDIAN);

        System.out.println("STUN Message:");
        System.out.println("Message Type: " + buffer.getShort());
        System.out.println("Message Length: " + buffer.getShort());
        System.out.println("Magic Cookie: " + Integer.toHexString(buffer.getInt()));
        System.out.println("Transaction ID: " + bytesToHex(buffer.array(), buffer.position(), 12));

        while (buffer.remaining() > 0) {
            short type = buffer.getShort();
            short length = buffer.getShort();
            byte[] value = new byte[length];
            buffer.get(value);

            switch (type) {
                case 0x0020: // XOR-MAPPED-ADDRESS
                    InetSocketAddress xorMappedAddress = parseXorAddress(value);
                    System.out.println("XOR-MAPPED-ADDRESS: " + xorMappedAddress);
                    break;
                case 0x0016: // XOR-RELAYED-ADDRESS
                    InetSocketAddress xorRelayedAddress = parseXorAddress(value);
                    System.out.println("XOR-RELAYED-ADDRESS: " + xorRelayedAddress);
                    break;
                case 0x000D: // LIFETIME
                    int lifetime = ByteBuffer.wrap(value).order(ByteOrder.BIG_ENDIAN).getInt();
                    System.out.println("Lifetime: " + lifetime);
                    break;
                default:
                    System.out.println("Attribute Type: " + type + ", Value: " + bytesToHex(value));
                    break;
            }
        }
        // buffer.position(buffer.position() + 12);

        // while (buffer.remaining() > 0) {
        // short type = buffer.getShort();
        // short length = buffer.getShort();
        // byte[] value = new byte[length];
        // buffer.get(value);

        // System.out.println("Attribute Type: " + type);
        // System.out.println("Attribute Length: " + length);
        // System.out.println("Attribute Value: " + bytesToHex(value));

        // // Skip padding
        // int padding = (4 - (length % 4)) % 4;
        // buffer.position(buffer.position() + padding);
        // }
    }

    private static String bytesToHex(byte[] bytes, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = offset; i < offset + length; i++) {
            sb.append(String.format("%02X ", bytes[i]));
        }
        return sb.toString();
    }

    private static InetSocketAddress extractRelayAddress(byte[] responseBuffer) {
        ByteBuffer buffer = ByteBuffer.wrap(responseBuffer);
        buffer.order(ByteOrder.BIG_ENDIAN);

        // Skip the STUN header
        buffer.position(20);

        while (buffer.remaining() > 0) {
            short type = buffer.getShort();
            short length = buffer.getShort();
            byte[] value = new byte[length];
            buffer.get(value);

            // if (type == 0x0020) { // XOR-RELAYED-ADDRESS
            // return parseXorAddress(value);
            // }
            if (type == 0x0016) { // XOR-MAPPED-ADDRESS
                return parseXorAddress(value);
            }

            // Skip padding
            int padding = (4 - (length % 4)) % 4;
            buffer.position(buffer.position() + padding);
        }

        return null;
    }
    //extract mapped address
    private static InetSocketAddress extractMappedAddress(byte[] responseBuffer) {
        ByteBuffer buffer = ByteBuffer.wrap(responseBuffer);
        buffer.order(ByteOrder.BIG_ENDIAN);

        // Skip the STUN header
        buffer.position(20);

        while (buffer.remaining() > 0) {
            short type = buffer.getShort();
            short length = buffer.getShort();
            byte[] value = new byte[length];
            buffer.get(value);

            if (type == 0x0020) { // XOR-MAPPED-ADDRESS
                return parseXorAddress(value);
            }

            // Skip padding
            int padding = (4 - (length % 4)) % 4;
            buffer.position(buffer.position() + padding);
        }

        return null;
    }

    // private static void sendMessageToPeer(InetSocketAddress relayAddress, String
    // peerIp, int peerPort, String message) {
    // try {
    // Socket peerSocket = new Socket(relayAddress.getAddress(),
    // relayAddress.getPort());
    // OutputStream peerOutputStream = peerSocket.getOutputStream();
    // InetSocketAddress peerAddress = new InetSocketAddress(peerIp, peerPort);

    // byte[] messageBytes = message.getBytes("UTF-8");

    // // Create a TURN Send Indication message
    // ByteBuffer buffer = ByteBuffer.allocate(23 + messageBytes.length);
    // buffer.putShort((short) 0x0016); // Send Indication message type
    // buffer.putShort((short) (8 + messageBytes.length)); // Message length
    // buffer.putInt(0x2112A442); // Magic cookie
    // buffer.putInt(0); // Transaction ID
    // buffer.putShort((short) 0x0012); // XOR-PEER-ADDRESS attribute type
    // buffer.putShort((short) 8); // Attribute length
    // buffer.put((byte) 0); // Reserved
    // buffer.put((byte) 1); // Family (IPv4)
    // buffer.putShort((short) (peerPort ^ (XOR_MASK >>> 16))); // Xored port
    // //buffer.putInt(peerAddress.getAddress().hashCode() ^ XOR_MASK); // Xored IP
    // address
    // buffer.putInt(InetAddress.getByName(peerIp).hashCode() ^ XOR_MASK); // Xored
    // IP address

    // buffer.put(messageBytes); // Message data

    // peerOutputStream.write(buffer.array());
    // peerOutputStream.flush();
    // peerSocket.close();
    // } catch (Exception e) {
    // e.printStackTrace();
    // }
    // }
    // private static void sendMessageToPeer(InetSocketAddress relayAddress, String
    // peerIp, int peerPort, String message) {
    // try {
    // Socket peerSocket = new Socket(relayAddress.getAddress(),
    // relayAddress.getPort());
    // OutputStream peerOutputStream = peerSocket.getOutputStream();
    // InetSocketAddress peerAddress = new InetSocketAddress(peerIp, peerPort);

    // byte[] messageBytes = message.getBytes("UTF-8");

    // // Check if existing buffer is enough, otherwise allocate a larger one
    // int requiredCapacity = 23 + messageBytes.length;
    // int messageLength = messageBytes.length;
    // ByteBuffer buffer;
    // if (ByteBuffer.allocate(requiredCapacity).remaining() >= messageBytes.length)
    // {
    // buffer = ByteBuffer.allocate(requiredCapacity);
    // } else {
    // // Allocate a larger buffer based on message size
    // buffer = ByteBuffer.allocate(requiredCapacity + 1024); // Adjust as needed
    // }

    // // Build the message (same as before)
    // buffer.putShort((short) 0x0016);
    // buffer.putShort((short) (8 + messageBytes.length));
    // buffer.putInt(0x2112A442);
    // buffer.putInt(0);
    // buffer.putShort((short) 0x0012);
    // buffer.putShort((short) 8);
    // buffer.put((byte) 0);
    // buffer.put((byte) 1);
    // buffer.putShort((short) (peerPort ^ (XOR_MASK >>> 16)));
    // buffer.putInt(InetAddress.getByName(peerIp).hashCode() ^ XOR_MASK);

    // buffer.put(messageBytes);
    // buffer.flip(); // Prepare buffer for reading

    // peerOutputStream.write(buffer.array());
    // peerOutputStream.flush();
    // peerSocket.close();
    // } catch (Exception e) {
    // e.printStackTrace();
    // }
    // }

    private static void sendMessageToPeer(InetSocketAddress relayAddress, String peerIp, int peerPort, String message) {
        try {
            Socket peerSocket = new Socket(relayAddress.getAddress(), relayAddress.getPort());
            OutputStream peerOutputStream = peerSocket.getOutputStream();
            InetSocketAddress peerAddress = new InetSocketAddress(peerIp, peerPort);

            // Build message using StringBuilder
            StringBuilder messageBuilder = new StringBuilder();
            messageBuilder.append((short) 0x0016); // Message type
            messageBuilder.append((short) (8 + message.length())); // Message length
            messageBuilder.append(0x2112A442); // Magic cookie
            messageBuilder.append(0); // Transaction ID
            messageBuilder.append((short) 0x0012); // Attribute type
            messageBuilder.append((short) 8); // Attribute length
            messageBuilder.append((byte) 0); // Reserved
            messageBuilder.append((byte) 1); // Family (IPv4)
            messageBuilder.append((short) (peerPort ^ (XOR_MASK >>> 16))); // Xored port
            messageBuilder.append(InetAddress.getByName(peerIp).hashCode() ^ XOR_MASK); // Xored IP address
            messageBuilder.append(message); // Actual message

            // Convert to byte array and send
            byte[] messageBytes = messageBuilder.toString().getBytes("UTF-8");
            peerOutputStream.write(messageBytes);
            peerOutputStream.flush();
            peerSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void printResponse(byte[] response) {
        System.out.println("Received response from server:");
        for (byte b : response) {
            System.out.print(String.format("%02X ", b));
        }
        System.out.println();
    }

    private static byte[] createAllocateRequest() {
        ByteBuffer buffer = ByteBuffer.allocate(512);
        buffer.order(ByteOrder.BIG_ENDIAN);

        // STUN header
        buffer.putShort((short) 0x0003); // Allocate
        buffer.putShort((short) 0x0000); // Message Length (to be filled later)
        buffer.putInt(XOR_MASK); // Magic Cookie
        buffer.put(new byte[12]); // Transaction ID

        // Add TRANSPORT attribute
        buffer.putShort((short) 0x0019); // TRANSPORT
        buffer.putShort((short) 4); // Length
        buffer.put((byte) 6); // Protocol (6 = TCP)
        buffer.put((byte) 0); // Reserved
        buffer.putShort((short) 0); // Reserved

        // Update Message Length
        int length = buffer.position() - 20;
        buffer.putShort(2, (short) length);

        byte[] request = new byte[buffer.position()];
        buffer.rewind();
        buffer.get(request);

        return request;
    }

    private static byte[] createAuthenticatedAllocateRequest(String nonce, String realm) {
        ByteBuffer buffer = ByteBuffer.allocate(512);
        buffer.order(ByteOrder.BIG_ENDIAN);

        // STUN header
        buffer.putShort((short) 0x0003); // Allocate
        buffer.putShort((short) 0x0000); // Message Length (to be filled later)
        buffer.putInt(XOR_MASK); // Magic Cookie
        buffer.put(new byte[12]); // Transaction ID

        // Add USERNAME attribute
        addAttribute(buffer, (short) 0x0006, USERNAME.getBytes());

        // Add REALM attribute
        addAttribute(buffer, (short) 0x0014, realm.getBytes());

        // Add NONCE attribute
        addAttribute(buffer, (short) 0x0015, nonce.getBytes());

        // Add TRANSPORT attribute
        buffer.putShort((short) 0x0019); // TRANSPORT
        buffer.putShort((short) 4); // Length
        buffer.put((byte) 6); // Protocol (6 = TCP)
        buffer.put((byte) 0); // Reserved
        buffer.putShort((short) 0); // Reserved

        // Add MESSAGE-INTEGRITY attribute (HMAC-SHA1)
        byte[] messageBytes = buffer.array();
        byte[] messageIntegrity = createMessageIntegrity(messageBytes, USERNAME, realm, PASSWORD, nonce);
        addAttribute(buffer, (short) 0x0008, messageIntegrity);

        // Update Message Length
        int length = buffer.position() - 20;
        buffer.putShort(2, (short) length);

        byte[] request = new byte[buffer.position()];
        buffer.rewind();
        buffer.get(request);

        return request;
    }

    private static byte[] createMessageIntegrity(byte[] message, String username, String realm, String password,
            String nonce) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update((username + ":" + realm + ":" + password).getBytes());
            byte[] key = md.digest();

            // Use HMAC-SHA1 to generate the message integrity
            Mac mac = Mac.getInstance("HmacSHA1");
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA1");
            mac.init(keySpec);

            return mac.doFinal(message);
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
        }
    }

    private static void addAttribute(ByteBuffer buffer, short type, byte[] value) {
        buffer.putShort(type);
        buffer.putShort((short) value.length);
        buffer.put(value);
        if (value.length % 4 != 0) {
            int padding = 4 - (value.length % 4);
            buffer.put(new byte[padding]);
        }
    }

    private static boolean isUnauthorizedResponse(byte[] response, int bytesRead) {
        ByteBuffer buffer = ByteBuffer.wrap(response, 0, bytesRead);
        buffer.order(ByteOrder.BIG_ENDIAN);

        buffer.getShort(); // Message Type
        buffer.getShort(); // Message Length
        buffer.getInt(); // Magic Cookie
        buffer.get(new byte[12]); // Transaction ID

        while (buffer.remaining() > 0) {
            short type = buffer.getShort();
            short length = buffer.getShort();
            if (type == 0x0009) { // ERROR-CODE attribute
                int errorCode = (buffer.get() & 0x7) * 100 + (buffer.get() & 0xFF);
                if (errorCode == 401) {
                    return true;
                }
            }
            buffer.position(buffer.position() + length);
        }
        return false;
    }

    private static String extractNonce(byte[] response) {
        return extractAttribute(response, (short) 0x0015);
    }

    private static String extractRealm(byte[] response) {
        return extractAttribute(response, (short) 0x0014);
    }

    private static String extractAttribute(byte[] response, short attributeType) {
        ByteBuffer buffer = ByteBuffer.wrap(response);
        buffer.order(ByteOrder.BIG_ENDIAN);

        buffer.getShort(); // Message Type
        buffer.getShort(); // Message Length
        buffer.getInt(); // Magic Cookie
        buffer.get(new byte[12]); // Transaction ID

        while (buffer.remaining() > 0) {
            short type = buffer.getShort();
            short length = buffer.getShort();
            if (type == attributeType) {
                byte[] value = new byte[length];
                buffer.get(value);
                return new String(value);
            }
            buffer.position(buffer.position() + length);
        }
        return null;
    }

    private static void printReadableResponse(byte[] response, int bytesRead) {
        ByteBuffer buffer = ByteBuffer.wrap(response, 0, bytesRead);
        buffer.order(ByteOrder.BIG_ENDIAN);

        int messageType = buffer.getShort();
        int messageLength = buffer.getShort();
        int magicCookie = buffer.getInt();
        byte[] transactionId = new byte[12];
        buffer.get(transactionId);

        System.out.println("Message Type: " + messageType);
        System.out.println("Message Length: " + messageLength);
        System.out.println("Magic Cookie: " + magicCookie);
        System.out.println("Transaction ID: " + bytesToHex(transactionId));

        while (buffer.remaining() > 0) {
            short type = buffer.getShort();
            short length = buffer.getShort();
            byte[] value = new byte[length];
            buffer.get(value);

            switch (type) {
                case 0x0020: // XOR-MAPPED-ADDRESS
                    InetSocketAddress xorMappedAddress = parseXorAddress(value);
                    System.out.println("XOR-MAPPED-ADDRESS: " + xorMappedAddress);
                    break;
                case 0x0016: // XOR-RELAYED-ADDRESS
                    InetSocketAddress xorRelayedAddress = parseXorAddress(value);
                    System.out.println("XOR-RELAYED-ADDRESS: " + xorRelayedAddress);
                    break;
                case 0x000D: // LIFETIME
                    int lifetime = ByteBuffer.wrap(value).order(ByteOrder.BIG_ENDIAN).getInt();
                    System.out.println("Lifetime: " + lifetime);
                    break;
                default:
                    System.out.println("Attribute Type: " + type + ", Value: " + bytesToHex(value));
                    break;
            }
        }
    }

    // private static InetSocketAddress parseXorAddress(byte[] value) {
    // ByteBuffer buffer = ByteBuffer.wrap(value);
    // buffer.order(ByteOrder.BIG_ENDIAN);

    // buffer.get(); // Reserved
    // byte family = buffer.get();
    // int port = buffer.getShort() ^ (XOR_MASK >>> 16);
    // int address = buffer.getInt() ^ XOR_MASK;

    // try {
    // InetAddress inetAddress =
    // InetAddress.getByAddress(ByteBuffer.allocate(4).putInt(address).array());
    // return new InetSocketAddress(inetAddress, port);
    // } catch (UnknownHostException e) {
    // e.printStackTrace();
    // return null;
    // }
    // }
    private static InetSocketAddress parseXorAddress(byte[] value) {
        ByteBuffer buffer = ByteBuffer.wrap(value);
        buffer.order(ByteOrder.BIG_ENDIAN);

        buffer.get(); // Reserved
        byte family = buffer.get();
        int port = buffer.getShort() ^ (XOR_MASK >>> 16);
        int address = buffer.getInt() ^ XOR_MASK;

        // Ensure the port number is correctly handled as an unsigned 16-bit integer
        port = port & 0xFFFF;

        try {
            InetAddress inetAddress = InetAddress.getByAddress(ByteBuffer.allocate(4).putInt(address).array());
            return new InetSocketAddress(inetAddress, port);
        } catch (UnknownHostException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}
