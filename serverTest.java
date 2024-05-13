import java.net.*;
import java.io.*;

public class serverTest {
    public static void main(String[] args) {
        String serverName = "stunturn.com";
        int port = 3478;
        testTurnServer(serverName, port);
    }

    public static void testTurnServer(String serverName, int port) {
        Socket socket = null;
        try {
            // Create a socket
            socket = new Socket(serverName, port);
            System.out.println("TURN server at " + serverName + ":" + port + " is reachable.");
        } catch (UnknownHostException e) {
            System.out.println("TURN server at " + serverName + ":" + port + " is not reachable. Error: " + e);
        } catch (IOException e) {
            System.out.println("TURN server at " + serverName + ":" + port + " is not reachable. Error: " + e);
        } finally {
            // Close the socket
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    System.out.println("Error while closing the socket: " + e);
                }
            }
        }
    }
}