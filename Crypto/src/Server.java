import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
	Socket clientSocket = null;
	public static void main(String args[])
    {
        Server server = new Server();
    }
	
	public Server(){
		try {
			ServerSocket connection = new ServerSocket(9090);
			System.out.println("Waiting for connection.");
            clientSocket = connection.accept();
            System.out.println("Connection received from " + connection.getInetAddress().getHostName());
        
            DataInputStream dIn = new DataInputStream(clientSocket.getInputStream());
         
            
           int length = dIn.readInt();                    // read length of incoming message
            //if(length>0) {
                //byte[] message = new byte[length];
                //dIn.readFully(message, 0, message.length); // read the message
                
            //}
           byte[] message = new byte[3];
           dIn.read(message);
         System.out.println(message[1]);
			
          // dIn.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
			
	}
}
