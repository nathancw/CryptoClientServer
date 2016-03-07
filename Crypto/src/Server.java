import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class Server {
	Socket clientSocket = null;
	public static void main(String args[])
    {
        Server server = new Server();
    }
	
	public Server(){
		try {
			//THIS IS BOB HE IS A BEAUTIFUL SERVER
			ServerSocket connection = new ServerSocket(9090);
			System.out.println("Waiting for connection." + System.currentTimeMillis());
            clientSocket = connection.accept();
            System.out.println("Connection received from " + connection.getInetAddress().getHostName() + " " +System.currentTimeMillis());
        
            //DataInputStream dIn = new DataInputStream(clientSocket.getInputStream());
            
            //Read in public key from Alice
            ObjectInputStream keyIn = new ObjectInputStream(clientSocket.getInputStream());
            Key alicePubKey = null;
            try {
            	System.out.println("Trying to read in Alice Pub Keyy. -----"+ System.currentTimeMillis());
				alicePubKey = (Key) keyIn.readObject();
				System.out.println("Read in Alice's Public Key: " + alicePubKey + "-----"+ System.currentTimeMillis());
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            
            //Now to generate the encryption using Alice's Public Key
            
            
           //Create and prepare the message we want to send.
            DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
			
			byte[] clientMessage = new byte[2000];
			
			for(int i = 0; i < 2000; i++)
				clientMessage[i] = 'b';
			////
			
			 //So from bob to alice he wants us to use So they need to agree on a shared secret key.

			dos.writeInt(clientMessage.length);
	        dos.write(clientMessage);
                
	       
                
            
          /*
           *   byte[] message;
            int length = dIn.readInt(); 
            message = new byte[length];
            dIn.readFully(message, 0, message.length); // read the message
  
            String m = new String(message);
            System.out.println(m);
           * 
           */
      	
          // dIn.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
			
	}
}
