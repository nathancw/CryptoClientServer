import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

public class Client {

	Socket serverSocket;
	String timeStamp;
	String pubKey;
	String privKey;
	
	public static void main(String args[])
    {
        Client client = new Client();
 
    }
	
	
	public Client(){
		
		try {
			//THIS IS ALICE SHE IS A BEAUTIFUL CLIENT
			//Generate Some keys first
			 Key alicePublicKey = null;
	         KeyPairGenerator kpg;
				try {
					System.out.println("Generating RSA Shared Key inside Alice  " + System.currentTimeMillis());
					kpg = KeyPairGenerator.getInstance("RSA");
					kpg.initialize(1024);
					KeyPair kp = kpg.genKeyPair();
					alicePublicKey = kp.getPublic();
					Key alicePrivateKey = kp.getPrivate();
					System.out.println("Key Generation Done for Alice.  " + System.currentTimeMillis());
					
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			
			//Connect to server
			serverSocket = new Socket("localhost",9090);
			System.out.println("Connected to localhost in port 9090  " + System.currentTimeMillis());
			
			 //DataOutputStream dos = new DataOutputStream(serverSocket.getOutputStream());
			 ObjectOutputStream keyOut = new ObjectOutputStream(serverSocket.getOutputStream());
			
			 byte[] message = new byte[2000];
			
			 //Prepare the message
			 for(int i = 0; i < 2000; i++)
				 message[i] = 'a';
		
			 
	
			 
	        //From Alice to bob we need to use RSA. So we need a shared secret key.
			//Send publicKey to Bob
			//dos.writeInt(aliceByteKey.length);
			System.out.println("Sending Public Key to Bob  " + System.currentTimeMillis());
			keyOut.writeObject(alicePublicKey);
				
				//dos.writeInt(message.length);
			    //dos.write(message);
			 
			    
			    
			    
			    
			    
			    
	         //Reading in from the server
	         DataInputStream dIn = new DataInputStream(serverSocket.getInputStream());
	         
	         byte[] serverMessage;
	         int length = dIn.readInt();           // read length of incoming message
	         message = new byte[length];
	         dIn.readFully(message, 0, message.length); // read the message
	  
	         String m = new String(message);
	         System.out.println(m);
	         
	         
	         
	         
			 //dos.close();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
		
	}
	
}
