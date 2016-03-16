import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Server {
	Socket clientSocket = null;
	public static PublicKey bobPublicKey;
	PublicKey alicePubKey = Client.alicePublicKey;
	PrivateKey bobPrivateKey;
	
	public static void main(String args[])
    {
        Server server = new Server();
    }
	
	public Server(){
		//THIS IS BOB HE IS A BEAUTIFUL SERVER
		//Set up connection
		
		KeyPairGenerator kpg;
	
	
		try{
			
		//Generate Pub/Priv keys using RSA below
		System.out.println("Generating RSA Shared Key inside Bob/Server  " + System.currentTimeMillis());
		kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);
		KeyPair kp = kpg.genKeyPair();
		bobPublicKey = kp.getPublic();
		bobPrivateKey = kp.getPrivate();
		//System.out.println("Key Generation Done for Bob/Server. BobPublicKey:" + bobPublicKey + System.currentTimeMillis());
		////////////////
		
		//Put Public key into encoded bytes and store in file for alice to grab
		byte[] bytePublicKey = bobPublicKey.getEncoded();

			try {
				FileOutputStream keyfos = new FileOutputStream("BobPublicKey");
				keyfos.write(bytePublicKey);
				keyfos.close();
			} catch (IOException e) {
			
				e.printStackTrace();
			}
		
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		
		ServerSocket connection;
		try {
			//set up connection and then wait
			connection = new ServerSocket(9090);
			System.out.println("Waiting for connection." + System.currentTimeMillis());
			//Wait for connection
	        clientSocket = connection.accept();
	        System.out.println("Connection received from " + connection.getInetAddress().getHostName() + " " +System.currentTimeMillis());
	        /////////////////////////////
			
	        //System.out.println("Trying to read in Alice Pub Keyy2.: " + Client.alicePublicKey + "-----"+ System.currentTimeMillis());
	        //Create and prepare the message we want to send.
	        // DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
	 		
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

        
      
        DataInputStream dIn;
		try {
			
			dIn = new DataInputStream(clientSocket.getInputStream());
			byte[] message;
	        int length = dIn.readInt(); 
	        message = new byte[length];
	        dIn.readFully(message); 
	  
	        
	        
	        System.out.println("Received Text from Alice: " + Arrays.toString(message));
	        
	        //Decrypt the text
	        byte[] decryptedText;
	    	Cipher RSAdecrypt = Cipher.getInstance("RSA/ECB/NoPadding");
			RSAdecrypt.init(Cipher.DECRYPT_MODE, bobPrivateKey);
			decryptedText = RSAdecrypt.doFinal(message);
	       
	        System.out.println("Got this decrypted secret key from alice? : " + Arrays.toString(decryptedText));
	        
	        
	        
	        
	        
	        
	        
	        
	        
	        //String m = new String(message);
	        //System.out.println(m);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
      
        
            /*
	 	byte[] clientMessage = new byte[2000];
	 		
	 		for(int i = 0; i < 2000; i++)
	 			clientMessage[i] = 'b';
 

 		dos.writeInt(clientMessage.length);
        dos.write(clientMessage);
        */
           

			
	}
}
