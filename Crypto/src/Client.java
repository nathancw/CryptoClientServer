import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class Client {

	Socket serverSocket;
	String timeStamp;
	String alicepubKey;
	String privKey;
	public static PublicKey alicePublicKey;
	PrivateKey alicePrivateKey;
	PublicKey bobPublicKey;
	SecretKey atobSecretKey;
	
	public static void main(String args[])
    {
        //Create connection and the keys
		Client client = new Client();
		byte[] secretKey;
		byte [] encryptedText = null;
        
		
		try {
			Cipher RSAencrKey = Cipher.getInstance("RSA/ECB/NoPadding");
			try {
				//Try to encrypt the key
				RSAencrKey.init(Cipher.ENCRYPT_MODE, client.getBobPublicKey());
				secretKey = client.getatobSecretKey().getEncoded();
				try {
					//Do the encryption.
					encryptedText = RSAencrKey.doFinal(secretKey);
				} catch (IllegalBlockSizeException e) {
					e.printStackTrace();
				} catch (BadPaddingException e) {
					e.printStackTrace();
				}
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
        
		System.out.println("EncryptedText:" + encryptedText);
		
		DataInputStream dIn;
		DataOutputStream dos;
		//Try to write the encrypted text to the server
		try {
			System.out.println("Sending text to bob: " + Arrays.toString(encryptedText));
			dos = new DataOutputStream(client.getServerSocket().getOutputStream());
			dIn = new DataInputStream(client.getServerSocket().getInputStream());
			dos.writeInt(encryptedText.length);
			dos.write(encryptedText);
			
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
    }
	
	
	private Socket getServerSocket() {
		return serverSocket;
	}


	private SecretKey getatobSecretKey() {
		return atobSecretKey;
	}


	private PublicKey getBobPublicKey() {
		return bobPublicKey;
	}


	public Client(){
		
		try {
			//THIS IS ALICE SHE IS A BEAUTIFUL CLIENT
			
			 alicePublicKey = null;
	         KeyPairGenerator kpg;
	              
				try {
					//Generate Pub/Priv keys using RSA below
					System.out.println("Generating RSA Shared Key inside Alice.");
					kpg = KeyPairGenerator.getInstance("RSA");
					kpg.initialize(1024);
					KeyPair kp = kpg.genKeyPair();
					alicePublicKey = kp.getPublic();
					alicePrivateKey = kp.getPrivate();
					System.out.println("Key Generation Done for Alice.");
					////////////////
					
					//Generate Secret Key to be sent to Bob
					KeyGenerator keyGen = KeyGenerator.getInstance("AES");
				    keyGen.init(128);
				    atobSecretKey = keyGen.generateKey();
				    System.out.println("Generated Secret Key in Alice: " + Arrays.toString(atobSecretKey.getEncoded()));
		
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
			//READ BOBS PUBLIC KEY IN
			readBobsKey();
				
			//Connect to server
			serverSocket = new Socket("localhost",9090);
			System.out.println("Connected to localhost in port 9090  " + System.currentTimeMillis());

			 byte[] message = new byte[2000];
			
			 //Prepare the message
			 for(int i = 0; i < 2000; i++)
				 message[i] = 'a';
		
			 
	 
	         
	         
			 //dos.close();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
		
	}
	
	public void readBobsKey() throws IOException{
		
		FileInputStream keyfis = new FileInputStream("BobPublicKey");
		byte[] encKey = new byte[keyfis.available()];  
		keyfis.read(encKey);
		
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			bobPublicKey = keyFactory.generatePublic(pubKeySpec);
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
		
		
	}
	
}
