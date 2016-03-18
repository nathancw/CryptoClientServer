import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
//import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Server {
	Socket clientSocket = null;
	PublicKey bobPublicKey;
	PrivateKey bobPrivateKey;
	DHParameterSpec dhSpec;
	SecretKey atobSecretKey;
	
	int bDHPrivate;
	BigInteger gBigInt;
	BigInteger pBigInt;
	BigInteger secretKeyBigInt;
	SecretKey btoaSecretKey;
	
	public static void main(String args[])
    {
        Server server = new Server();
    }
	
	public Server(){
		
		//THIS IS BOB HE IS A BEAUTIFUL SERVER
		
		//Generate DH values, and pub/priv keys for storage so alice can pick them up
		this.generateAndStoreKeys();
		////////////////////
		
		//Set up connection
		ServerSocket connection;
		try {
			//set up connection and then wait
			connection = new ServerSocket(9090);
			System.out.println("Waiting for connection.");
			//Wait for connection
	        clientSocket = connection.accept();
	        System.out.println("Connection received from " + connection.getInetAddress().getHostName() + ".");
	 		
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		///////////////////////
        
      
        DataInputStream dIn;
		try {
			
			dIn = new DataInputStream(clientSocket.getInputStream());
			byte[] message;
	        int length = dIn.readInt(); 
	        message = new byte[length];
	        dIn.read(message); 
	        
	        //Read in second message length and size
	        int length2 = dIn.readInt();
	        byte [] secretMessage = new byte[length2];
	        dIn.read(secretMessage);
	        
	        System.out.println("\nReceived Text from Alice: " + Arrays.toString(message));
	        
	        //Decrypt the text
	        byte[] decryptedText;
	        byte[] decryptedMessage;
	        
	    	Cipher RSAdecrypt = Cipher.getInstance("RSA/ECB/NoPadding");
			RSAdecrypt.init(Cipher.DECRYPT_MODE, bobPrivateKey);
			
			//This produces a massive 128 byte key instead of 128bits
			decryptedText = RSAdecrypt.doFinal(message);
			
			//Get last 16 bytes for our 128 bit AES secretkey
			byte[] byte16Key = new byte[16];
			for(int x = 0; x < 16; x++)
				byte16Key[x] = decryptedText[127-15+x];
	       
			//Change decrypted text to secret key again
			atobSecretKey = new SecretKeySpec(byte16Key, 0, byte16Key.length, "AES");
			System.out.println("\nGot secret Key from Alice: " + Arrays.toString(atobSecretKey.getEncoded()));
			
			//Decrypt cipher of sharedSecretKey
			Cipher AESdecrypt = Cipher.getInstance("AES/ECB/NoPadding");
			AESdecrypt.init(Cipher.DECRYPT_MODE, atobSecretKey);
			decryptedMessage = AESdecrypt.doFinal(secretMessage);
			
	        System.out.println("\nGot this decrypted message from alice? : " + new String(decryptedMessage));
	        
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
      	
		
		//DH Protocol Send G and P and the value to the Client for generate secret Key
		System.out.println("Sending DH Protocol over to Alice");
		sendDHProtocol();
		////////////////////////////////////////////////////////
		
		//Read in the values
		int size;
		try {
			dIn = new DataInputStream(clientSocket.getInputStream());
			size = dIn.readInt();
			byte[] number = new byte[size];
			dIn.read(number);
			BigInteger aliceNum = new BigInteger(number);
			System.out.println("Read in Alice's NUmber.");

			this.secretKeyBigInt = aliceNum.pow(bDHPrivate).mod(pBigInt);
			System.out.println("Computed Shared Secret Key DH Value: " + secretKeyBigInt);
			
			btoaSecretKey = new SecretKeySpec(secretKeyBigInt.toByteArray(), 0, secretKeyBigInt.toByteArray().length, "AES");
			
			System.out.println("New DH shared secret key: " +  Arrays.toString(btoaSecretKey.getEncoded()));
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	
	}
	
	public void generateAndStoreKeys(){
		
		KeyPairGenerator kpg;
		try{
			
		//Generate Pub/Priv keys using RSA below
		System.out.println("Generating RSA Shared Key inside Bob/Server.");
		kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);
		KeyPair kp = kpg.genKeyPair();
		this.bobPublicKey = kp.getPublic();
		this.bobPrivateKey = kp.getPrivate();
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
		
			 
	    //Generate p and b for DH protocol
	 	int bitLength = 512; // 512 bits
	    SecureRandom rnd = new SecureRandom();
	    pBigInt = BigInteger.probablePrime(bitLength, rnd);
	    gBigInt = BigInteger.probablePrime(bitLength, rnd);
	    
	    System.out.println("pBigInt: " + pBigInt);
	    System.out.println("\n DH Pair generated. p: " + pBigInt + " , g: " + gBigInt);
	  
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	public void sendDHProtocol(){
		
		try {
			DataOutputStream dout = new DataOutputStream(clientSocket.getOutputStream());
			byte[] p = pBigInt.toByteArray();
			byte[] g = gBigInt.toByteArray();
			
			bDHPrivate = 132;
			
			System.out.println("Generated byte arrays of g,p, and bobprivate.");
			
			BigInteger bobValue = gBigInt.pow(bDHPrivate).mod(pBigInt);
			System.out.println("bobValue: " + bobValue);
			dout.writeInt(p.length);
			dout.write(p);
			
			dout.writeInt(g.length);
			dout.write(g);
			
			dout.writeInt(bobValue.toByteArray().length);
			dout.write(bobValue.toByteArray());
			System.out.println("Done Sending all the values over to Alice");
			
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
	}
}
