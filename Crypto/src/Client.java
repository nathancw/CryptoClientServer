import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
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
import javax.crypto.spec.SecretKeySpec;

public class Client {

	Socket serverSocket;
	String timeStamp;
	String alicepubKey;
	String privKey;
	public static PublicKey alicePublicKey;
	PrivateKey alicePrivateKey;
	PublicKey bobPublicKey;
	SecretKey atobSecretKey;
	int aliceDHPrivate;
	BigInteger DHsecretKey;
	BigInteger aliceValue;
	SecretKey btoaSecretKey;
	
	public static void main(String args[])
    {
        //Create connection and the keys
		Client client = new Client();
		byte[] secretKey;
		byte [] encryptedText = null;
		byte [] encryptedMessage = null;
		
		byte[] message = {'1','a','b','c','1','a','b','c','1','a','b','c','1','a','b','c'};
        
		//Encrypt the secret key generated in the client
		try {
			Cipher RSAencrKey = Cipher.getInstance("RSA/ECB/NoPadding");
			try {
				//Try to encrypt the key
				RSAencrKey.init(Cipher.ENCRYPT_MODE, client.getBobPublicKey());
				secretKey = client.getatobSecretKey().getEncoded();
				
				Cipher AESencrypt = Cipher.getInstance("AES/ECB/NoPadding");
				AESencrypt.init(Cipher.ENCRYPT_MODE, client.getatobSecretKey());
				
				try {
					//Do the encryption.
					encryptedText = RSAencrKey.doFinal(secretKey);
					encryptedMessage = AESencrypt.doFinal(message);
					
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
       ///////////////////////////
		
		System.out.println("EncryptedText:" + encryptedText);
		
		//Send the key to the server
		DataInputStream dIn;
		DataOutputStream dos;
		//Try to write the encrypted text to the server
		try {
			System.out.println("Sending text to bob: " + Arrays.toString(encryptedText));
			dos = new DataOutputStream(client.getServerSocket().getOutputStream());
			dos.writeInt(encryptedText.length);
			dos.write(encryptedText);
			
			dos.writeInt(encryptedMessage.length);
			dos.write(encryptedMessage);
			
			System.out.println("Done writing to Bob/Server");
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
       ////////////////////////////////////
		
		//Read in Bob's DH Protocol values
		try {
			System.out.println("Trying to read in the values for DH protocol from Bob.");
			dIn = new DataInputStream(client.getServerSocket().getInputStream());
			int pLength = dIn.readInt();
			byte[] p = new byte[pLength];
			dIn.read(p);
			BigInteger pValue = new BigInteger(p);
			
			
			int gLength = dIn.readInt();
			byte[] g = new byte[gLength];
			dIn.read(g);
			BigInteger gValue = new BigInteger(g);
			
			int bLength = dIn.readInt();
			byte[] b = new byte[bLength];
			dIn.read(b);
			BigInteger bValue = new BigInteger(b);
		
			System.out.println("Read in DH Values from Bob/Server P: " + pValue + " , G: " + gValue + " , bValue: " + bValue);
			//Compute the values
			client.computeDHValue(pValue,gValue,bValue);

			dos = new DataOutputStream(client.getServerSocket().getOutputStream());
			dos.writeInt(client.getAliceValue().toByteArray().length);
			dos.write(client.getAliceValue().toByteArray());
			
		
		} catch (IOException e) {
			e.printStackTrace();
		}
		/////////////////////////////////////////////
    }
	
	private BigInteger getAliceValue() {
		return aliceValue;
	}

	private BigInteger getDHsecretKey() {

		return DHsecretKey;
	}

	public void computeDHValue(BigInteger p, BigInteger g, BigInteger bValue){
		
		this.aliceDHPrivate = 283;
		this.aliceValue = g.pow(aliceDHPrivate).mod(p);
		
		System.out.println("Read in DH Values from Bob/Server inside computeDHValue AliceValue: " + aliceValue);
		this.DHsecretKey = bValue.pow(aliceDHPrivate).mod(p);
		
		System.out.println("Got DHSecretKey: " + DHsecretKey);
		
		btoaSecretKey = new SecretKeySpec(DHsecretKey.toByteArray(), 0, DHsecretKey.toByteArray().length, "AES");
		
		System.out.println("New DH shared secret key: " + Arrays.toString(btoaSecretKey.getEncoded()));
		
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
