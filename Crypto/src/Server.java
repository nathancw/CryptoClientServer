import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
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
	PublicKey alicePublicKey;
	PrivateKey bobPrivateKey;
	DHParameterSpec dhSpec;
	SecretKey atobSecretKey;
	
	
	int bDHPrivate;
	int bDHIntegrityPrivate;
	BigInteger gBigInt;
	BigInteger pBigInt;
	BigInteger secretKeyBigInt;
	BigInteger integrityKeyBigInt;
	SecretKey btoaSecretKey;
	SecretKey atobIntegrityKey;
	SecretKey btoaIntegrityKey;
	
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
        
		//Read in alices public key for future use.
		try {
			readAlicesKey();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		///
		
		//Reading in the values below
        DataInputStream dIn;
		try {
			
			dIn = new DataInputStream(clientSocket.getInputStream());
			//Read in encrypted shared key
			byte[] atobKey;
	        int length = dIn.readInt(); 
	        atobKey = new byte[length];
	        dIn.read(atobKey); 
	        
	        //Read in integrity Key
	        byte[] integrityKey;
	        int length2 = dIn.readInt();
	        integrityKey = new byte[length2];
	        dIn.read(integrityKey);
	        
	        //Read in second message length and size
	        int length3 = dIn.readInt();
	        byte [] secretMessage = new byte[length3];
	        dIn.read(secretMessage);
	        
	        System.out.println("\nReceived Text from Alice: " + Arrays.toString(atobKey));
	        
	        //Decrypt the text
	        byte[] decryptedsecretKey;
	        byte[] decryptedIntegrityKey;
	        byte[] decryptedMessage;
	        
	    	Cipher RSAdecrypt = Cipher.getInstance("RSA/ECB/NoPadding");
			RSAdecrypt.init(Cipher.DECRYPT_MODE, bobPrivateKey);
			
			//This produces a massive 128 byte key instead of 128bits
			decryptedsecretKey = RSAdecrypt.doFinal(atobKey);
			decryptedIntegrityKey = RSAdecrypt.doFinal(integrityKey);
			
			//Get last 16 bytes for our 128 bit AES secretkey
			byte[] byte16SecretKey = new byte[16];
			byte[] byte16IntegrityKey = new byte[16];
			for(int x = 0; x < 16; x++){
				byte16SecretKey[x] = decryptedsecretKey[127-15+x];
				byte16IntegrityKey[x] = decryptedIntegrityKey[127-15+x];
			}
	       
			//Change decrypted text to secret key again
			atobSecretKey = new SecretKeySpec(byte16SecretKey, 0, byte16SecretKey.length, "AES");
			atobIntegrityKey = new SecretKeySpec(byte16IntegrityKey, 0, byte16IntegrityKey.length, "AES");
			System.out.println("\nGot secret Key from Alice: " + Arrays.toString(atobSecretKey.getEncoded()));
			System.out.println("\nGot Integrity Key from Alice: " + Arrays.toString(atobIntegrityKey.getEncoded()));
			
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
			//Read in secret key first 
			dIn = new DataInputStream(clientSocket.getInputStream());
			size = dIn.readInt();
			byte[] secretKeynumber = new byte[size];
			dIn.read(secretKeynumber);
			BigInteger aliceSecretNum = new BigInteger(secretKeynumber);
			
			//Read in integrity key number
			int size2 = dIn.readInt();
			byte[] integrityKeynumber = new byte[size2];
			dIn.read(integrityKeynumber);
			BigInteger aliceIntegrityNum = new BigInteger(integrityKeynumber);
			System.out.println("Read in Alice's NUmber.");
			
			//Compute the biginteger values of each
			this.secretKeyBigInt = aliceSecretNum.pow(bDHPrivate).mod(pBigInt);
			this.integrityKeyBigInt = aliceIntegrityNum.pow(bDHIntegrityPrivate).mod(pBigInt);
			
			System.out.println("Computed Shared Secret Key DH Value: " + secretKeyBigInt);
			System.out.println("Computed Shared Integrity Key DH Value: " + integrityKeyBigInt);
			
			//Make them into actual SecretKeys
			btoaSecretKey = new SecretKeySpec(secretKeyBigInt.toByteArray(), 0, secretKeyBigInt.toByteArray().length, "AES");
			btoaIntegrityKey = new SecretKeySpec(integrityKeyBigInt.toByteArray(), 0, integrityKeyBigInt.toByteArray().length, "AES");
			
			System.out.println("New DH shared secret key: " +  Arrays.toString(btoaSecretKey.getEncoded()));
			System.out.println("New DH shared Integrity key: " +  Arrays.toString(btoaIntegrityKey.getEncoded()));
			
			
			//////////
			
			
			///
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		///We now have all the keys setup at this point in the server program, so alice is now going to now send us 2000 byte message digitally signed
		try {
			
			dIn = new DataInputStream(clientSocket.getInputStream());
			int sigLength = dIn.readInt();
			byte[] sigBytes = new byte[sigLength];
			dIn.read(sigBytes);
			
			int messageLength = dIn.readInt();
			byte [] aliceMessage = new byte[messageLength];
			dIn.read(aliceMessage);
			
			Signature sig = Signature.getInstance("MD5WithRSA");
		    sig.initVerify(alicePublicKey);
			sig.update(sigBytes);
			
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] mdMessage = md.digest(aliceMessage);
			
			System.out.println("Read in Sigbytes: " + Arrays.toString(sigBytes) + "\nSignature verified? : " + sig.verify(mdMessage));
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
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
			bDHIntegrityPrivate = 258;
			
			System.out.println("Generated byte arrays of g,p, and bobprivate.");
			
			BigInteger bobSecretValue = gBigInt.pow(bDHPrivate).mod(pBigInt);
			BigInteger bobIntegrityValue = gBigInt.pow(bDHIntegrityPrivate).mod(pBigInt);
			System.out.println("Generated in Bob DH SecretKey Value: " + bobSecretValue + ", DH IntegrityKey Value: " + bobIntegrityValue);
			dout.writeInt(p.length);
			dout.write(p);
			
			dout.writeInt(g.length);
			dout.write(g);
			
			//Write secret key value
			dout.writeInt(bobSecretValue.toByteArray().length);
			dout.write(bobSecretValue.toByteArray());
			
			//Write integrity key value
			dout.writeInt(bobIntegrityValue.toByteArray().length);
			dout.write(bobIntegrityValue.toByteArray());
			
			System.out.println("Done Sending all the values over to Alice");
			
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		
	}
	
	public void readAlicesKey() throws IOException{
		
		FileInputStream keyfis = new FileInputStream("AlicePublicKey");
		byte[] encKey = new byte[keyfis.available()];  
		keyfis.read(encKey);
		
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			alicePublicKey = keyFactory.generatePublic(pubKeySpec);
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//System.out.println("Read in alice's public key: " + alicePublicKey);
		
		
	}
}
