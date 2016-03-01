import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Date;

public class Client {

	Socket serverSocket;
	String timeStamp;
	
	public static void main(String args[])
    {
        Client client = new Client();
 
    }
	
	
	public Client(){
		
		try {
			serverSocket = new Socket("localhost",9090);
			System.out.println("Connected to localhost in port 9090");
			
			 DataOutputStream dos = new DataOutputStream(serverSocket.getOutputStream());
			
			 byte[] message = new byte[3];
			
			 message[0] = 'a';
			 message[1] = 5;
	         dos.writeInt(message.length);
	         dos.write(message);
	         dos.flush();
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
