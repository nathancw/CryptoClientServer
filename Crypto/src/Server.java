import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;


public class Server {

    static final int PORT = 4921;
    ServerSocket serverSocket;
    Socket socket;
    ServerThread serverThreads[];
    int orderNumber;
    		
    public static void main(String args[]) {
    	Server server = new Server();
    }
    
  
    public Server() {
    	orderNumber = 0;
        serverSocket = null;
        socket = null;

        //Mention the amount of threads we want
        serverThreads = new ServerThread[10];
        
        try {
            serverSocket = new ServerSocket(PORT);
            System.out.println("Waiting for connection. - Server");
        } catch (IOException e) {
            e.printStackTrace();

        }
             
        int count = 0;
        BufferedReader in;
        while (true) {
            try {
            	//Accept the connection
                socket = serverSocket.accept();   
                
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                
                //Server type determines if its a chef or whatever. It just simply says Chef.
                String type = in.readLine();
                System.out.println("Connection received from " + serverSocket.getInetAddress().getHostName() + ". and type: + " + type);
                //Create the new thread
                serverThreads[count] = new ServerThread(this,socket,type);
                serverThreads[count].start();
                System.out.println("serverThreads[" + count  +"] created" );
                     
               count++;
            } catch (IOException e) {
                System.out.println("I/O error: " + e);
                e.printStackTrace();
            }
         
        }
    }
    
    public void handle(String str){
    	
    	//order number is  ready so we sent ot waiter
    	if(str.charAt(1) == 'h'){
    		for(int x = 0 ; x < serverThreads.length; x++){

    			if(serverThreads[x] != null){
	    			if(serverThreads[x].getType().equals("Waiter")){
	    				serverThreads[x].send("Order READY Number: " + orderNumber + " " +str);
	    			}
	    			
	    		}
    		}
    	}
    	//Its a customer order, send to waiter
    	else if(str.charAt(1)== 'u'){
    		
    		orderNumber++;
    		
    		for(int x = 0 ; x < serverThreads.length; x++){
    			System.out.println("trying to send order: " + orderNumber + " X: " + x);
    			if(serverThreads[x] != null){
	    			if(serverThreads[x].getType().equals("Chef") || serverThreads[x].getType().equals("Waiter")){
	    				System.out.println("sending order" + orderNumber + " to X: " + x);
	    				serverThreads[x].send("Order Number: " + orderNumber + " " +str);
	    			
	    			}	
	    		}
    		}
    	}
    	
    }
    

}

class ServerThread extends Thread {
	
    protected Socket socket;
    PrintWriter out;
	BufferedReader in;
	Server server;
	String type;
    
    public ServerThread(Server serv, Socket clientSocket, String type) {
        this.socket = clientSocket;
        this.server = serv;
        this.type = type;

        try {
        	in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			out = new PrintWriter(socket.getOutputStream());
		} catch (IOException e) {
			e.printStackTrace();
		}
    }

    public void send(String str) {
		
    	
		out.println(str);
		out.flush();
		System.out.println("Done sending message in " + this.type);
	}

	public void run() {
  
        String line;
     
        System.out.println("Running thread: " + type);
        try {
			while (((line = in.readLine()) != null)) {

			        System.out.println("Server read: " + line);
			        server.handle(line);

			
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
        
    }
    
    public PrintWriter getOutputStream(){
    	return out;
    }
    public BufferedReader getInputStream(){
    	return in;
    }
    public String getType(){
	  return type;
    }
}