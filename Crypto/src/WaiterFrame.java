import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.JTextArea;


public class WaiterFrame {

	private JPanel contentPane;
	private JTextField ordertextField;
	private int tableNumber = 12345;
	Socket serverSocket;
	static final int PORT = 4921;
	BufferedReader in;
	PrintWriter out;
	//private WaiterThread waiter;
	private WaiterFrame frame;
	static JTextArea textArea;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {

		EventQueue.invokeLater(new Runnable() {
			public void run() {	
				WaiterFrame frame;
				frame = new WaiterFrame();
			}
		});	     
		
		WaiterThread waiter = new WaiterThread();
		waiter.start();
				
	}

	/**
	 * Create the frame.
	 */
	public WaiterFrame(){
		
	
		
		JFrame frame = new JFrame();
		frame.setVisible(true);
		frame.setTitle("Waiter Frame");
		
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setBounds(100, 100, 607, 387);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		frame.setContentPane(contentPane);
		contentPane.setLayout(new GridLayout(4, 4, 0, 0));
		
		JPanel panel_1 = new JPanel();
		contentPane.add(panel_1);
		panel_1.setLayout(new BorderLayout(0, 0));
		
		JLabel lblNewLabel = new JLabel("Waiter Program");
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		panel_1.add(lblNewLabel, BorderLayout.NORTH);
		
		JLabel lblTableNumber = new JLabel("Input Order Number Ready and press submit");
		lblTableNumber.setHorizontalAlignment(SwingConstants.CENTER);
		panel_1.add(lblTableNumber, BorderLayout.CENTER);
		
		JPanel panel_3 = new JPanel();
		contentPane.add(panel_3);
		panel_3.setLayout(new BorderLayout(0, 0));
		
		JLabel lblOrdersRecieved = new JLabel("Orders Recieved:");
		lblOrdersRecieved.setHorizontalAlignment(SwingConstants.CENTER);
		lblOrdersRecieved.setVerticalAlignment(SwingConstants.TOP);
		panel_3.add(lblOrdersRecieved, BorderLayout.NORTH);
		
		textArea = new JTextArea();
		panel_3.add(textArea, BorderLayout.CENTER);
		textArea.setLineWrap(true);
		
		JPanel panel_2 = new JPanel();
		contentPane.add(panel_2);
		
		JLabel lblorderNumber = new JLabel("Table  exit: ");
		panel_2.add(lblorderNumber);
		
		ordertextField = new JTextField();
		panel_2.add(ordertextField);
		ordertextField.setColumns(10);
		
		JPanel panel = new JPanel();
		contentPane.add(panel);
		
		JButton btnSubmit = new JButton("Submit");
		btnSubmit.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				
				//Make the total order to send
				String totalOrder = "Waiter. Order Ready Number:"+ ordertextField.getText();
				
				WaiterThread.sendOrder(totalOrder);
				
				JOptionPane.showMessageDialog(new JFrame(), "Order Number Ready Submitted");
				
			}
		});
		panel.add(btnSubmit);
		
	}

	public static void updateLabel(String str){
		textArea.append(str + "\n");
	}
}

class WaiterThread extends Thread {

	 //WaiterFrame frame;
	 static final int PORT = 4921;
	 DataInputStream din;
	 DataOutputStream dout;
	 BufferedReader in;
	 static PrintWriter out;
	 
	 public WaiterThread(){
		 
		 //this.frame= frame;
		 
		Socket serverSocket;
		try {
			serverSocket = new Socket("localhost",PORT);
			in = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
			
			System.out.println("Connected to localhost in port 4921 - Waiter");
			out = new PrintWriter(serverSocket.getOutputStream(),true);
			out.println("Waiter");
			
			
		} catch (UnknownHostException e) {
	
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
				
		
		
	 }
	 
	 public void run(){
		 
		 try {

			String readLine; 
			while(!((readLine = waitForServerResponse()).equals("Exit"))){				
				System.out.println("Chef read: " + readLine);
				WaiterFrame.updateLabel(readLine);
			}
		
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		 
	 }
	 
	 public String waitForServerResponse() throws IOException{
		 
		 String readLine;
		 while(((readLine = in.readLine()) != null)){
			 		return readLine;
		 }
		 return "";
		 
	 }

	public static void sendOrder(String str){
			out.println(str);
			System.out.println("Order done writing to the server.");
		}
	
	

}
