import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import java.awt.GridLayout;

import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.JLabel;
import javax.swing.BoxLayout;
import java.awt.FlowLayout;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.swing.JButton;
import javax.swing.SwingConstants;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;


public class CustomerFrame extends JFrame {

	private JPanel contentPane;
	private JTextField drinktextField;
	private JTextField appetizertextField;
	private JTextField maintextField;
	private JTextField deserttextField;
	private JTextField flighttextField;
	private int tableNumber = 12345;
	Socket serverSocket;
	static final int PORT = 4921;
	BufferedReader in;
	PrintWriter out;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					CustomerFrame frame = new CustomerFrame();
					frame.setVisible(true);
					frame.connectToServer();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public CustomerFrame() {
		setTitle("Customer Order Frame");
		
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 607, 387);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(new GridLayout(4, 4, 0, 0));
		
		JPanel panel_1 = new JPanel();
		contentPane.add(panel_1);
		panel_1.setLayout(new BorderLayout(0, 0));
		
		JLabel lblNewLabel = new JLabel("Welcome to the Restaurunt.");
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		panel_1.add(lblNewLabel, BorderLayout.NORTH);
		
		JLabel lblTableNumber = new JLabel("Table Number: " + tableNumber);
		lblTableNumber.setHorizontalAlignment(SwingConstants.CENTER);
		panel_1.add(lblTableNumber, BorderLayout.CENTER);
		
		JLabel lblPleaseEnterYour = new JLabel("Please enter your flight number and order below and press submit.");
		lblPleaseEnterYour.setHorizontalAlignment(SwingConstants.CENTER);
		panel_1.add(lblPleaseEnterYour, BorderLayout.SOUTH);
		
		JPanel panel_2 = new JPanel();
		contentPane.add(panel_2);
		
		JLabel lblNewLabel_1 = new JLabel("Input Flight Number:");
		panel_2.add(lblNewLabel_1);
		
		flighttextField = new JTextField();
		panel_2.add(flighttextField);
		flighttextField.setColumns(10);
		
		JPanel panel_3 = new JPanel();
		contentPane.add(panel_3);
		panel_3.setLayout(new BorderLayout(0, 0));
		
		JPanel panel_4 = new JPanel();
		FlowLayout flowLayout = (FlowLayout) panel_4.getLayout();
		panel_3.add(panel_4, BorderLayout.NORTH);
		
		JLabel lblInputOrder = new JLabel("Input Order:");
		panel_4.add(lblInputOrder);
		
		JPanel orderPanel = new JPanel();
		panel_3.add(orderPanel, BorderLayout.CENTER);
		
		JLabel lblDrink = new JLabel("Drink:");
		orderPanel.add(lblDrink);
		
		drinktextField = new JTextField();
		orderPanel.add(drinktextField);
		drinktextField.setColumns(10);
		
		JLabel lblAppetizer = new JLabel("Appetizer:");
		orderPanel.add(lblAppetizer);
		
		appetizertextField = new JTextField();
		orderPanel.add(appetizertextField);
		appetizertextField.setColumns(10);
		
		JLabel lblMainCourse = new JLabel("Main Course:");
		orderPanel.add(lblMainCourse);
		
		maintextField = new JTextField();
		orderPanel.add(maintextField);
		maintextField.setColumns(10);
		
		JLabel lblDesert = new JLabel("Desert:");
		orderPanel.add(lblDesert);
		
		deserttextField = new JTextField();
		orderPanel.add(deserttextField);
		deserttextField.setColumns(10);
		
		JPanel panel = new JPanel();
		contentPane.add(panel);
		
		JButton btnSubmit = new JButton("Submit");
		btnSubmit.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				
				//Make the total order to send
				String totalOrder = "Customer. Flight Number: " + flighttextField.getText() + ", Table Number: " + tableNumber + ", Drink: " + drinktextField.getText() + ", Appetizer: " + appetizertextField.getText() +
						", Main: " + maintextField.getText() + ", Desert: " + deserttextField.getText();
				
				sendOrder(totalOrder);
				
				JOptionPane.showMessageDialog(new JFrame(), "Order Submitted");
				
			}
		});
		panel.add(btnSubmit);
	}
	
	/*connect to the server*/
	public void connectToServer(){
		  
		  try {
			  
				Socket serverSocket = new Socket("localhost",PORT);
				in= new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
				System.out.println("Connected to localhost in port 4921 - Customer");
				out = new PrintWriter(serverSocket.getOutputStream(),true);

				out.println("Customer");
			
				//String readLine = waitForServerResponse();
				//System.out.println("Customer read: " + readLine);
				

				
			} catch (UnknownHostException e) {
				e.printStackTrace();
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
	
	public void sendOrder(String str){
		out.println(str);
		System.out.println("Order done writing to the server.");
	}

}
