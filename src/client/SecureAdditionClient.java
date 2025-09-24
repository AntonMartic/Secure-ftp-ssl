// A client-side class that uses a secure TCP/IP socket

package client;

import java.io.*;
import java.net.*;
import java.security.KeyStore;
import javax.net.ssl.*;
import java.util.Scanner;

public class SecureAdditionClient {
	private InetAddress host;
	private int port;
	// This is not a reserved port number 
	static final int DEFAULT_PORT = 8189;
	static final String KEYSTORE = "src/client/LIUkeystore.ks";
	static final String TRUSTSTORE = "src/client/LIUtruststore.ks";
	static final String KEYSTOREPASS = "123456";
	static final String TRUSTSTOREPASS = "abcdef";
	static final String CLIENT_FILES_DIR = "src/client/files/";
	
	// Constructor @param host Internet address of the host where the server is located
	// @param port Port number on the host where the server is listening
	public SecureAdditionClient(InetAddress host, int port) {
		this.host = host;
		this.port = port;
	}
	
  // The method used to start a client object
	public void run() {
		try {

			KeyStore ks = KeyStore.getInstance("JCEKS");
			ks.load(new FileInputStream(KEYSTORE), KEYSTOREPASS.toCharArray());
			
			KeyStore ts = KeyStore.getInstance("JCEKS");
			ts.load(new FileInputStream(TRUSTSTORE), TRUSTSTOREPASS.toCharArray());

			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, KEYSTOREPASS.toCharArray());

			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(ts);

			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init( kmf.getKeyManagers(), tmf.getTrustManagers(), null);

			SSLSocketFactory sslFact = sslContext.getSocketFactory();   
			
			// Initiates connection to server and performs SSL handshake
			// Client verifies server's certificate against its truststore
			SSLSocket client =  (SSLSocket)sslFact.createSocket(host, port);
			client.setEnabledCipherSuites(client.getSupportedCipherSuites() );
			System.out.println("\n>>>> SSL/TLS handshake completed");

			
			BufferedReader socketIn = new BufferedReader(new InputStreamReader(client.getInputStream()));
			PrintWriter socketOut = new PrintWriter(client.getOutputStream(), true);
			
			/* Input server action (UI) */
			Scanner scan = new Scanner(System.in);
			
			System.out.println("Select option\n"
					+ "1: Download file from server\n"
					+ "2: Upload file to server\n"
					+ "3: Delete file on server\n"
					+ "Enter choice (1-3): ");
			
			String option = scan.nextLine(); // input option
			socketOut.println(option); // Send option to server
			
			switch (option) {
            	case "1": // DOWNLOAD
            		System.out.print("Enter filename to download: "); 
                    String downloadFilename = scan.nextLine(); // input filename
                    socketOut.println(downloadFilename); // Send filename to server
                    
                    // Read server response
                    String status = socketIn.readLine();
                    if (status.equals("FILE_EXISTS")) {
                        downloadFile(socketIn, downloadFilename);
                        System.out.println("Download completed successfully!");
                    } else {
                        System.out.println("Error: " + status);
                    }
            		break;
            		
            	case "2": // UPLOAD
            		System.out.print("Enter filename to upload: "); 
                    String uploadFilename = scan.nextLine(); // input filename
                    File uploadFile = new File(CLIENT_FILES_DIR + uploadFilename);
                    
                    // Check if file exist
                    if (!uploadFile.exists()) {
                        System.out.println("Error: File not found locally");
                        socketOut.println("ERROR:File not found");
                    } else {
                        socketOut.println(uploadFilename); // Send filename to server
                        uploadFile(socketOut, uploadFile);
                        System.out.println("Upload completed!");
                    }
            		break;
            		
            	case "3": // DELETE
            		System.out.print("Enter filename to delete: "); 
            		String deleteFilename = scan.nextLine();
            		socketOut.println(deleteFilename); // Send filename to server
            		
            		String deleteResult = socketIn.readLine();
                    System.out.println("Server response: " + deleteResult);
            		break;
            		
            	default:
                    System.out.println("Invalid option");
                    socketOut.println("INVALID_OPTION");
                    break;
			}
			
			scan.close();
            socketOut.println("END_SESSION"); // Signal end of session
            client.close();
			
		} catch(Exception e) {
			System.out.println("Client error: " + e);
			e.printStackTrace();
		}
	}
	
	// Method to download file from server
    private void downloadFile(BufferedReader socketIn, String filename) {
    	try {
    		
    		File downloadDir = new File(CLIENT_FILES_DIR);
    		if (!downloadDir.exists()) downloadDir.mkdirs();
    		
    		File outputFile = new File(CLIENT_FILES_DIR + filename);
            FileWriter writer = new FileWriter(outputFile);
            
            String line;
            while (!(line = socketIn.readLine()).equals("END_OF_FILE")) {
                writer.write(line + "\n");
            }
            writer.close();
    		
    	} catch (Exception e) {
    		System.out.println("Download error: " + e);
		}
    }
	
    // Method to upload file to server
    private void uploadFile(PrintWriter socketOut, File file) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                socketOut.println(line);
            }
            reader.close();
            socketOut.println("END_OF_FILE"); // Signal end of file
        } catch (Exception e) {
            System.out.println("Upload error: " + e);
        }
    }
	
	// The test method for the class @param args Optional port number and host name
	public static void main(String[] args) {
		try {
			InetAddress host = InetAddress.getLocalHost();
			int port = DEFAULT_PORT;
			if (args.length > 0) {
				port = Integer.parseInt(args[0]);
			}
			if (args.length > 1) {
				host = InetAddress.getByName(args[1]);
			}
			SecureAdditionClient addClient = new SecureAdditionClient(host, port);
			addClient.run();
		} catch (UnknownHostException e) {
			System.out.println(e);
			e.printStackTrace();
		}
	}
}
