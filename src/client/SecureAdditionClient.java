
package client;

import java.io.*;
import java.net.*;
import java.security.KeyStore;
import javax.net.ssl.*;
import java.util.Scanner;

//A client-side class that uses a secure TCP/IP socket
public class SecureAdditionClient {
	private InetAddress host;
	private int port;
	
	// Default port used by both client and server 
	static final int DEFAULT_PORT = 8189;
	
	// Client-side keystore and truststore with passwords
    // (keystore holds the client's private key + certificate,
    //  truststore holds certificates of servers it trusts)
	static final String KEYSTORE = "src/client/LIUkeystore.ks";
	static final String TRUSTSTORE = "src/client/LIUtruststore.ks";
	static final String KEYSTOREPASS = "123456";
	static final String TRUSTSTOREPASS = "abcdef";
	
	// Folder where the client stores its local files
	static final String CLIENT_FILES_DIR = "src/client/files/";
	
	// Constructor @param host Internet address of the host where the server is located
	// @param port Port number on the host where the server is listening
	public SecureAdditionClient(InetAddress host, int port) {
		this.host = host;
		this.port = port;
	}
	
	/** Starts the client, sets up SSL context and communicates with the server */
	public void run() {
		try {
			// === Load keystore & truststore ===
			// The keystore contains the client's private key + certificate
			// Loads the client's keystore containing its private key and certificate
			// So the client can prove its identity to the server
			KeyStore ks = KeyStore.getInstance("JCEKS");
			ks.load(new FileInputStream(KEYSTORE), KEYSTOREPASS.toCharArray());
			
			// The truststore contains trusted server certificates
			// Loads the client's truststore containing trusted server certificates
			// So the client can verify which server to trust
			KeyStore ts = KeyStore.getInstance("JCEKS");
			ts.load(new FileInputStream(TRUSTSTORE), TRUSTSTOREPASS.toCharArray());

			// === Initialize Key and Trust Manager factories ===
			// Creates a factory that manages the client's keys for SSL handshake
			// Handles the client-side of the cryptographic handshake
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, KEYSTOREPASS.toCharArray());

			// Creates a factory that decides which server certificates to trust
			// Implements the client's trust policy
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(ts);

			// === Create SSLContext and socket factory ===
			// Creates the main SSL context that combines keys and trust settings
			// This is the core SSL engine that handles all secure communication
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

			SSLSocketFactory sslFact = sslContext.getSocketFactory();  
			
			// === Create the SSL socket (client side) ===
			// This triggers the SSL/TLS handshake:
            //  - server sends its certificate
            //  - client verifies server identity against its truststore
            //  - client sends its certificate to server for mutual auth
			SSLSocket client =  (SSLSocket)sslFact.createSocket(host, port);
			client.setEnabledCipherSuites(client.getSupportedCipherSuites());
			System.out.println("\n>>>> SSL/TLS handshake completed");

			// === Streams for communication over encrypted channel ===
			BufferedReader socketIn = new BufferedReader(new InputStreamReader(client.getInputStream()));
			PrintWriter socketOut = new PrintWriter(client.getOutputStream(), true);
			
			// === User interface in console ===
			Scanner scan = new Scanner(System.in);
			System.out.println("Select option\n"
					+ "1: Download file from server\n"
					+ "2: Upload file to server\n"
					+ "3: Delete file on server\n"
					+ "Enter choice (1-3): ");
			
			String option = scan.nextLine(); // user’s choice
			socketOut.println(option); // send choice to server
			
			// === Handle each menu choice ===
			switch (option) {
            	case "1": // --- DOWNLOAD ---
            		System.out.print("Enter filename to download: "); 
                    String downloadFilename = scan.nextLine();
                    socketOut.println(downloadFilename); // tell server which file
                    
                    String status = socketIn.readLine(); // server reply
                    if (status.equals("FILE_EXISTS")) {
                        downloadFile(socketIn, downloadFilename);
                        System.out.println("Download completed successfully!");
                    } else {
                        System.out.println("Error: " + status);
                    }
            		break;
            		
            	case "2": // --- UPLOAD ---
            		System.out.print("Enter filename to upload: "); 
                    String uploadFilename = scan.nextLine();
                    File uploadFile = new File(CLIENT_FILES_DIR + uploadFilename);
                    
                    // Check that the file exists locally before uploading
                    if (!uploadFile.exists()) {
                        System.out.println("Error: File not found locally");
                        socketOut.println("ERROR:File not found");
                    } else {
                        socketOut.println(uploadFilename); // Send filename to server first
                        uploadFile(socketOut, uploadFile);
                        System.out.println("Upload completed!");
                    }
            		break;
            		
            	case "3": // --- DELETE ---
            		System.out.print("Enter filename to delete: "); 
            		String deleteFilename = scan.nextLine();
            		socketOut.println(deleteFilename); // tell server which file
            		
            		String deleteResult = socketIn.readLine();
                    System.out.println("Server response: " + deleteResult);
            		break;
            		
            	default:
                    System.out.println("Invalid option");
                    socketOut.println("INVALID_OPTION");
                    break;
			}
			
			// Signal the end of the session to server
			scan.close();
            socketOut.println("END_SESSION"); // Signal end of session
            client.close();
			
		} catch(Exception e) {
			System.out.println("Client error: " + e);
			e.printStackTrace();
		}
	}
	
	/** Receives a file from server over the secure channel */
    private void downloadFile(BufferedReader socketIn, String filename) {
    	try {
    		
    		File downloadDir = new File(CLIENT_FILES_DIR);
    		if (!downloadDir.exists()) downloadDir.mkdirs();
    		
    		File outputFile = new File(CLIENT_FILES_DIR + filename);
            FileWriter writer = new FileWriter(outputFile);
            
            String line;
            // Server signals end of file with END_OF_FILE marker
            while (!(line = socketIn.readLine()).equals("END_OF_FILE")) {
                writer.write(line + "\n");
            }
            writer.close();
    		
    	} catch (Exception e) {
    		System.out.println("Download error: " + e);
		}
    }
	
    /** Sends a file to server over the secure channel */
    private void uploadFile(PrintWriter socketOut, File file) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                socketOut.println(line);
            }
            reader.close();
            socketOut.println("END_OF_FILE"); // mark end of file for server
        } catch (Exception e) {
            System.out.println("Upload error: " + e);
        }
    }
	
    /** Entry point of client */
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
