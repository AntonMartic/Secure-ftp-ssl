
package server;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.*;
import java.util.StringTokenizer;

// An example class that uses the secure server socket class
public class SecureAdditionServer {
	private int port;
	
	// Default port for server to listen on
	static final int DEFAULT_PORT = 8189;
	
	// Server-side keystore and truststore with passwords
    // (keystore holds the server's private key + certificate,
    //  truststore holds certificates of trusted clients)
	static final String KEYSTORE = "src/server/LIUkeystore.ks";
	static final String TRUSTSTORE = "src/server/LIUtruststore.ks";
	static final String KEYSTOREPASS = "123456";
	static final String TRUSTSTOREPASS = "abcdef";
	
	// Folder where server stores its files
	static final String SERVER_FILES_DIR = "src/server/files/";
	
	/** Constructor
	 * @param port The port where the server
	 *    will listen for requests
	 */
	SecureAdditionServer(int port) {
		this.port = port;
	}
	
	/** Starts the secure server, sets up SSL context and listens for connections */
	public void run() {
		try {
			// === Load server keystore and truststore ===
			// Loads the server's keystore containing its private key and certificate
			// So the server can prove its identity to clients
			KeyStore ks = KeyStore.getInstance("JCEKS");
			ks.load(new FileInputStream(KEYSTORE), KEYSTOREPASS.toCharArray());
			
			// Loads the server's truststore containing trusted client certificates
			// So the server can verify which clients to trust
			KeyStore ts = KeyStore.getInstance("JCEKS");
			ts.load(new FileInputStream(TRUSTSTORE), TRUSTSTOREPASS.toCharArray());
			
			// === Initialize Key and Trust Manager factories ===
			// Creates a factory that manages the server's keys for SSL handshake
			// Handles the server-side of the cryptographic handshake
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, KEYSTOREPASS.toCharArray());
			
			// Creates a factory that decides which client certificates to trust
			// Implements the server's trust policy
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(ts);
			
			// === Create SSLContext and server socket factory ===
			// Creates the main SSL context that combines keys and trust settings
			// This is the core SSL engine that handles all secure communication
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			
			// Creates a secure server socket that listens on the specified port
			// This is where clients will connect securely
			SSLServerSocketFactory sslServerFactory = sslContext.getServerSocketFactory();
			SSLServerSocket sss = (SSLServerSocket) sslServerFactory.createServerSocket(port);
			
			// Enable strong cipher suites
			sss.setEnabledCipherSuites(sss.getSupportedCipherSuites());
			
			// Force client authentication by server (mutual SSL)
			sss.setNeedClientAuth(true);
			
			System.out.println("\n>>>> SecureAdditionServer: active ");
			
			// === Main accept loop ===
			// Accepts new client connections and spins off a thread per client
			
			// Waits for a client to connect, then establishes the secure SSL/TLS handshake
			// 1. Client and server negotiate encryption algorithms
			// 2. Server proves its identity with certificate
			// 3. They establish a shared secret key for encryption
			// 4. Secure channel is ready!
			while (true) {
                SSLSocket incoming = (SSLSocket) sss.accept();
                System.out.println("Client connected!");
                
                // Handle each client in its own thread for multiple clients
                new ClientHandler(incoming).start();
            }

			
		}
		catch(Exception e) {
			System.out.println("Server error: " + e);
			e.printStackTrace();
		}
	}
	
	/** Inner class to handle each client independently */
    private class ClientHandler extends Thread {
        private SSLSocket socket;
        
        public ClientHandler(SSLSocket socket) {
            this.socket = socket;
        }
        
        public void run() {
        	try(
        			// Streams automatically encrypted/decrypted by SSL layer
        			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        			PrintWriter out = new PrintWriter(socket.getOutputStream(), true );
    			) {
        			// First line from client: which action?
	        		String option = in.readLine();
	                System.out.println("Client selected option: " + option);
	
	                // Handle requested operation
	                switch (option) {
	                    case "1": // DOWNLOAD
	                        handleDownload(in, out);
	                        break;
	                    case "2": // UPLOAD  
	                    	handleUpload(in, out);
	                        break;
	                    case "3": // DELETE
	                    	handleDelete(in, out);
	                        break;
	                    default:
	                        out.println("ERROR:Invalid option");
	                        break;
	                }
	                
	                // Wait for end-of-session signal from client
	                String endSignal = in.readLine();
	                if ("END_SESSION".equals(endSignal)) {
	                    System.out.println("Client session ended normally");
	                }
        		
        		} catch (Exception e) {
                    System.out.println("Client handling error: " + e);
                } finally {
                    try { socket.close(); } catch (IOException e) {}
                }
    	}
        
        /** Send a file to client securely */
        private void handleDownload(BufferedReader in, PrintWriter out) {
        	try {
        		String filename = in.readLine();
                File file = new File(SERVER_FILES_DIR + filename);
                
                if (!file.exists()) {
                    out.println("ERROR:File not found");
                    System.out.println("Download failed: File " + '"' +filename + '"' + " not found");
                    return;
                }
                
                out.println("FILE_EXISTS"); // tell client the file exists
                System.out.println("Sending file: " + filename);
                
                BufferedReader fileReader = new BufferedReader(new FileReader(file));
                String line;
                while ((line = fileReader.readLine()) != null) {
                    out.println(line);
                }
                fileReader.close();
                out.println("END_OF_FILE"); // Signal end of file
                
                System.out.println("File " + filename + " sent successfully");
                
        	} catch (Exception e) {
                System.out.println("Download handling error: " + e);
                out.println("ERROR:Server error during download");
            }
        }
        
        /** Receive a file from client securely */
        private void handleUpload(BufferedReader in, PrintWriter out) {
        	try {
        		String filename = in.readLine();
        		
        		if (filename.startsWith("ERROR:")) {
                    System.out.println("Client error: " + filename);
                    return;
                }
        		
        		// creates folder if it does not exist already
        		File uploadDir = new File(SERVER_FILES_DIR);
                if (!uploadDir.exists()) uploadDir.mkdirs();
                
                File file = new File(SERVER_FILES_DIR + filename);
                FileWriter writer = new FileWriter(file);
                System.out.println("Receiving file: " + filename);
                
                String line;
                while (!(line = in.readLine()).equals("END_OF_FILE")) {
                    writer.write(line + "\n");
                }
                writer.close();
                
                System.out.println("File " + filename + " received successfully");
                out.println("UPLOAD_SUCCESS");
                
        	} catch (Exception e) {
                System.out.println("Upload handling error: " + e);
                out.println("ERROR:Server error during upload");
            }
        }
        
        /** Delete a file on server */
        private void handleDelete(BufferedReader in, PrintWriter out) {
        	try {
        		String filename = in.readLine();
                File file = new File(SERVER_FILES_DIR + filename);
                
                if (file.delete()) {
                    out.println("File " + filename + " deleted successfully");
                    System.out.println("File " + filename + " deleted");
                } else {
                    out.println("ERROR:File not found or cannot be deleted");
                    System.out.println("Delete failed for file: " + filename);
                }
        	} catch (Exception e) {
                System.out.println("Delete handling error: " + e);
                out.println("ERROR:Server error during deletion");
            }
        }
        
    }
	
    /** Entry point of server */
	public static void main(String[] args) {
		int port = DEFAULT_PORT;
		if (args.length > 0 ) {
			port = Integer.parseInt(args[0]);
		}
		SecureAdditionServer addServe = new SecureAdditionServer(port);
		addServe.run();
	}
}

