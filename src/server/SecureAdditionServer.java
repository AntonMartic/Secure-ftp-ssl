// An example class that uses the secure server socket class

package server;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.*;
import java.util.StringTokenizer;


public class SecureAdditionServer {
	private int port;
	// This is not a reserved port number
	static final int DEFAULT_PORT = 8189;
	static final String KEYSTORE = "src/server/LIUkeystore.ks";
	static final String TRUSTSTORE = "src/server/LIUtruststore.ks";
	static final String KEYSTOREPASS = "123456";
	static final String TRUSTSTOREPASS = "abcdef";
	static final String SERVER_FILES_DIR = "src/server/files/";
	
	/** Constructor
	 * @param port The port where the server
	 *    will listen for requests
	 */
	SecureAdditionServer(int port) {
		this.port = port;
	}
	
	/** The method that does the work for the class */
	public void run() {
		try {
			
			// Loads the server's keystore containing its private key and certificate
			// So the server can prove its identity to clients
			KeyStore ks = KeyStore.getInstance("JCEKS");
			ks.load(new FileInputStream(KEYSTORE), KEYSTOREPASS.toCharArray());
			
			// Loads the server's truststore containing trusted client certificates
			// So the server can verify which clients to trust
			KeyStore ts = KeyStore.getInstance("JCEKS");
			ts.load(new FileInputStream(TRUSTSTORE), TRUSTSTOREPASS.toCharArray());
			
			// Creates a factory that manages the server's keys for SSL handshake
			// Handles the server-side of the cryptographic handshake
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, KEYSTOREPASS.toCharArray());
			
			// Creates a factory that decides which client certificates to trust
			// Implements the server's trust policy
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(ts);
			
			// Creates the main SSL context that combines keys and trust settings
			// This is the core SSL engine that handles all secure communication
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			
			// Creates a secure server socket that listens on the specified port
			// This is where clients will connect securely
			SSLServerSocketFactory sslServerFactory = sslContext.getServerSocketFactory();
			SSLServerSocket sss = (SSLServerSocket) sslServerFactory.createServerSocket(port);
			
			// Server authenticates the client
			sss.setNeedClientAuth(true);
			sss.setEnabledCipherSuites( sss.getSupportedCipherSuites());
			
			System.out.println("\n>>>> SecureAdditionServer: active ");
			
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
	
	// Inner class to handle each client connection
    private class ClientHandler extends Thread {
        private SSLSocket socket;
        
        public ClientHandler(SSLSocket socket) {
            this.socket = socket;
        }
        
        public void run() {
        	try(
        			// Creates streams to read from and write to the client
        			// All data through these streams is automatically encrypted/decrypted by SSL
        			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        			PrintWriter out = new PrintWriter(socket.getOutputStream(), true );
    			) {
        		
	        		String option = in.readLine();
	                System.out.println("Client selected option: " + option);
	
	                switch (option) {
	                    case "1": // DOWNLOAD
	                        handleDownload(in, out);
	                        break;
	                    case "2": // UPLOAD  
	                    	handleUpload(in, out);
	                        break;
	                    case "3": // DELETE

	                        break;
	                    default:
	                        out.println("ERROR:Invalid option");
	                        break;
	                }
	                
	                // Wait for session end signal
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
        
        private void handleDownload(BufferedReader in, PrintWriter out) {
        	try {
        		String filename = in.readLine();
                File file = new File(SERVER_FILES_DIR + filename);
                
                if (!file.exists()) {
                    out.println("ERROR:File not found");
                    System.out.println("Download failed: File " + '"' +filename + '"' + " not found");
                    return;
                }
                
                out.println("FILE_EXISTS"); // Tell client file exists
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
        
        private void handleUpload(BufferedReader in, PrintWriter out) {
        	try {
        		String filename = in.readLine();
        		
        		if (filename.startsWith("ERROR:")) {
                    System.out.println("Client error: " + filename);
                    return;
                }
        		
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
        
        
    }
	
	
	/** The test method for the class
	 * @param args[0] Optional port number in place of
	 *        the default
	 */
	public static void main(String[] args) {
		int port = DEFAULT_PORT;
		if (args.length > 0 ) {
			port = Integer.parseInt(args[0]);
		}
		SecureAdditionServer addServe = new SecureAdditionServer(port);
		addServe.run();
	}
}

