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
	
	/** Constructor
	 * @param port The port where the server
	 *    will listen for requests
	 */
	SecureAdditionServer( int port ) {
		this.port = port;
	}
	
	/** The method that does the work for the class */
	public void run() {
		try {
			
			// Loads the server's keystore containing its private key and certificate
			// So the server can prove its identity to clients
			KeyStore ks = KeyStore.getInstance( "JCEKS" );
			ks.load( new FileInputStream( KEYSTORE ), KEYSTOREPASS.toCharArray() );
			
			// Loads the server's truststore containing trusted client certificates
			// So the server can verify which clients to trust
			KeyStore ts = KeyStore.getInstance( "JCEKS" );
			ts.load( new FileInputStream( TRUSTSTORE ), TRUSTSTOREPASS.toCharArray() );
			
			// Creates a factory that manages the server's keys for SSL handshake
			// Handles the server-side of the cryptographic handshake
			KeyManagerFactory kmf = KeyManagerFactory.getInstance( "SunX509" );
			kmf.init( ks, KEYSTOREPASS.toCharArray() );
			
			// Creates a factory that decides which client certificates to trust
			// Implements the server's trust policy
			TrustManagerFactory tmf = TrustManagerFactory.getInstance( "SunX509" );
			tmf.init( ts );
			
			// Creates the main SSL context that combines keys and trust settings
			// This is the core SSL engine that handles all secure communication
			SSLContext sslContext = SSLContext.getInstance( "TLS" );
			sslContext.init( kmf.getKeyManagers(), tmf.getTrustManagers(), null );
			
			// Creates a secure server socket that listens on the specified port
			// This is where clients will connect securely
			SSLServerSocketFactory sslServerFactory = sslContext.getServerSocketFactory();
			SSLServerSocket sss = (SSLServerSocket) sslServerFactory.createServerSocket( port );
			
			// Server authenticates the client
			sss.setNeedClientAuth(true);
			sss.setEnabledCipherSuites( sss.getSupportedCipherSuites() );
			
			System.out.println("\n>>>> SecureAdditionServer: active ");
			
			// Waits for a client to connect, then establishes the secure SSL/TLS handshake
			// 1. Client and server negotiate encryption algorithms
			// 2. Server proves its identity with certificate
			// 3. They establish a shared secret key for encryption
			// 4. Secure channel is ready!
			SSLSocket incoming = (SSLSocket)sss.accept();

			// Creates streams to read from and write to the client
			// All data through these streams is automatically encrypted/decrypted by SSL
			BufferedReader in = new BufferedReader( new InputStreamReader( incoming.getInputStream() ) );
			PrintWriter out = new PrintWriter( incoming.getOutputStream(), true );			
			
			// Reads lines from client until an empty line is received
			// Adds numbers together, TODO: replace with file operations (download, upload, delete files)
			String str;
			while ( !(str = in.readLine()).equals("") ) {
				double result = 0;
				StringTokenizer st = new StringTokenizer( str );
				try {
					while( st.hasMoreTokens() ) {
						Double d = new Double( st.nextToken() );
						result += d.doubleValue();
					}
					out.println( "The result is " + result );
				}
				catch( NumberFormatException nfe ) {
					out.println( "Sorry, your list contains an invalid number" );
				}
			}
			incoming.close();
		}
		catch( Exception x ) {
			System.out.println( x );
			x.printStackTrace();
		}
	}
	
	
	/** The test method for the class
	 * @param args[0] Optional port number in place of
	 *        the default
	 */
	public static void main( String[] args ) {
		int port = DEFAULT_PORT;
		if (args.length > 0 ) {
			port = Integer.parseInt( args[0] );
		}
		SecureAdditionServer addServe = new SecureAdditionServer( port );
		addServe.run();
	}
}

