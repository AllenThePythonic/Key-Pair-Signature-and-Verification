package keyPairPack;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/* 
 * java signDoc <<theDoc>> <<privateKeyFile>> <<signatureFile>> 
 * 
 * When the above command is executed, theDoc will be signed with the private key stored in privatedKeyFile
 * The signature is stored in signature file.
 * 
 */

public class signDoc {

	/* Get private key from file */
	private static PrivateKey getPrivateKey(String keyName)
			throws InvalidKeySpecException, IOException,
			NoSuchAlgorithmException {

		/* Map the file of private key */
		File f = new File(keyName);
		FileInputStream fis = null;

		fis = new FileInputStream(f);

		DataInputStream dis = extracted(fis);
		byte[] keyBytes = new byte[(int) f.length()];

		dis.readFully(keyBytes);
		dis.close();

		/* Define PKCS8E Encoding Standard */
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = null;

		/* Generate RSA private key by Key Factory */
		kf = KeyFactory.getInstance("RSA");

		return kf.generatePrivate(spec);
	}

	/* For extracting DataInputStream */
	private static DataInputStream extracted(FileInputStream in) {
		return new DataInputStream(in);
	}

	/* Main program of signDoc */
	public static void main(String args[]) {

		try {

			System.out.println("Args[2] -> " + args[2]);
			System.out.println("Args[3] -> " + args[3]);
			System.out.println("Args[4] -> " + args[4]);

			/* Data input from Test.doc */
			FileInputStream in = new FileInputStream(new File(args[2]));
			int count = in.available();
			/* Read the Doc to be bytes */
			byte[] data = new byte[count];
			extracted(in).read(data);
			extracted(in).close();

			/* Define the signature type */
			Signature sign = Signature.getInstance("SHA512withRSA");

			/* Initial Signature */
			sign.initSign(getPrivateKey(args[3]));
			sign.update(data);

			/* Store the signature file */
			byte[] signatureBytes = sign.sign();

			/* Output file of byte array */
			FileOutputStream stream = new FileOutputStream(args[4]);
			try {
				stream.write(signatureBytes);
			} finally {
				stream.close();
			}

			/* Message */
			System.out.println("Signature length : " + signatureBytes.length);
			System.out.println("Signature has been Stored.");

			/* Capture all possible Exceptions */
		} catch (NoSuchAlgorithmException e) {

			System.out.println(e);
		} catch (InvalidKeyException e) {

			e.printStackTrace();
		} catch (InvalidKeySpecException e) {

			e.printStackTrace();
		} catch (SignatureException e) {

			e.printStackTrace();
		} catch (IOException e) {

			e.printStackTrace();
		} catch (Exception e) {

			e.printStackTrace();
		}
	}
}
