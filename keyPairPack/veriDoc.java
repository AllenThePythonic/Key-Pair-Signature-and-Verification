package keyPairPack;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

public class veriDoc {

	private static boolean verify(String keyName, byte[] data, byte[] sign)
			throws Exception {

		/* Map the file of PUBLIC key from file */
		File f = new File(keyName);
		FileInputStream fis = null;

		fis = new FileInputStream(f);

		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int) f.length()];

		dis.readFully(keyBytes);
		dis.close();

		/* Define X509 Encoding Standard */
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = null;

		kf = KeyFactory.getInstance("RSA");

		PublicKey key = kf.generatePublic(spec);

		Signature signer = Signature.getInstance("SHA512withRSA");
		signer.initVerify(key);
		signer.update(data);
		return (signer.verify(sign));
	}

	/* For extracting DataInputStream */
	private static DataInputStream extracted(FileInputStream in) {
		return new DataInputStream(in);
	}

	/* Main program of veriDoc */
	public static void main(String[] args) {

		byte[] data = null;
		byte[] signatureBytes = null;

		System.out.println("Args[2] -> " + args[2]);
		System.out.println("Args[3] -> " + args[3]);
		System.out.println("Args[4] -> " + args[4]);

		try {
			/* Data input from Test.doc */
			FileInputStream in = new FileInputStream(new File(args[2]));
			int count = in.available();

			/* Read the Doc to be bytes */
			data = new byte[count];
			extracted(in).read(data);

			/* Read the signature file to be bytes */
			FileInputStream in2 = new FileInputStream(new File(args[4]));
			int count2 = in2.available();

			/* Read the Doc to be bytes */
			signatureBytes = new byte[count2];
			extracted(in2).read(signatureBytes);
			extracted(in2).close();

			System.out.println("length of Bytes " + signatureBytes.length);

			if (verify(new String(args[3]), data, signatureBytes)) {
				System.out.println("Verify.");
			} else {
				System.out.println("Not Verify.");
			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
