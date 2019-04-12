package secure;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class StandardFileDecryption extends FileSecurity implements FileDecryption {
	private static final String NOT_VERIFIED = "The signature was not verified";

	public StandardFileDecryption(Properties properties, String propertiesFileName) {
		super(properties, propertiesFileName);
	}

	/**
	 * decrypt the encrypted file using the chosen symmetric algorithm.
	 */
	@Override
	public void decrypt(String cipherTextFileName, String keyStoreFileName, String keyStorePassword,
			String pairPassword) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException,
			CertificateException, IOException, InvalidKeyException, UnrecoverableKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException {
		KeyStore keyStore = getKeyStore(keyStoreFileName, keyStorePassword);

		// Read all the values from the property file.
		Decoder decoder = Base64.getDecoder();

		byte[] encryptedAes = decoder.decode(getProperty(SYMMETRIC_KEY));
		byte[] iv = decoder.decode(getProperty(IV));
		byte[] signature = decoder.decode(getProperty(SIGNATURE));

		byte[] aesKey = decryptSymmetricKey(getProperty(A_SYMMETRIC_ALGO),
				(PrivateKey) keyStore.getKey(getProperty(SECOND_KEYSTORE_PAIR), pairPassword.toCharArray()),
				encryptedAes);

		File encryptedFile = new File(cipherTextFileName);
		String decryptedFileName = encryptedFile.getParent() + "\\" + DECRYPTED_FILE_NAME;

		decryptFile(aesKey, iv, cipherTextFileName, encryptedFile, decryptedFileName);

		if (!verifySignature(calculateEncryptedFileHash(cipherTextFileName), signature, keyStore)) {
			System.out.println(NOT_VERIFIED);

			try (FileOutputStream fis = new FileOutputStream(decryptedFileName)) {
				fis.write(NOT_VERIFIED.getBytes());
			}
		}
	}

	/**
	 * Verifing that the given signature from the properties is like the signature of the hash of the encrypted file.
	 * @param hash
	 * @param signature
	 * @param keyStore
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws KeyStoreException
	 * @throws SignatureException
	 */
	private boolean verifySignature(byte[] hash, byte[] signature, KeyStore keyStore)
			throws NoSuchAlgorithmException, InvalidKeyException, KeyStoreException, SignatureException {
		Signature sig = Signature.getInstance(getProperty(SIGNATURE_TYPE));
		sig.initVerify(keyStore.getCertificate(getProperty(FIRST_KEY_STORE_CRT)).getPublicKey());
		sig.update(hash);

		return sig.verify(signature);
	}

	/**
	 * Decryped the file using the symmetric key and the iv.
	 * 
	 * @param aesKey
	 * @param iv
	 * @param cipherTextFileName
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IOException
	 */
	private void decryptFile(byte[] aesKey, byte[] iv, String cipherTextFileName, File encryptedFile,
			String decrypedFileName) throws InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchPaddingException, IOException {
		SecretKeySpec sks = new SecretKeySpec(aesKey, getProperty(SYMMETRIC_ALGO));
		IvParameterSpec ivParam = new IvParameterSpec(iv);

		Cipher cipher = Cipher.getInstance(getTransformation());
		cipher.init(Cipher.DECRYPT_MODE, sks, ivParam);

		try (CipherInputStream cis = new CipherInputStream(new FileInputStream(encryptedFile), cipher)) {
			try (FileOutputStream fos = new FileOutputStream(decrypedFileName)) {
				byte[] fileBytes = new byte[1024];
				int amountRead;

				while ((amountRead = cis.read(fileBytes)) != -1) {
					fos.write(fileBytes, 0, amountRead);
				}
			}
		}
	}

	/**
	 * Decrypted the symmetric key we got from the properties file using the a
	 * symmetric algorithm and the private key of the current user.
	 * 
	 * @param aSymmerticAlgo
	 * @param privateKey
	 * @param encryptedAes
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private byte[] decryptSymmetricKey(String aSymmerticAlgo, PrivateKey privateKey, byte[] encryptedAes)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {
		Cipher cipher = Cipher.getInstance(aSymmerticAlgo);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		return cipher.doFinal(encryptedAes);
	}

}
