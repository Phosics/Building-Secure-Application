package secure;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class StandardFileEncryption extends FileSecurity implements FileEncryption {
	public StandardFileEncryption(Properties properties, String propertiesFileName) {
		super(properties, propertiesFileName);
	}

	/**
	 * Encrypt a file using generated symmetric key with given private-public keys.
	 */
	@Override
	public void encrypt(String plainTextFileName, String keyStoreFileName, String keyStorePassword, String pairPassword)
			throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException,
			IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, UnrecoverableKeyException, SignatureException {
		KeyStore keyStore = getKeyStore(keyStoreFileName, keyStorePassword);
		IvParameterSpec iv = generateIV(getProperty(PRND_METHOD), getIntProperty(SYMMETRIC_KEY_IV_SIZE));
		SecretKey symmetricKey = generateSymmetricKey(getProperty(SYMMETRIC_ALGO));

		// encrypting the file using the symmetric key and the iv.
		Cipher cipher = Cipher.getInstance(getTransformation());
		cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, iv);

		File plainTextFile = new File(plainTextFileName);
		String encryptedFileName = plainTextFile.getParent() + "\\" + ENCRYPTED_FILE_NAME;
		encryptFile(new File(plainTextFileName), cipher, encryptedFileName);

		byte[] signature = signEncryptedFile(calculateEncryptedFileHash(encryptedFileName),
				(PrivateKey) keyStore.getKey(getProperty(FIRST_KEYSTORE_PAIR), pairPassword.toCharArray()));

		saveToProperties(iv.getIV(), encryptSymmetricKey(getProperty(A_SYMMETRIC_ALGO), symmetricKey, keyStore),
				signature);
	}

	/**
	 * Sign the hash of the file using the current user private key.
	 * 
	 * @param signatureType
	 * @param encryptedFileHash
	 * @param privateKey
	 * @return
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private byte[] signEncryptedFile(byte[] encryptedFileHash, PrivateKey privateKey)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		Signature sig = Signature.getInstance(getProperty(SIGNATURE_TYPE));
		sig.initSign(privateKey);
		sig.update(encryptedFileHash);

		return sig.sign();
	}

	/**
	 * Saves the new data into the properties file.
	 * 
	 * @param iv
	 * @param encryptedSymmetricKey
	 * @param signature
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private void saveToProperties(byte[] iv, byte[] encryptedSymmetricKey, byte[] signature)
			throws FileNotFoundException, IOException {
		Encoder base64Encoder = Base64.getEncoder();

		properties.put(SYMMETRIC_KEY, base64Encoder.encodeToString(encryptedSymmetricKey));
		properties.put(IV, base64Encoder.encodeToString(iv));
		properties.put(SIGNATURE, base64Encoder.encodeToString(signature));

		properties.store(new FileOutputStream(propertiesFileName), "");
	}

	/**
	 * Encrypt the symmetric key using the PublicKey of the other user by getting
	 * the PublicKey from the Certificate we got in the KeyStore.
	 * 
	 * @param aSymmetricAlgo
	 * @param secretKey
	 * @param keyStore
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws KeyStoreException
	 */
	private byte[] encryptSymmetricKey(String aSymmetricAlgo, SecretKey secretKey, KeyStore keyStore)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, KeyStoreException {
		Cipher cipher = Cipher.getInstance(aSymmetricAlgo);
		cipher.init(Cipher.ENCRYPT_MODE, keyStore.getCertificate(getProperty(SECOND_KEY_STORE_CRT)).getPublicKey());

		return cipher.doFinal(secretKey.getEncoded());
	}

	/**
	 * Encrypt the file using the CipherOutputStream
	 * 
	 * @param plainTextFile
	 * @param cos
	 * @throws IOException
	 */
	private static void encryptFile(File plainTextFile, Cipher cipher, String encryptedFileName) throws IOException {
		try (CipherOutputStream cos = new CipherOutputStream(new FileOutputStream(encryptedFileName), cipher)) {
			try (FileInputStream fis = new FileInputStream(plainTextFile)) {
				byte[] fileBytes = new byte[1024];
				int amountRead;
				
				while ((amountRead = fis.read(fileBytes)) != -1) {
					cos.write(fileBytes, 0, amountRead);
				}
			}
		}
	}

	/**
	 * Generating Random IV. Using SecureRandom to generate pseudo random sequence
	 * of bytes.
	 * 
	 * @return Iv
	 * @throws NoSuchAlgorithmException
	 */
	private static IvParameterSpec generateIV(String prndMethod, int ivSize) throws NoSuchAlgorithmException {
		SecureRandom sr = SecureRandom.getInstance(prndMethod);
		byte[] ivBytes = new byte[ivSize];

		sr.nextBytes(ivBytes);

		// Symmetric
		return new IvParameterSpec(ivBytes);
	}

	/**
	 * Using KeyGenerator to generate the SymmetricKey.
	 * 
	 * @param symmetricAlgorithem
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private static SecretKey generateSymmetricKey(String symmetricAlgorithem) throws NoSuchAlgorithmException {
		KeyGenerator kg = KeyGenerator.getInstance(symmetricAlgorithem);
		return kg.generateKey();
	}

}
