package secure;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Properties;

public abstract class FileSecurity {
	protected static final String KEY_STORE_TYPE = "keyStoreType";
	protected static final String KEY_STORE_PROVIDER = "keyStoreProvider";
	protected static final String SYMMETRIC_ALGO = "symmetricAlgo";
	protected static final String A_SYMMETRIC_ALGO = "aSymmetricAlgo";
	protected static final String SIGNATURE_TYPE = "signatureType";
	protected static final String HASH_TYPE = "hashType";
	protected static final String HASH_PROVIDER = "hashProvider";
	protected static final String PRND_METHOD = "prndMethod";
	protected static final String SYMMETRIC_KEY_IV_SIZE = "symmetricKeyIVSize";
	protected static final String FIRST_KEY_STORE_CRT = "firstKeyStoreCrt";
	protected static final String SECOND_KEY_STORE_CRT = "secondKeyStoreCrt";
	protected static final String SYMMETRIC_ALGO_MODE = "symmetricAlgoMode";
	protected static final String SYMMETRIC_ALGO_PADDING = "symmetricAlgoPadding";
	protected static final String FIRST_KEYSTORE_PAIR = "firstKeyStorePair";
	protected static final String SECOND_KEYSTORE_PAIR = "secondKeyStorePair";
	protected static final String SYMMETRIC_KEY = "symmetricKey";
	protected static final String IV = "iv";
	protected static final String SIGNATURE = "signature";
	
	protected static final String ENCRYPTED_FILE_NAME = "ciphertext.txt";
	protected static final String DECRYPTED_FILE_NAME = "decrypted.txt";
	
	private static final String TRANSFORMATION_FORMAT = "%s/%s/%s";

	protected Properties properties;
	protected String propertiesFileName;

	public FileSecurity(Properties properties, String propertiesFileName) {
		this.properties = properties;
		this.propertiesFileName = propertiesFileName;
	}

	protected String getProperty(String key) {
		return properties.getProperty(key);
	}

	protected int getIntProperty(String key) {
		return Integer.parseInt(properties.getProperty(key));
	}

	/**
	 * Get a keystore.
	 * 
	 * @param keystoreFileName
	 * @param keyStorePassword
	 * @param keyStoreType
	 * @param keyStoreProvider
	 * @return
	 * @throws KeyStoreException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	protected KeyStore getKeyStore(String keystoreFileName, String keyStorePassword) throws KeyStoreException,
			NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance(getProperty(KEY_STORE_TYPE), getProperty(KEY_STORE_PROVIDER));
		keyStore.load(new FileInputStream(keystoreFileName), keyStorePassword.toCharArray());

		return keyStore;
	}
	
	/**
	 * Get the @algo/@mode/@padding string.
	 * 
	 * @return
	 */
	protected String getTransformation() {
		return String.format(TRANSFORMATION_FORMAT, getProperty(SYMMETRIC_ALGO), getProperty(SYMMETRIC_ALGO_MODE),
				getProperty(SYMMETRIC_ALGO_PADDING));
	}
	
	/**
	 * Calculate the hash value of the encrypted file using MessageDigest.
	 * 
	 * @param cipherFileName
	 * @param hashType
	 * @param hashProvider
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	protected byte[] calculateEncryptedFileHash(String encryptedFileName)
			throws NoSuchAlgorithmException, NoSuchProviderException, FileNotFoundException, IOException {
		MessageDigest md = MessageDigest.getInstance(getProperty(HASH_TYPE), getProperty(HASH_PROVIDER));

		try (FileInputStream fis = new FileInputStream(encryptedFileName)) {
			byte[] fileBytes = new byte[1024];
			int amountRead;
			
			while ((amountRead = fis.read(fileBytes)) != -1) {
				md.update(fileBytes, 0, amountRead);
			}
		}

		return md.digest();
	}
}
