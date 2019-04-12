package secure;

import java.io.FileInputStream;
import java.util.Properties;

public class FileHandler {
	private static final int KEY_STORE_NAME = 0;
	private static final int KEY_STORE_PASSWORD = 1;
	private static final int KEY_STORE_PAIR_PASSWORD = 2;
	private static final int FILE_NAME = 3;
	private static final int MODE = 4;

	private static final String ENCRYPTING_MODE = "e";
	private static final String DECRYPTION_MODE = "d";
	private static final String PROPERTIES_FILE_NAME = "resources/conf.properties";

	public static void main(String[] args) {
		Properties propFile = new Properties();

		try {
			propFile.load(new FileInputStream(PROPERTIES_FILE_NAME));

			if (args[MODE].equals(ENCRYPTING_MODE)) {
				new StandardFileEncryption(propFile, PROPERTIES_FILE_NAME).encrypt(args[FILE_NAME],
						args[KEY_STORE_NAME], args[KEY_STORE_PASSWORD], args[KEY_STORE_PAIR_PASSWORD]);
			} else if (args[MODE].equals(DECRYPTION_MODE)) {
				new StandardFileDecryption(propFile, PROPERTIES_FILE_NAME).decrypt(args[FILE_NAME],
						args[KEY_STORE_NAME], args[KEY_STORE_PASSWORD], args[KEY_STORE_PAIR_PASSWORD]);
			} else {
				System.out.println("Bad mode given.");
			}
		} catch (Exception e) {
			System.out.println("ERROR" + e.getMessage());
		}
	}
}