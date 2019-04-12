package secure;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public interface FileDecryption {
	void decrypt(String cipherTextFileName, String keyStoreFileName, String keyStorePassword, String pairPassword)
			throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException,
			IOException, InvalidKeyException, UnrecoverableKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException;
}
