import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.HexFormat;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.utils.Key;

public class Main {

	static final int NONCEBYTES = 24;
	static final int KEYBYTES = 32;
	static final String plaintext = "The quick brown fox jumps over the lazy dog";
	
	public static void main(String[] args) throws Exception {

		Security.addProvider(new BouncyCastleProvider());
		
		// Step 1: Create test keypair
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
		KeyPair kp = kpg.generateKeyPair();	    
		PrivateKey privKey = kp.getPrivate();
		PublicKey pubKey = kp.getPublic();
		
	    // Step 2: Create X25519 shared secret
		SecretKey secKey = generateSecretKey(privKey, pubKey);
		
		// Step 3: Create key with HSalsa20(k, 0)
	    HSalsa20 hSalsa20 = new HSalsa20();
	    byte[] finalKey = hSalsa20.getData(secKey.getEncoded(), new byte[16]);
	    
	    // Step 4: Perform XSalsa20-Poly1305
	    byte[] nonce = new byte[NONCEBYTES];
	    SecureRandom secureRandom = new SecureRandom();
	    secureRandom.nextBytes(nonce);
	    byte[] result = performXSalsa20Poly1305(finalKey, nonce, plaintext.getBytes(StandardCharsets.UTF_8));
	    System.out.println("nonce: " + (HexFormat.of().formatHex(nonce))); 
	    System.out.println("ciphertext - BC: " + HexFormat.of().formatHex(result));
	    
	    // -------------------------------------------------------------------------------
	    // Step 5: Comparison with Lazysodium

	    // convert ANS.1/DER keys to raw keys for Lazysodium
	    byte[] pubKeyRaw = Arrays.copyOfRange(pubKey.getEncoded(), pubKey.getEncoded().length - KEYBYTES, pubKey.getEncoded().length);
	    byte[] privKeyRaw = Arrays.copyOfRange(privKey.getEncoded(), privKey.getEncoded().length - KEYBYTES, privKey.getEncoded().length);
	    Key pubKeyLazy = Key.fromBytes(pubKeyRaw);
	    Key privKeyLazy = Key.fromBytes(privKeyRaw);
	    com.goterl.lazysodium.utils.KeyPair keyPairLazy = new com.goterl.lazysodium.utils.KeyPair(pubKeyLazy, privKeyLazy);
	    
		SodiumJava sodium = new SodiumJava();
	    LazySodiumJava lazySodium = new LazySodiumJava(sodium, StandardCharsets.UTF_8);
				
	    String macCiphertext = lazySodium.cryptoBoxEasy(plaintext, nonce , keyPairLazy);
	    System.out.println("ciphertext - LS: " + macCiphertext.toLowerCase()); // 16 byte tag | length
	}
	
	private static SecretKey generateSecretKey(PrivateKey privateKey, PublicKey publicKey) throws Exception {
	    KeyAgreement keyAgreement = KeyAgreement.getInstance("X25519", new BouncyCastleProvider());
	    keyAgreement.init(privateKey);
	    keyAgreement.doPhase(publicKey, true);
	    return keyAgreement.generateSecret("X25519");
	}
	
	private static byte[] performXSalsa20Poly1305(byte[] key, byte[] nonce, byte[] plaintext) {
	    XSalsa20Engine xSalsa20Engine = new XSalsa20Engine();
	    xSalsa20Engine.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
	    
	    // - generate mac key
	    byte[] macKey = new byte[KEYBYTES];
	    xSalsa20Engine.processBytes(macKey, 0, macKey.length, macKey, 0);

	    // - encrypt plaintext
	    byte[] ciphertext = new byte[plaintext.length];
	    xSalsa20Engine.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
	    
	    // - generate mac
	    Poly1305 poly1305 = new Poly1305();
	    poly1305.init(new KeyParameter(macKey));
	    byte[] mac = new byte[poly1305.getMacSize()];
	    poly1305.update(ciphertext, 0, plaintext.length); // ciphertext size = plaintext size
	    poly1305.doFinal(mac, 0);

	    // - concatenate, e.g. mac|ciphertext
	    return Arrays.concatenate(mac, ciphertext);
	}
}

class HSalsa20 extends Salsa20Engine
{
    public byte[] getData(byte[] keyBytes, byte[] ivBytes) 
    {
        super.setKey(keyBytes, ivBytes);
        
        Pack.littleEndianToInt(ivBytes, 8, engineState, 8, 2);

        int[] hsalsa20Out = new int[engineState.length];
        salsaCore(20, engineState, hsalsa20Out);

        engineState[1] = hsalsa20Out[0] - engineState[0];
        engineState[2] = hsalsa20Out[5] - engineState[5];
        engineState[3] = hsalsa20Out[10] - engineState[10];
        engineState[4] = hsalsa20Out[15] - engineState[15];

        engineState[11] = hsalsa20Out[6] - engineState[6];
        engineState[12] = hsalsa20Out[7] - engineState[7];
        engineState[13] = hsalsa20Out[8] - engineState[8];
        engineState[14] = hsalsa20Out[9] - engineState[9];

        byte[] result = null;
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
            outputStream.write( Pack.intToLittleEndian(engineState[1] ));
            outputStream.write( Pack.intToLittleEndian(engineState[2] ));
            outputStream.write( Pack.intToLittleEndian(engineState[3] ));
            outputStream.write( Pack.intToLittleEndian(engineState[4] ));
            outputStream.write( Pack.intToLittleEndian(engineState[11] ));
            outputStream.write( Pack.intToLittleEndian(engineState[12] ));
            outputStream.write( Pack.intToLittleEndian(engineState[13] ));
            outputStream.write( Pack.intToLittleEndian(engineState[14] ));
            result = outputStream.toByteArray();
        } catch(Exception ex) {
            ex.printStackTrace(); // your exception handling
        }
        
        return result;
   }
}
