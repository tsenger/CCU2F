package de.tsenger.u2f;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.AESKey;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacard.security.Signature;

import com.nxp.id.jcopx.KeyAgreementX;
import com.nxp.id.jcopx.KeyBuilderX;
import com.nxp.id.jcopx.SignatureX;

public class PRNGTest extends Applet {

	private static Signature cmac;

	private static AESKey drngAESKey;

	private static byte[] tmp;

	private static KeyPair keyPair;
	private static AESKey drngKey1;
	private static AESKey drngKey2;
	private static AESKey macKey;
	private static Signature drng1;
	private static Signature drng2;
	private static Signature cmacSign;
	private static Signature cmacVerify;
	private static RandomData random;
	private static byte[] scratch;
	private static KeyAgreement ecMultiplyHelper;

	private PRNGTest() {
		random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

		drngAESKey = (AESKey) KeyBuilderX.buildKey(KeyBuilderX.TYPE_AES_STATIC,
				KeyBuilder.LENGTH_AES_128, false);

		tmp = JCSystem.makeTransientByteArray((short) 40,
				JCSystem.CLEAR_ON_DESELECT);

		random.generateData(tmp, (short) 0, (short) 16);
		drngAESKey.setKey(tmp, (short) 0);

		scratch = JCSystem.makeTransientByteArray((short) 32,
				JCSystem.CLEAR_ON_DESELECT);

		keyPair = new KeyPair((ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256,false), 
				(ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false));
		Secp256r1.setCommonCurveParameters((ECKey) keyPair.getPrivate());
		Secp256r1.setCommonCurveParameters((ECKey) keyPair.getPublic());

		

		// Initialize the unique key for DRNG function (AES CMAC)
		drngKey1 = (AESKey) KeyBuilderX.buildKey(KeyBuilderX.TYPE_AES_STATIC,
				KeyBuilder.LENGTH_AES_128, false);
		drngKey2 = (AESKey) KeyBuilderX.buildKey(KeyBuilderX.TYPE_AES_STATIC,
				KeyBuilder.LENGTH_AES_128, false);
		random.generateData(scratch, (short) 0, (short) 32);
		drngKey1.setKey(scratch, (short) 0);
		drngKey2.setKey(scratch, (short) 16);

		drng1 = SignatureX.getInstance(SignatureX.ALG_AES_CMAC16, false);
		drng1.init(drngKey1, Signature.MODE_SIGN);
		drng2 = SignatureX.getInstance(SignatureX.ALG_AES_CMAC16, false);
		drng2.init(drngKey2, Signature.MODE_SIGN);

		// Initialize the unique key for MAC function (AES CMAC)
		macKey = (AESKey) KeyBuilderX.buildKey(KeyBuilderX.TYPE_AES_STATIC,
				KeyBuilder.LENGTH_AES_128, false);
		random.generateData(scratch, (short) 0, (short) 16);
		macKey.setKey(scratch, (short) 0);

		cmacSign = SignatureX.getInstance(SignatureX.ALG_AES_CMAC16, false);
		cmacSign.init(macKey, Signature.MODE_SIGN);

		cmacVerify = SignatureX.getInstance(SignatureX.ALG_AES_CMAC16, false);
		cmacVerify.init(macKey, Signature.MODE_VERIFY);

		// Initialize ecMultiplier
		ecMultiplyHelper = KeyAgreementX.getInstance(KeyAgreementX.ALG_EC_SVDP_DH_PLAIN_XY, false);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new PRNGTest().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) 0x00:
			handleGetPRand(apdu);
			break;
		case (byte) 0x01:
			handleGetCmac(apdu);
			break;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void handleGetCmac(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short dataLen = apdu.setIncomingAndReceive();
		short dataOffset = apdu.getOffsetCdata();

		if (dataLen != 32) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		cmac = SignatureX.getInstance(SignatureX.ALG_AES_CMAC16, false);
		cmac.init(drngAESKey, Signature.MODE_SIGN);
		short sigLen = cmac
				.sign(buffer, dataOffset, dataLen, buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, sigLen);

	}

	private void handleGetPRand(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short dataLen = apdu.setIncomingAndReceive();
		short dataOffset = apdu.getOffsetCdata();
		random.setSeed(buffer, dataOffset, dataLen);
		random.generateData(buffer, (short) 0, (short) 16);
		apdu.setOutgoingAndSend((short) 0, (short) 16);
	}

}
