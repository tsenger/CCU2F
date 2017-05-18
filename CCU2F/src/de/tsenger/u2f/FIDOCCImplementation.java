/*
*******************************************************************************
*   FIDO CCU2F Authenticator
*   (c) 2017 tsenger
*   based on FIDO U2F Authenticator by Ledger 
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*******************************************************************************
*/

package de.tsenger.u2f;

import javacard.framework.JCSystem;
import javacard.framework.Util;
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

public class FIDOCCImplementation implements FIDOAPI {

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


    public FIDOCCImplementation() {
    	
    	random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    	
        scratch = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        
        keyPair = new KeyPair(
            (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
            (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false));
        Secp256r1.setCommonCurveParameters((ECKey)keyPair.getPrivate());
        Secp256r1.setCommonCurveParameters((ECKey)keyPair.getPublic());
                
        // Initialize the unique key for DRNG function (AES CMAC)
        drngKey1 = (AESKey)KeyBuilderX.buildKey(KeyBuilderX.TYPE_AES_STATIC, KeyBuilder.LENGTH_AES_128, false);
        drngKey2 = (AESKey)KeyBuilderX.buildKey(KeyBuilderX.TYPE_AES_STATIC, KeyBuilder.LENGTH_AES_128, false);
        random.generateData(scratch, (short)0, (short)32);
        drngKey1.setKey(scratch, (short)0);
        drngKey2.setKey(scratch, (short)16);
        
        drng1 = SignatureX.getInstance(SignatureX.ALG_AES_CMAC16, false);
        drng1.init(drngKey1, Signature.MODE_SIGN);
        drng2 = SignatureX.getInstance(SignatureX.ALG_AES_CMAC16, false);
        drng2.init(drngKey2, Signature.MODE_SIGN);
        
        // Initialize the unique key for MAC function (AES CMAC)
        macKey = (AESKey)KeyBuilderX.buildKey(KeyBuilderX.TYPE_AES_STATIC, KeyBuilder.LENGTH_AES_128, false);
        random.generateData(scratch, (short)0, (short)16);
        macKey.setKey(scratch, (short)0);
        
        cmacSign = SignatureX.getInstance(SignatureX.ALG_AES_CMAC16, false);
        cmacSign.init(macKey, Signature.MODE_SIGN);
        
        cmacVerify = SignatureX.getInstance(SignatureX.ALG_AES_CMAC16, false);
        cmacVerify.init(macKey, Signature.MODE_VERIFY);
        
        // Initialize ecMultiplier 
        ecMultiplyHelper = KeyAgreementX.getInstance(KeyAgreementX.ALG_EC_SVDP_DH_PLAIN_XY, false);
    }
    
    /**
	 * Generate Public Key from given Private Key. Uses the Key Agreement API of Java card.
	 * @param pointOutputBuffer Output buffer
	 * @param offset Offset of the output buffer
	 * @return Length of the final EC point
	 */
	private short generatePublicKeyPoint(byte[] pointOutputBuffer, short offset){
		ecMultiplyHelper.init(keyPair.getPrivate());
		return ecMultiplyHelper.generateSecret(Secp256r1.SECP256R1_G, (short) 0, (short) 65, pointOutputBuffer, offset);
}

    public short generateKeyAndWrap(byte[] applicationParameter, short applicationParameterOffset, ECPrivateKey generatedPrivateKey, byte[] publicKey, short publicKeyOffset, byte[] keyHandle, short keyHandleOffset) {
        // Generate 48 byte nonce
    	random.generateData(keyHandle, keyHandleOffset, (short) 48);
    	
    	//Generate PrivKey 
    	drng1.update(applicationParameter, applicationParameterOffset, (short) 32);
    	drng1.sign(keyHandle, keyHandleOffset, (short) 48, scratch, (short) 0);
    	drng2.update(applicationParameter, applicationParameterOffset, (short) 32);
    	drng2.sign(keyHandle, keyHandleOffset, (short) 48, scratch, (short) 16);
    	
    	//TODO Remove! Only for TEST !!!
//    	random.generateData(scratch, (short)0, (short) 32);
    	
    	// Set private Key S, before generating Public Key
    	((ECPrivateKey)keyPair.getPrivate()).setS(scratch, (short) 0, (short) 32);
    	
    	generatePublicKeyPoint(publicKey, publicKeyOffset);
    	
    	// erase Private Key
    	Util.arrayFillNonAtomic(scratch, (short)0, (short)32, (byte)0x00);
    	((ECPrivateKey)keyPair.getPrivate()).setS(scratch, (short) 0, (short) 32);
    	
    	cmacSign.update(applicationParameter, applicationParameterOffset, (short) 32);
    	cmacSign.sign(keyHandle, keyHandleOffset, (short) 48, keyHandle, (short) (keyHandleOffset + 48));
        
        return (short)64;
    }

    public boolean unwrap(byte[] keyHandle, short keyHandleOffset, short keyHandleLength, byte[] applicationParameter, short applicationParameterOffset, ECPrivateKey unwrappedPrivateKey) {
        // Verify
    	cmacVerify.update(applicationParameter, applicationParameterOffset, (short) 32);
    	if (!cmacVerify.verify(keyHandle, keyHandleOffset, (short) 48, keyHandle, (short) (keyHandleOffset + 48), (short) 16)) {
    		return false;
    	}
    	
    	//only get key if signing is required
        if (unwrappedPrivateKey != null) {
        	//Regenerate PrivKey 
        	drng1.update(applicationParameter, applicationParameterOffset, (short) 32);
        	drng1.sign(keyHandle, keyHandleOffset, (short) 48, scratch, (short) 0);
        	drng2.update(applicationParameter, applicationParameterOffset, (short) 32);
        	drng2.sign(keyHandle, keyHandleOffset, (short) 48, scratch, (short) 16);
        	
            unwrappedPrivateKey.setS(scratch, (short)0, (short)32);
        }
        Util.arrayFillNonAtomic(scratch, (short)0, (short)32, (byte)0x00);
        return true;
    }

}
