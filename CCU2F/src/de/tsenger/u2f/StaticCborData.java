package de.tsenger.u2f;

public class StaticCborData {
	
	/* 
	 * A2                                      # map(2)
   	 *    01                                   # unsigned(1)
     *    82                                   # array(2)
     *       68                                # text(8)
     *          4649444F5F325F30               # "FIDO_2_0"
     *       66                                # text(6)
     *          5532465F5632                   # "U2F_V2"
     *    03                                   # unsigned(3)
     *    C2                                   # tag(2)
     *       50                                # bytes(16)
     *          0ABAD13AA8E0651FD985090165406A01 # "\n\xBA\xD1:\xA8\xE0e\x1F\xD9\x85\t\x01e@j\x01"
	 */
	public static final byte[] AUTHENTICATOR_INFO = {
			(byte) 0xA2, (byte) 0x01, (byte) 0x82, (byte) 0x68, (byte) 0x46, (byte) 0x49, (byte) 0x44, (byte) 0x4F,
			(byte) 0x5F, (byte) 0x32, (byte) 0x5F, (byte) 0x30, (byte) 0x66, (byte) 0x55, (byte) 0x32, (byte) 0x46, 
			(byte) 0x5F, (byte) 0x56, (byte) 0x32, (byte) 0x03, (byte) 0xC2, (byte) 0x50, (byte) 0x0A, (byte) 0xBA, 
			(byte) 0xD1, (byte) 0x3A, (byte) 0xA8, (byte) 0xE0, (byte) 0x65, (byte) 0x1F, (byte) 0xD9, (byte) 0x85, 
			(byte) 0x09, (byte) 0x01, (byte) 0x65, (byte) 0x40, (byte) 0x6A, (byte) 0x01
	};
}
