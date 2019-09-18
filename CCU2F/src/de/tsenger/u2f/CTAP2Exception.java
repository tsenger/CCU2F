package de.tsenger.u2f;

import javacard.framework.CardRuntimeException;

public class CTAP2Exception extends CardRuntimeException {
	
	public static short CTAP1_ERR_SUCCESS = 0x00;
	public static short CTAP1_ERR_INVALID_COMMAND = 0x01;
	public static short CTAP1_ERR_INVALID_PARAMETER = 0x02;
	public static short CTAP1_ERR_INVALID_LENGTH = 0x03;
	public static short CTAP1_ERR_INVALID_SEQ = 0x04;
	public static short CTAP1_ERR_TIMEOUT = 0x05;
	public static short CTAP1_ERR_CHANNEL_BUSY = 0x06;
	public static short CTAP1_ERR_LOCK_REQUIRED = 0x0A;
	public static short CTAP1_ERR_INVALID_CHANNEL = 0x0B;
	public static short CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11;
	public static short CTAP2_ERR_INVALID_CBOR = 0x12;
	public static short CTAP2_ERR_MISSING_PARAMETER = 0x14;
	public static short CTAP2_ERR_LIMIT_EXCEEDED = 0x15;
	public static short CTAP2_ERR_UNSUPPORTED_EXTENSION = 0x16;
	public static short CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19;
	public static short CTAP2_ERR_PROCESSING = 0x21;
	public static short CTAP2_ERR_INVALID_CREDENTIAL = 0x22;
	public static short CTAP2_ERR_USER_ACTION_PENDING = 0x23;
	public static short CTAP2_ERR_OPERATION_PENDING = 0x24;
	public static short CTAP2_ERR_NO_OPERATIONS = 0x25;
	public static short CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26;
	public static short CTAP2_ERR_OPERATION_DENIED = 0x27;
	public static short CTAP2_ERR_KEY_STORE_FULL = 0x28;
	public static short CTAP2_ERR_NO_OPERATION_PENDING = 0x2A;
	public static short CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B;
	public static short CTAP2_ERR_INVALID_OPTION = 0x2C;
	public static short CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D;
	public static short CTAP2_ERR_NO_CREDENTIALS = 0x2E;
	public static short CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F;
	public static short CTAP2_ERR_NOT_ALLOWED = 0x30;
	public static short CTAP2_ERR_PIN_INVALID = 0x31;
	public static short CTAP2_ERR_PIN_BLOCKED = 0x32;
	public static short CTAP2_ERR_PIN_AUTH_INVALID = 0x33;
	public static short CTAP2_ERR_PIN_AUTH_BLOCKED = 0x34;
	public static short CTAP2_ERR_PIN_NOT_SET = 0x35;
	public static short CTAP2_ERR_PIN_REQUIRED = 0x36;
	public static short CTAP2_ERR_PIN_POLICY_VIOLATION = 0x37;
	public static short CTAP2_ERR_PIN_TOKEN_EXPIRED = 0x38;
	public static short CTAP2_ERR_REQUEST_TOO_LARGE = 0x39;
	public static short CTAP2_ERR_ACTION_TIMEOUT = 0x3A;
	public static short CTAP2_ERR_UP_REQUIRED = 0x3B;
	public static short CTAP1_ERR_OTHER = 0x7F;
	public static short CTAP2_ERR_SPEC_LAST = 0xDF;
	public static short CTAP2_ERR_EXTENSION_FIRST = 0xE0;
	public static short CTAP2_ERR_EXTENSION_LAST = 0xEF;
	public static short CTAP2_ERR_VENDOR_FIRST = 0xF0;
	public static short CTAP2_ERR_VENDOR_LAST = 0xFF;


	public CTAP2Exception(short reason) {
		super(reason);
	}

}
