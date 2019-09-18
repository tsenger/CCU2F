package de.tsenger.u2f;

import javacard.framework.Util;

public class SimpleDecoder {
	
	// maximum depth
	static final byte MAX_DEPTH = 4;
	
	// position of depth in nestingArray
	static final byte DEPTH_NOFF = 0;
	
	// max 4 level of nesting
	// remaingObjects[0] stores the current depth
	// remaingObjects[1] stores number of remaining objects in first level of depth
	// in first short half
	// remaingObjects[2] stores number of remaining objects in first level of depth
	// in second short half , etc.
	static byte[] nestingArray = new byte[MAX_DEPTH*2+1];	

	// counts the decoded objects of each level of depth
	static byte[] objectCounter = new byte[MAX_DEPTH*2];
	
	
	static byte getMajorType(byte[] input, short inOffset) {
		return (byte) ((input[inOffset]&0xE0)>>5);
	}
	
	static byte getAdditionInfo(byte[] input, short inOffset) {
		return (byte) (input[inOffset]&0x1F);
	}
	
	/**
	 * Returns either the number of elements (array and maps) or the value (byte string and text string) in a byte array
	 * @param input byte array 
	 * @param inOffset offset in input byte array
	 * @param output byte array to store the result
	 * @param outOffset offset in the output byte array
	 * @return size in output byte array
	 * @throws CTAP2Exception
	 */
	static short getValue(byte[] input, short inOffset, byte[] output, short outOffset) throws CTAP2Exception {
		
		short simpleValue = 0;
		short returnLength = 0;
	
		byte majorType = getMajorType(input, inOffset);
		if (majorType==6) throw new CTAP2Exception(CTAP2Exception.CTAP2_ERR_INVALID_CBOR);
		
		byte addInfo = getAdditionInfo(input, inOffset);
		
		if (addInfo < 24) {
			simpleValue = output[outOffset] = addInfo;
			returnLength = 1;
		}
		else if (addInfo == 24) {
			simpleValue = output[outOffset] = input[++inOffset];
			returnLength = 1;
		}
		else if (addInfo == 25) {
			output[outOffset] = input[++inOffset];
			output[(short)(outOffset+1)] = input[++inOffset];
			simpleValue =  Util.getShort(output, outOffset);
			returnLength = 2;
		} else if (addInfo >= 26)
			throw new CTAP2Exception(CTAP2Exception.CTAP2_ERR_INVALID_CBOR);
		
		if (majorType==2 || majorType==3) {
			for (short i=0;i<simpleValue;i++) {
				output[outOffset++]=input[++inOffset];
			}
			returnLength = simpleValue;
		}
		return returnLength;		
	}	
	

	/**
	 * Returns the number of bytes used to store the size.
	 * @param input byte array
	 * @param inOffset position in the input byte array that holds the major tag
	 * @return number of bytes used to store the size info
	 * @throws CTAP2Exception if size exceeds two bytes
	 */
	static short getSizeBytes(byte[] input, short inOffset) throws CTAP2Exception {

		byte majorType = getMajorType(input, inOffset);		
		if (majorType==6) throw new CTAP2Exception(CTAP2Exception.CTAP2_ERR_INVALID_CBOR);
		
		byte addInfo = getAdditionInfo(input, inOffset);

		if (addInfo < 24) {
			return (short) 0;
		}
		else if (addInfo == 24) {
			return (short) 1;
		}
		else if (addInfo == 25) {
			return (short) 2;
		} 
		else 
			throw new CTAP2Exception(CTAP2Exception.CTAP2_ERR_INVALID_CBOR);
	}
	
	/**
	 * Get the offset of the next major type
	 * @param input byte array
	 * @param inOffset offset of the actual major type
	 * @return offset in input byte array that points to next major type
	 * @throws CTAP2Exception
	 */
	static short getNext(byte[] input, short inOffset) throws CTAP2Exception {
				
		byte majorType = getMajorType(input, inOffset);
		short size = getSizeBytes(input, inOffset);
					
		if (majorType==2 || majorType == 3) {
			if (size==0) size = (short) (input[inOffset] & 0x1F);
			else if (size==1) size += (short) (input[(short)(inOffset+1)] & 0xFF);
			else if (size==2) size += Util.getShort(input, inOffset);
		}		
		return (short) (inOffset+size+1);
	}
	
	/**
	 * Search and returns offset of the next given major type  
	 * @param mType next major type for search for
	 * @param input input array to search in
	 * @param startOffset starting point to search
	 * @param endOffset offset where input data ends
	 * @return offset of found mType in input array or -1 for no result
	 * @throws CTAP2Exception 
	 */
	static short getNextMajorType(byte mType, byte[] input, short startOffset, short endOffset) throws CTAP2Exception {
		
		short pointer = startOffset ;
		
		while (pointer < endOffset) {
			
			byte majorType = getMajorType(input, pointer);
			if (majorType==mType) return pointer;			
			
			pointer = getNext(input, pointer);
		}
		
		return -1;
	}
	
//	/**
//	 * Returns the value of the given map index. inOffset must point to a valid majorType map
//	 * @param key must be of majorType 0
//	 * @param input input array 
//	 * @param inOffset offset in input array that contains a map majorType
//	 * @param output
//	 * @param outOffset
//	 * @return size of output data
//	 * @throws CTAP2Exception 
//	 */
//	static short getValueAtMapKey(byte key, byte[] input, short inOffset, byte[] output, short outOffset) throws CTAP2Exception  {
//			
//		short pointer = inOffset ;
//		
//		byte tag = input[pointer];			
//		byte majorType = (byte) ((tag&0xE0)>>5);
//		
//		if (majorType!=5) return -1;
//		
//		short ofs = -2;
//		byte simpleValue = -1;
//		do {
//			ofs = getNextMajorType((byte) 0, input, inOffset);
//			if (ofs==-1) return 0;
//			simpleValue = (byte) (tag & 0x1F);
//		} while (simpleValue!=key);
//		return getValue(input, ofs, output, outOffset);
//
//	}
	
	
	/**
	 * Get major type, size and value of the given tag index (objectNo) in the given nesting depth
	 * e.g. to get the the 3th object (major type, size and value) in the 2nd level of the given CBOR structure
	 * use objectNo=3 and depth=2    
	 * @param depth The nesting level to search in
	 * @param objectNo which index to get in the given depth (first object = 0, second object =1, etc.) 
	 * @param input input byte array
	 * @param startOffset offset in input array to start search
	 * @param endOffset offset in put array where the search should stop
	 * @param output output byte array contains major Tag (byte[0]), size as short value in byte[1] and byte[2], data if available in the following bytes
	 * @param outOffset offset in output array
	 * @return size in output or -1 if no object was found
	 * @throws CTAP2Exception
	 */
	static short getObjectAt(byte depth, byte objectNo, byte[] input, short startOffset, short endOffset, byte[] output, short outOffset) throws CTAP2Exception {
		
		Util.arrayFillNonAtomic(nestingArray,(short) 0, (short) nestingArray.length, (byte) 0);
		Util.arrayFillNonAtomic(objectCounter,(short) 0, (short) objectCounter.length, (byte) 0);
				
		for (short pointer=startOffset;pointer<endOffset;pointer++) {
		
			byte actualDepth = nestingArray[DEPTH_NOFF];
			
			// objectCounter[actualDeepth]++;
			short value = Util.getShort(objectCounter, (short) (actualDepth*2));
			Util.setShort(objectCounter, (short) (actualDepth*2), (short) (value+1));

			byte majorType = getMajorType(input, pointer);
			byte addInfo   = getAdditionInfo(input, pointer);
			
			// get size 
			short size=0;
			if (addInfo < 24) size = addInfo;
			else if (addInfo == 24) 
				size = input[++pointer];
			else if (addInfo == 25) {
				size = Util.getShort(input, ++pointer);
				pointer++;
			} else if (addInfo >= 26) 
				throw new CTAP2Exception(CTAP2Exception.CTAP2_ERR_INVALID_CBOR);
			
			boolean data = false;			
									
			switch (majorType) {
			case 0: 
			case 1:
			case 7:
				break;
				
			case 2:				
			case 3:
				for (short i=0;i<size;i++) {
					pointer++;
					output[(short)(outOffset+3+i)]=input[pointer];
				}
				data = true;
				break;
				
			case 4:
				//size = number of items in array
				nestingArray[DEPTH_NOFF]++;
				Util.setShort(nestingArray, (short) ((nestingArray[DEPTH_NOFF])*2-1),  (short) (size+1));
				break;
				
			case 5:
				// size = number of pairs
				nestingArray[DEPTH_NOFF]++;
				Util.setShort(nestingArray, (short) ((nestingArray[DEPTH_NOFF])*2-1),  (short) (size*2+1));
				break;
			
			case 6:
				throw new CTAP2Exception(CTAP2Exception.CTAP2_ERR_INVALID_CBOR);					
			}
			
			if (actualDepth==depth && Util.getShort(objectCounter, (short) (actualDepth*2))==objectNo) {
				output[outOffset]=majorType;
				Util.setShort(output, (short) (outOffset+1), size);
				if (data) return (short) (size+3);
				else return 3;
			}
			
			calcDepth(nestingArray);
									
		}
		return -1;
	}


	/**
	 * Recursive calculation of the current depth of nesting
	 * @param remainingObjects byte array that keeps the information of number of elements in each depth
	 */
	private static void calcDepth(byte[] remainingObjects) {
		
		// remainingObjects[0] contains the current depth
		if (remainingObjects[0]==0) return;
		short leveldepth = Util.getShort(remainingObjects, (short) (remainingObjects[0]*2-1));
		if (leveldepth != 0) {
			Util.setShort(remainingObjects, (short) (remainingObjects[0]*2-1), --leveldepth);

			if (leveldepth == 0) {
				remainingObjects[0]--;
				calcDepth(remainingObjects);	
			}
		}		
	}
	
	/** Return size of given major type
	 * @param input byte array	
	 * @param inOffset offset in byte array which contains a major type
	 * @return size of the given major type
	 * @throws Exception is size exceeds max length of data type short
	 */
	static short getSize(byte[] input, short inOffset) throws CTAP2Exception {
		short size = 0;
		byte addInfo = getAdditionInfo(input, inOffset);

		if (addInfo < 24) {
			size = addInfo;
		}
		else if (addInfo == 24) {
			size = input[(short)(inOffset+1)];
		}
		else if (addInfo == 25) {
			size = Util.getShort(input, (short) (inOffset+1));
		} else if (addInfo >= 26) 
			throw new CTAP2Exception(CTAP2Exception.CTAP2_ERR_INVALID_CBOR);
		
		return size;
	}
	
	/**
	 * Return the offset inside a map or array at the given index
	 * @param input input array
	 * @param inOffset offset in input array which contains a map or array major type
	 * @param index number of element which offset should be returned
	 * @return offset of indexed element
	 * @throws Exception if inOffset doesn't point to a map or array major type
	 */
	static short getElementAtIndex(byte[] input, short inOffset, byte index) throws CTAP2Exception {
		
		Util.arrayFillNonAtomic(nestingArray,(short) 0, (short) nestingArray.length, (byte) 0);
			
		byte mType = getMajorType(input, inOffset);
		if (mType!=4&&mType!=5) throw new CTAP2Exception(CTAP2Exception.CTAP2_ERR_INVALID_CBOR);
		
		short size = getSize(input, inOffset); 
		size = (short) (mType==4?size:size*2);
		if (!(index<size)) throw new CTAP2Exception(CTAP2Exception.CTAP2_ERR_INVALID_CBOR);
		
		short pointer = getNext(input, inOffset);
		
		for (short i=0;i<size;i++) {
			if(i==index) return pointer;
			pointer = getNextAtSameDepth(input, pointer);
		}		
		return -1;
	}
	
	/**
	 * Returns next major type in the same level of depth. Uses recursive calls of itself.
	 * @param input byte array
	 * @param inOffset offset of first element of the level to search in 
	 * @return offset of next major type in the same level of depth
	 * @throws Exception
	 */
	static short getNextAtSameDepth(byte[] input, short inOffset) throws CTAP2Exception {
					
		byte mType = getMajorType(input, inOffset);
		if (mType==4||mType==5) {
			short size = getSize(input, inOffset);
			size = (short) (mType==4?size:size*2);
			short remainingSize;
			
			nestingArray[DEPTH_NOFF]++;
			Util.setShort(nestingArray, (short) ((nestingArray[DEPTH_NOFF])*2-1),  size);
			
			inOffset = getNext(input, inOffset);
			do {				
				inOffset = getNextAtSameDepth(input, inOffset);
				remainingSize = (short) (Util.getShort(nestingArray,  (short) (nestingArray[DEPTH_NOFF]*2-1))-1);
				Util.setShort(nestingArray, (short) ((nestingArray[DEPTH_NOFF])*2-1), remainingSize );
			} while (remainingSize>0);
			nestingArray[DEPTH_NOFF]--;
			return inOffset;
		}
		return getNext(input, inOffset);
	}

}
