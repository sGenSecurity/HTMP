#
##SEED####
from struct import pack, unpack
import seed_tab

check = lambda x: x & 0x00000000ffffffff

global KC 
KC= [0x9e3779b9
	,0x3c6ef373
	,0x78dde6e6
	,0xf1bbcdcc
	,0xe3779b99
	,0xc6ef3733
	,0x8dde6e67
	,0x1bbcdccf
	,0x3779b99e
	,0x6ef3733c
	,0xdde6e678
	,0xbbcdccf1
	,0x779b99e3
	,0xef3733c6
	,0xde6e678d
	,0xbcdccf1b
    ,0x79b99e37
    ,0xf3733c6e
    ,0xe6e678dd
    ,0xcdccf1bb
    ,0x9b99e377
    ,0x3733c6ef
    ,0x6e678dde
    ,0xdccf1bbc]

def byte_xor(data):
	data_1 = data & 0x000000ff
	data_2 = (data & 0x0000ff00) >> 8
	data_3 = (data & 0x00ff0000) >> 16
	data_4 = (data & 0xff000000) >> 24

	return seed_tab.SS0[data_1] ^ seed_tab.SS1[data_2] ^ seed_tab.SS2[data_3] ^ seed_tab.SS3[data_4]

def RoundKeyU0(A, B, C, D, KC):
	T0 = check(A + C - KC)
	T1 = check(B + KC - D)
		
	if T0 < 0:
		T0 = 0x100000000-T0
	if T1 < 0:
		T1 = 0x100000000-T1
	
	K = [byte_xor(T0), byte_xor(T1)]

	return K

def RoundKeyU1(A, B, C, D, KC):
	T0 = check(A + C - KC)
	T1 = check(B + KC - D)
	
	if T0 < 0:
		T0 = (0x100000000-T0) & 0xffffffff
	if T1 < 0:
		T1 = (0x100000000-T1) & 0xffffffff

	K = [byte_xor(T0), byte_xor(T1)]
	
	return K


def Seed128_RoundKey(UserKey):
	if len(UserKey) != 16 :
		print "Length must be 16"
		return

	A = unpack("<L",UserKey[0:4])[0]
	B = unpack("<L",UserKey[4:8])[0]
	C = unpack("<L",UserKey[8:12])[0]
	D = unpack("<L",UserKey[12:16])[0]

	K = ""
	for i in range(0,7):
		temp = []
		temp = RoundKeyU0(A, B, C, D, KC[2*i])
		K += pack(">L", temp[0])
		K += pack(">L", temp[1])
		temp = A
		A = check((A >> 8) ^ (B << 24))
		B = check((B >> 8) ^ (temp << 24))

		temp = RoundKeyU1(A, B, C, D, KC[2*i+1])
		K += pack(">L", temp[0])
		K += pack(">L", temp[1])
		
		temp = C
		C = check((C << 8) ^ (D >> 24))
		D = check((D << 8) ^ (temp >> 24))

	temp = RoundKeyU0(A, B, C, D, KC[14])
	K += pack(">L", temp[0])
	K += pack(">L", temp[1])

	temp = A

	A = check((A >> 8) ^ (B << 24))
	B = check((B >> 8) ^ (temp << 24))

	T0 = check(A + C - KC[15])
	T1 = check(B - D + KC[15])
	
	K += pack(">L",byte_xor(T0))
	K += pack(">L",byte_xor(T1))

	return K


def Seed_Round(L0, L1, R0, R1, K):
	T0 = R0 ^ K[0]
	T1 = R1 ^ K[1]
	T1 ^= T0
	
	T1 = byte_xor(T1)
	T0 = check(T0 + T1)
	
	T0 = byte_xor(T0)
	T1 = check(T1 + T0)
	
	T1 = byte_xor(T1)
	T0 = check(T0 + T1)

	return [L0 ^ T0, L1 ^ T1]

def Seed128_Encrypt(UserData, RoundKey):

	while(len(UserData)!=16):
		UserData += "\x00"
	L0 = unpack("<L",UserData[0:4])[0]
	L1 = unpack("<L",UserData[4:8])[0]
	R0 = unpack("<L",UserData[8:12])[0]
	R1 = unpack("<L",UserData[12:16])[0]

	print hex(L0)+"========"

	K = []
	for i in range(0,32):
		K.append(unpack(">L", RoundKey[i*4:(i+1)*4])[0])


	for i in range(0,8):
		temp = Seed_Round(L0, L1, R0, R1, [K[4*i+0],K[4*i+1]])
		L0 = temp[0]
		L1 = temp[1]

		temp = Seed_Round(R0, R1, L0, L1, [K[4*i+2], K[4*i+3]])
		R0 = temp[0]
		R1 = temp[1]

	ret = ""
	ret += pack("<L", R0)
	ret += pack("<L", R1)
	ret += pack("<L", L0)
	ret += pack("<L", L1)

	return ret

def Seed128_Decrypt(UserData, RoundKey):

	L0 = unpack("<L",UserData[0:4])[0]
	L1 = unpack("<L",UserData[4:8])[0]
	R0 = unpack("<L",UserData[8:12])[0]
	R1 = unpack("<L",UserData[12:16])[0]

	K = []
	for i in range(0,32):
		K.append(unpack(">L", RoundKey[i*4:(i+1)*4])[0])

	for i in range(0,8):
		temp = Seed_Round(L0, L1, R0, R1, [K[4*(8-i)-2], K[4*(8-i)-1]])
		L0 = temp[0]
		L1 = temp[1]

		temp = Seed_Round(R0, R1, L0, L1, [K[4*(8-i)-4], K[4*(8-i)-3]])

		R0 = temp[0]
		R1 = temp[1]

	ret = ""
	ret += pack("<L", R0)
	ret += pack("<L", R1)
	ret += pack("<L", L0)
	ret += pack("<L", L1)

	return ret


def Seed256_Encrypt(UserData, RoundKey):

	while(len(UserData)!=16):
		UserData += "\x00"

	L0 = unpack(">L",UserData[0:4])[0]
	L1 = unpack(">L",UserData[4:8])[0]
	R0 = unpack(">L",UserData[8:12])[0]
	R1 = unpack(">L",UserData[12:16])[0]

	K = []
	for i in range(0,48):
		K.append(unpack(">L", RoundKey[i*4:(i+1)*4])[0])

	print "0x"+hex(L0)

	for i in range(0,12):
		temp = Seed_Round(L0, L1, R0, R1, [K[4*i+0],K[4*i+1]])
		L0 = temp[0]
		L1 = temp[1]
		print "+++++\n%08X\n%08X"%(L0,L1)
		temp = Seed_Round(R0, R1, L0, L1, [K[4*i+2], K[4*i+3]])
		R0 = temp[0]
		R1 = temp[1]

	ret = ""
	ret += pack(">L", R0)
	ret += pack(">L", R1)
	ret += pack(">L", L0)
	ret += pack(">L", L1)
		
	return ret

def Seed256_Decrypt(UserData, RoundKey):

	L0 = unpack(">L",UserData[0:4])[0]
	L1 = unpack(">L",UserData[4:8])[0]
	R0 = unpack(">L",UserData[8:12])[0]
	R1 = unpack(">L",UserData[12:16])[0]
		
	K = []
	for i in range(0,48):
		K.append(unpack(">L", RoundKey[i*4:(i+1)*4])[0])

	for i in range(0,12):
		temp = Seed_Round(L0, L1, R0, R1, [K[4*(12-i)-2], K[4*(12-i)-1]])
		L0 = temp[0]
		L1 = temp[1]
		
		temp = Seed_Round(R0, R1, L0, L1, [K[4*(12-i)-4], K[4*(12-i)-3]])
		
		R0 = temp[0]
		R1 = temp[1]
		
	ret = ""
	ret += pack(">L", R0)
	ret += pack(">L", R1)
	ret += pack(">L", L0)
	ret += pack(">L", L1)

	return ret

def Seed256_RoundKey(UserKey):
	if len(UserKey) != 32 :
		print "Length must be 32"
		return

	A = unpack("<L",UserKey[0:4])[0]
	B = unpack("<L",UserKey[4:8])[0]
	C = unpack("<L",UserKey[8:12])[0]
	D = unpack("<L",UserKey[12:16])[0]
	E = unpack("<L",UserKey[16:20])[0]
	F = unpack("<L",UserKey[20:24])[0]
	G = unpack("<L",UserKey[24:28])[0]
	H = unpack("<L",UserKey[28:32])[0]
	

	K = ""
	temp = check((A+C) ^ E) - F
	if temp < 0 :
		temp = 0x100000000 - temp
	temp ^= KC[0]
	print hex(byte_xor(((check(A+C) ^ E) - F)^KC[0]))
	K += pack(">L",byte_xor(temp))
	
	temp = check(B - D)
	if temp < 0:
		temp = 0x100000000 - temp
	temp = check((temp ^ G) + H) ^ KC[0]
	K += pack(">L",byte_xor(temp))
	
	rot = 0
	for i in range(0,11):
		if rot == 0:
			rot = 9
		elif rot == 9:
			rot = 11
		elif rot == 11:
			rot = 12
		elif rot == 12:
			rot = 9
		
		temp = []
		
		T0 = D            
		D = check((D>>rot) ^ (C<<(32-rot))) 
		C = check((C>>rot) ^ (B<<(32-rot)))   	
		B = check((B>>rot) ^ (A<<(32-rot)))
		temp = encRoundKeyU0(A, B, C, D, E, F, G, H, KC[2*i+1], rot)
		K += pack(">L", temp[0])
		K += pack(">L", temp[1])

		T0 = E
		E = check((E<<rot) ^ (F>>(32-rot)))
		F = check((F<<rot) ^ (G>>(32-rot)))
		G = check((G<<rot) ^ (H>>(32-rot)))
		H = check((H<<rot) ^ (T0>>(32-rot)))
		temp = encRoundKeyU1(A, B, C, D, E, F, G, H, KC[2*i+2], rot)
		K += pack(">L", temp[0])
		K += pack(">L", temp[1])

	T0 = D            
	D = check((D>>rot) ^ (C<<(32-rot)))                
	C = check((C>>rot) ^ (B<<(32-rot)))   	
	B = check((B>>rot) ^ (A<<(32-rot)))	
	temp = encRoundKeyU0(A, B, C, D, E, F, G, H, KC[23],rot)
	K += pack(">L", temp[0])
	K += pack(">L", temp[1])



	return K

def encRoundKeyU0(A, B, C, D, E, F, G, H, KC, rot):
	T0 = check(((A + C) ^ E ) - F) ^ KC
	T1 = check(((B - D) ^ G ) + H) ^ KC
		
	if T0 < 0:
		T0 = 0x100000000-T0
	if T1 < 0:
		T1 = 0x100000000-T1
	
	K = [byte_xor(T0), byte_xor(T1)]

	return K

def encRoundKeyU1(A, B, C, D, E, F, G, H, KC, rot):
	T0 = check((((A + C) ^ E ) - F) ^ KC)
	T1 = check((((B - D) ^ G ) + H) ^ KC)
	
	if T0 < 0:
		T0 = (0x100000000-T0) & 0xffffffff
	if T1 < 0:
		T1 = (0x100000000-T1) & 0xffffffff

	K = [byte_xor(T0), byte_xor(T1)]
	
	return K


