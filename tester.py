from bitcoin.core import lx, b2lx, b2x, CTransaction, CMutableTransaction

from signatures import *

# tx = "0100000001186f9f998a5aa6f048e51dd8419a14d8a0f1a8a2836dd73 4d2804fe65fa35779000000008b483045022100884d142d86652a3f47 ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039 ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e3813 01410484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade84 16ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc1 7b4a10fa336a8d752adfffffffff0260e31600000000001976a914ab68 025513c3dbd2f7b92a94e0581f5d50f654e788acd0ef800000000000 1976a9147f9b1a7fb68d60c536c2fd8aeaa53a8f3cc025a888ac 00000000"
#
# print(len(tx))
#
# #output = '60e316-0000000000-19-76a914ab68025513c3d-bd2f7b92a94e0581f5d50f654e788ac-d0ef80-0000000000-19-76a9147f9b1a7fb68d6-0c536c2fd8aeaa53a8f3cc025a888ac'
# #print(len(output))
#
# #print(hex(25))
#
# #string ="OP_DUP OP_HASH160 ab68025513c3dbd2f7b92a94e0581f5d50f654e7 OP_EQUALVERIFY OP_CHECKSIG"
#
# #hexnum =int(hex(int(0.015 * 10**8)),16)
# #hexnum.to_bytes(4, 'little')
# #print(hexnum.to_bytes(4, 'little'))
# #string2 = b'OP_DUP OP_HASH160 ab68025513c3dbd2f7b92a94e0581f5d50f654e7 OP_EQUALVERIFY OP_CHECKSIG'
# #print(hash(bytes(string2)).hexdigest())
# #a ='01000000 01 be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396 00000000 19 76 a9 14 dd6cce9f255a8cc17bda8ba0373df8e861cb866e 88 ac ffffffff 01 23ce010000000000 19 76 a9 14 a2fd2e039a86dbcf0e1a664729e09e8007f89510 88 ac 00000000 01000000'
# a='''0100000001be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396000000001976a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88acffffffff0123ce0100000000001976a9142bc89c2702e0e618db7d59eb5ce2f0f147b4075488ac0000000001000000'''
# hash1=hash(bytes(a.encode('utf-8'))).hexdigest()
# print(hash1)
#
# print(hash(bytes(hash1.encode('utf-8'))).hexdigest())
#
# print(hash(bytes(hex(8499980080),'utf-8')).digest())
# print(len('11b6e0460bb810b05744f8d38262f95fbab02b168b070598a6f31fad438fced4'))
#
# print(len('186f9f998a5aa6f048e51dd8419a14d8a0f1a8a2836dd734d2804fe65fa35779'))
# print(int('17',base=16))
# '''01000000
# 01
# 186f9f998a5aa6f048e51dd8419a14d8a0f1a8a2836dd734d2804fe65fa35779
# 00000000
# 8b483045022100884d142d86652a3f47 ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039 ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e3813 01410484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade84 16ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc1 7b4a10fa336a8d752adfffffffff0260e31600000000001976a914ab6 8025513c3dbd2f7b92a94e0581f5d50f654e788acd0ef800000000000 1976a9147f9b1a7fb68d60c536c2fd8aeaa53a8f3cc025a888ac 00000000
# '''

txOrg = "01000000015cd81501e2a63c942fcb24de76d4532406156c8cb10b5dcb123a1cb5be13d884000000008a4730440220404b9f69f969d776f3610192bec0d18a8e47256f39148251d91cfa355c0f9f0302202d060128513a45aae40f75e807acddf0e0d90a097af72de88f1956ce7338216001410437078f8c4a54b67cd1724a3535cb1918bca186c7a143459c9aac35113d4a958b0d4eea6b320fa82c17147b72e0fe11c08b0054897ffb7bdb194f259b0db9e129ffffffff02a0860100000000001976a914478075922af41fb441aa0ab67e91aef27ef1e68688ac50c30000000000001976a914ec06b2bf18c89706855f761d215f21f3315b399488ac00000000"


class Raw_signature_tx:
    def __init__(self,tx):
        self.txOrg = tx
        self.bytesused = {
            'version': ['Version',4],
            'flag': ['Flag',2],
            'inputcount': ['Input Count',1],
            'inputprevoutputhash': ['Input 1 Outpoint TXID',32],
            'inputprevoutputindex': ['Outpoint index number',4],
            'scriptlen': ['Bytes in SignScript',1, 'Push bytes as data',1],
            'inputsecuence': ['Input secuence',4],
            'outputCount': ['Output Count', 1],
            'witnesscount': ['Witness Count', 1],
            'locktime': ['Locktime', 4],
        }
    def space_separator(self,len_data):
        return "." * (50 - len_data) if len_data < 50 else "." * 5
    def printer(self, parameter):

        if parameter == 'rest':
            if len(self.txOrg) == 0:
              print("!!Nada al final!!")
            else:
                print(self.txOrg)

        elif parameter == 'scriptlen':
            val = self.txOrg[0:self.bytesused[parameter][1] * 2]
            valint =int(val ,16)
            len_data = len(val)
            first_string = "|"
            space_after_data = self.space_separator(len_data)

            print("{}{}{}:{} . Int Value: {} . Bytes: {}".format(first_string,val,space_after_data,self.bytesused[parameter][0],valint, self.bytesused[parameter][1]))
            self.txOrg = self.txOrg[self.bytesused[parameter][1] * 2:]

            val_signature = self.txOrg[0:self.bytesused[parameter][1] * 2]
            val_signature_int = int(val_signature, 16)
            len_data = len(val)
            #self.txOrg = self.txOrg[self.bytesused[parameter][1] * 2:]

            ## Le resto 1 byte al signscript len del len del signature
            valint = valint -1
            first_string = "|"
            space_after_data = self.space_separator(len_data)
            print("{}{}{}:{} . Int Value: {} . Bytes: {}".format(first_string, val_signature, space_after_data,
                                                                 self.bytesused[parameter][2], val_signature_int,
                                                                 self.bytesused[parameter][3]))
            self.txOrg = self.txOrg[self.bytesused[parameter][1] * 2:]

            signature = self.txOrg[0:(val_signature_int -1) * 2]

            len_data = len(signature)
            first_string = "|"
            space_after_data = self.space_separator(len_data)

            print("{}{}{}:Sign script . Bytes: {}".format(first_string,signature,space_after_data, self.bytesused[parameter][1]))
            self.txOrg = self.txOrg[len_data:]
            print("|{}{} . Bytes: {}".format(self.txOrg[0:2], ' \\Added after signature', 1))
            print("|{}{} . Bytes: {}".format(self.txOrg[2:4], ' \\Length of public key', 1))
            print("{}{}{} . Bytes: {}".format(first_string,self.txOrg[4:int(self.txOrg[2:4], 16)*2], space_after_data,(valint - val_signature_int) * 2))
            self.txOrg = self.txOrg[int(self.txOrg[2:4], 16)*2 + 4:]
        elif parameter =='outputs':
            counts = int(self.txOrg[0:self.bytesused['outputCount'][1] * 2])
            len_data = 1
            first_string = "|"
            space_after_data = self.space_separator(len_data)

            print("{}{}{}:{}. Bytes: {}".format(first_string,counts,space_after_data,'Cantidad de outputs', 1))
            self.txOrg = self.txOrg[1 * 2:]
            i = 0
            while i < counts:
                i+=1
                value = self.txOrg[0:8 * 2]
                valueInt = int(b2x(lx(value)),16)
                len_data = len(value)
                first_string = "|"
                space_after_data = self.space_separator(len_data)

                print("{}{}{}:Output {} . value in Satoshies: {} . Bytes: {}".format(first_string,value,space_after_data, i , valueInt, 8))
                self.txOrg = self.txOrg[8 * 2:]

                lenoutputscript = self.txOrg[0:1 * 2]
                lenoutputscriptInt = int(self.txOrg[0:1 * 2],base=16)
                len_data = len(lenoutputscript)
                first_string = "|"
                space_after_data = self.space_separator(len_data)
                print("{}{}{}:Output {} public key script length . Integer value {} . Bytes: {}".format(first_string,lenoutputscript,space_after_data,i, lenoutputscriptInt, 1))
                self.txOrg = self.txOrg[1 * 2:]
                data = self.txOrg[0:lenoutputscriptInt * 2]
                len_data = len(data)
                first_string = "|"
                space_after_data = self.space_separator(len_data)
                print("{}{}{}:Output {} . Bytes: {}".format(first_string, data, space_after_data, i , lenoutputscriptInt))
                self.txOrg = self.txOrg[lenoutputscriptInt * 2:]

        elif parameter =='witness':
            counts = int(self.txOrg[0:self.bytesused['witnesscount'][1] * 2])
            data = self.bytesused['witnesscount'][0]
            len_data = len(data)
            first_string = "|"
            space_after_data = self.space_separator(len_data)
            print("{}{}{}:{} . Bytes: {}".format(first_string,counts,space_after_data,data, 1))
            self.txOrg = self.txOrg[1 * 2:]
            i = 0
            while i < counts:
                i+=1
                lenwitnessdata = int(self.txOrg[0:1 * 2],base=16)
                print("{} Witness {} length: {} . Bytes: {}".format(first_string, i, lenwitnessdata, 1))
                self.txOrg = self.txOrg[1 * 2:]
                print("Output {} value: {} . Bytes: {}".format(i, self.txOrg[0:lenwitnessdata * 2], lenwitnessdata))
                self.txOrg = self.txOrg[lenwitnessdata * 2:]
        else:
            data = self.txOrg[0:self.bytesused[parameter][1] * 2]
            len_data = len(data)
            first_string = "|"
            space_after_data = "."*(50 -len_data) if len_data < 50 else 5
            print("{}{}{}:{} . Bytes: {}".format(first_string,data,space_after_data, self.bytesused[parameter][0], self.bytesused[parameter][1]))
            self.txOrg = self.txOrg[self.bytesused[parameter][1] * 2:]

    def printer_all(self, width_flag=True):
        print("######## BEGIN ########")
        self.printer('version')
        if width_flag:
            self.printer('flag')
        self.printer('inputcount')
        self.printer('inputprevoutputhash')
        self.printer('inputprevoutputindex')
        self.printer('scriptlen')
        self.printer('inputsecuence')
        self.printer('outputs')
        self.printer('witness')
        self.printer('locktime')
        self.printer('rest')
        print("######## END ########")

#object = Raw_signature_tx(txOrg)
#object.printer_all()

#object1 = Raw_signature_tx(txOrg1)
#object1.printer_all()

txOrgCcharpexample = '01000000015cd81501e2a63c942fcb24de76d4532406156c8cb10b5dcb123a1cb5be13d884000000008a47304402203f3fa0f312724f41a0fa8c09f371ddf193916dc9c4fc5137711d49f18fafe0a002204f5f2b3925a62fe43d335ed0a17255dc199dedd16f628c1dc4f48f76e16ebe9901410437078f8c4a54b67cd1724a3535cb1918bca186c7a143459c9aac35113d4a958b0d4eea6b320fa82c17147b72e0fe11c08b0054897ffb7bdb194f259b0db9e129ffffffff02a0860100000000001976a914478075922af41fb441aa0ab67e91aef27ef1e68688ac50c30000000000001976a914ec06b2bf18c89706855f761d215f21f3315b399488ac00000000'

object2 = Raw_signature_tx(txOrgCcharpexample)
object2.printer_all(False)
