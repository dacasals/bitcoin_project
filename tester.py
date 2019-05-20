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

txOrg = "0200000000010111b6e0460bb810b05744f8d38262f95fbab02b168b070598a6f31fad438fced4000000001716001427c106013c0042da165c082b3870c31fb3ab4683feffffff0200ca9a3b0000000017a914d8b6fcc85a383261df05423ddf068a8987bf0287873067a3fa0100000017a914d5df0b9ca6c0e1ba60a9ff29359d2600d9c6659d870247304402203b85cb05b43cc68df72e2e54c6cb508aa324a5de0c53f1bbfe997cbd7509774d022041e1b1823bdaddcd6581d7cde6e6a4c4dbef483e42e59e04dbacbaf537c3e3e8012103fbbdb3b3fc3abbbd983b20a557445fb041d6f21cc5977d2121971cb1ce5298978c000000"

txOrg1 = "0100000001186f9f998a5aa6f048e51dd8419a14d8a0f1a8a2836dd734d2804fe65fa35779000000008b483045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e381301410484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adfffffffff0260e31600000000001976a914ab68025513c3dbd2f7b92a94e0581f5d50f654e788acd0ef8000000000001976a9147f9b1a7fb68d60c536c2fd8aeaa53a8f3cc025a888ac00000000"

class Raw_signature_tx:
    def __init__(self,tx):
        self.txOrg = tx
        self.bytesused = {
            'version': ['Version',4],
            'flag': ['Flag',2],
            'inputcount': ['Input Count',1],
            'inputprevoutputhash': ['Input 1 Previous Output Hash',32],
            'inputprevoutputindex': ['Input 1 Previous Output',4],
            'scriptlen': ['Script length',1],
            'inputsecuence': ['Input secuence',4],
            'outputCount': ['Output Count', 1],
            'witnesscount': ['Witness Count', 1],
            'locktime': ['Locktime', 4],
        }
    def printer(self, parameter):

        if parameter == 'rest':
            if len(self.txOrg) == 0:
              print("!!Nada al final!!")
            else:
                print(self.txOrg)

        elif parameter == 'scriptlen':
            val = self.txOrg[0:self.bytesused[parameter][1] * 2]
            valint =int(val ,16)
            print("{}: {} . In hex: {} . Bytes: {}".format(self.bytesused[parameter][0],valint, val, self.bytesused[parameter][1]))
            self.txOrg = self.txOrg[self.bytesused[parameter][1] * 2:]

            leng_signature = self.txOrg[0:self.bytesused[parameter][1] * 2]
            leng_signature_int = int(leng_signature,16)

            print("Sign script: {} . Bytes: {}".format(self.txOrg[0:valint * 2], self.bytesused[parameter][1]))
            print("Signature: {} . Bytes: {}".format(self.txOrg[2:leng_signature_int * 2], leng_signature_int))
            resto = self.txOrg[leng_signature_int*2:leng_signature_int*2 + (valint -leng_signature_int)*2]
            print("Resto: {} . Bytes: {}".format(resto, leng_signature_int))
            self.txOrg = self.txOrg[leng_signature_int*2 + (valint -leng_signature_int)*2:]

        elif parameter =='outputs':
            counts = int(self.txOrg[0:self.bytesused['outputCount'][1] * 2])
            print("Cantidad de outputs: {} . Bytes: {}".format(counts, 1))
            self.txOrg = self.txOrg[1 * 2:]
            i = 0
            while i < counts:
                i+=1
                value = self.txOrg[0:8 * 2]
                valueInt = int(b2x(lx(value)),16)
                print("Output {} value in HEX: {} . value in Satoshies: {} . Bytes: {}".format(i, value, valueInt, 8))
                self.txOrg = self.txOrg[8 * 2:]
                lenoutputscript = int(self.txOrg[0:1 * 2],base=16)
                print("Output {} public key script length: {} . Bytes: {}".format(i, lenoutputscript, 1))
                self.txOrg = self.txOrg[1 * 2:]

                print("Output {} value {} . Bytes: {}".format(i, self.txOrg[0:lenoutputscript * 2], lenoutputscript))
                self.txOrg = self.txOrg[lenoutputscript * 2:]

        elif parameter =='witness':
            counts = int(self.txOrg[0:self.bytesused['witnesscount'][1] * 2])
            print("{}: {} . Bytes: {}".format(self.bytesused['witnesscount'][0],counts, 1))
            self.txOrg = self.txOrg[1 * 2:]
            i = 0
            while i < counts:
                i+=1
                lenwitnessdata = int(self.txOrg[0:1 * 2],base=16)
                print("Witness {} length: {} . Bytes: {}".format(i, lenwitnessdata, 1))
                self.txOrg = self.txOrg[1 * 2:]
                print("Output {} value: {} . Bytes: {}".format(i, self.txOrg[0:lenwitnessdata * 2], lenwitnessdata))
                self.txOrg = self.txOrg[lenwitnessdata * 2:]

        else:

            print("{}: {} . Bytes: {}".format(self.bytesused[parameter][0],self.txOrg[0:self.bytesused[parameter][1] * 2], self.bytesused[parameter][1]))
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

txOrgCcharpexample = '0100000001be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396000000008b483045022100da43201760bda697222002f56266bf65023fef2094519e13077f777baed553b102205ce35d05eabda58cd50a67977a65706347cc25ef43153e309ff210a134722e9e0141042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9ffffffff0123ce0100000000001976a9142bc89c2702e0e618db7d59eb5ce2f0f147b4075488ac00000000'
#txOrgCcharpexample = '0100000001be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396000000006b483045022100bbb36669c0c4db391c0c42aa617262da467078a70977cde16f94c4312ecdad8402203b8ba6f479ba12c7848722b1a8cee731ae3b2faf637be6d295e5b2d24915e4360121032daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db                                                                ffffffff0123ce0100000000001976a9142bc89c2702e0e618db7d59eb5ce2f0f147b4075488ac00000000'

object2 = Raw_signature_tx(txOrgCcharpexample)
object2.printer_all(False)
