# Class to split de raw transaction
class Raw_signature_tx:
    def __init__(self, tx):
        self.txOrg = tx
        self.bytesused = {
            'version': ['Version', 4],
            'flag': ['Flag', 2],
            'inputcount': ['Input Count', 1],
            'inputprevoutputhash': ['Input 1 Outpoint TXID', 32],
            'inputprevoutputindex': ['Outpoint index number', 4],
            'scriptlen': ['Bytes in SignScript', 1, 'Push bytes as data', 1],
            'inputsecuence': ['Input secuence', 4],
            'outputCount': ['Output Count', 1],
            'witnesscount': ['Witness Count', 1],
            'locktime': ['Locktime', 4],
        }

    def flip_byte_order(self, stringstr):
        flipped = "".join(reversed([stringstr[i:i + 2] for i in range(0, len(stringstr), 2)]))
        return flipped

    def space_separator(self, len_data):
        return "." * (50 - len_data) if len_data < 50 else "." * 5

    def printer(self, parameter):

        if parameter == 'rest':
            if len(self.txOrg) == 0:
                print("!!Nada al final!!")
            else:
                print(self.txOrg)

        elif parameter == 'scriptlen':
            val = self.txOrg[0:self.bytesused[parameter][1] * 2]
            valint = int(val, 16)
            len_data = len(val)
            first_string = "|"
            space_after_data = self.space_separator(len_data)

            print("{}{}{}:{} . Int Value: {} . Bytes: {}".format(first_string, val, space_after_data,
                                                                 self.bytesused[parameter][0], valint,
                                                                 self.bytesused[parameter][1]))
            self.txOrg = self.txOrg[self.bytesused[parameter][1] * 2:]

            val_signature = self.txOrg[0:self.bytesused[parameter][1] * 2]
            val_signature_int = int(val_signature, 16)
            len_data = len(val)
            # self.txOrg = self.txOrg[self.bytesused[parameter][1] * 2:]

            ## Le resto 1 byte al signscript len del len del signature
            valint = valint - 1
            first_string = "|"
            space_after_data = self.space_separator(len_data)
            print("{}{}{}:{} . Int Value: {} . Bytes: {}".format(first_string, val_signature, space_after_data,
                                                                 self.bytesused[parameter][2], val_signature_int,
                                                                 self.bytesused[parameter][3]))
            self.txOrg = self.txOrg[self.bytesused[parameter][1] * 2:]

            signature = self.txOrg[0:(val_signature_int - 1) * 2]

            len_data = len(signature)
            first_string = "|"
            space_after_data = self.space_separator(len_data)

            print("{}{}{}:Sign script . Bytes: {}".format(first_string, signature, space_after_data,
                                                          self.bytesused[parameter][1]))
            self.txOrg = self.txOrg[len_data:]
            print("|{}{} . Bytes: {}".format(self.txOrg[0:2], ' \\Added after signature', 1))
            print("|{}{} . Bytes: {}".format(self.txOrg[2:4], ' \\Length of public key', 1))
            print(
                "{}{}{} . Bytes: {}".format(first_string, self.txOrg[4:int(self.txOrg[2:4], 16) * 2], space_after_data,
                                            (valint - val_signature_int) * 2))
            self.txOrg = self.txOrg[int(self.txOrg[2:4], 16) * 2 + 4:]
        elif parameter == 'outputs':
            counts = int(self.txOrg[0:self.bytesused['outputCount'][1] * 2])
            len_data = 1
            first_string = "|"
            space_after_data = self.space_separator(len_data)

            print("{}{}{}:{}. Bytes: {}".format(first_string, counts, space_after_data, 'Cantidad de outputs', 1))
            self.txOrg = self.txOrg[1 * 2:]
            i = 0
            while i < counts:
                i += 1
                value = self.txOrg[0:8 * 2]
                valueInt = int(self.flip_byte_order(value), 16)
                len_data = len(value)
                first_string = "|"
                space_after_data = self.space_separator(len_data)

                print("{}{}{}:Output {} . value in Satoshies: {} . Bytes: {}".format(first_string, value,
                                                                                     space_after_data, i, valueInt, 8))
                self.txOrg = self.txOrg[8 * 2:]

                lenoutputscript = self.txOrg[0:1 * 2]
                lenoutputscriptInt = int(self.txOrg[0:1 * 2], base=16)
                len_data = len(lenoutputscript)
                first_string = "|"
                space_after_data = self.space_separator(len_data)
                print("{}{}{}:Output {} public key script length . Integer value {} . Bytes: {}".format(first_string,
                                                                                                        lenoutputscript,
                                                                                                        space_after_data,
                                                                                                        i,
                                                                                                        lenoutputscriptInt,
                                                                                                        1))
                self.txOrg = self.txOrg[1 * 2:]
                data = self.txOrg[0:lenoutputscriptInt * 2]
                len_data = len(data)
                first_string = "|"
                space_after_data = self.space_separator(len_data)
                print(
                    "{}{}{}:Output {} . Bytes: {}".format(first_string, data, space_after_data, i, lenoutputscriptInt))
                self.txOrg = self.txOrg[lenoutputscriptInt * 2:]

        elif parameter == 'witness':
            counts = int(self.txOrg[0:self.bytesused['witnesscount'][1] * 2])
            data = self.bytesused['witnesscount'][0]
            len_data = len(data)
            first_string = "|"
            space_after_data = self.space_separator(len_data)
            print("{}{}{}:{} . Bytes: {}".format(first_string, counts, space_after_data, data, 1))
            self.txOrg = self.txOrg[1 * 2:]
            i = 0
            while i < counts:
                i += 1
                lenwitnessdata = int(self.txOrg[0:1 * 2], base=16)
                print("{} Witness {} length: {} . Bytes: {}".format(first_string, i, lenwitnessdata, 1))
                self.txOrg = self.txOrg[1 * 2:]
                print("Output {} value: {} . Bytes: {}".format(i, self.txOrg[0:lenwitnessdata * 2], lenwitnessdata))
                self.txOrg = self.txOrg[lenwitnessdata * 2:]
        else:
            data = self.txOrg[0:self.bytesused[parameter][1] * 2]
            len_data = len(data)
            first_string = "|"
            space_after_data = self.space_separator(len_data)
            print("{}{}{}:{} . Bytes: {}".format(first_string, data, space_after_data, self.bytesused[parameter][0],
                                                 self.bytesused[parameter][1]))
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


# object = Raw_signature_tx(txOrg)
# object.printer_all()

# object1 = Raw_signature_tx(txOrg1)
# object1.printer_all()

txOrgCcharpexample = '01000000015cd81501e2a63c942fcb24de76d4532406156c8cb10b5dcb123a1cb5be13d884000000008a47304402203f3fa0f312724f41a0fa8c09f371ddf193916dc9c4fc5137711d49f18fafe0a002204f5f2b3925a62fe43d335ed0a17255dc199dedd16f628c1dc4f48f76e16ebe9901410437078f8c4a54b67cd1724a3535cb1918bca186c7a143459c9aac35113d4a958b0d4eea6b320fa82c17147b72e0fe11c08b0054897ffb7bdb194f259b0db9e129ffffffff02a0860100000000001976a914478075922af41fb441aa0ab67e91aef27ef1e68688ac50c30000000000001976a914ec06b2bf18c89706855f761d215f21f3315b399488ac00000000'

object2 = Raw_signature_tx(txOrgCcharpexample)
object2.printer_all(False)
