class TCP :

    def __init__  (self , src_port, dest_port, sequence, acknowledgment, offset, flags, window, checksum, urgent_pointer, options) :
        self.src_port = src_port
        self.dest_port = dest_port
        self.sequence = sequence
        self.acknowledgment = acknowledgment
        self.offset = offset
        self.flags = flags
        self.window = window
        self.checksum = checksum
        self.urgent_pointer = urgent_pointer 
        self.options = options
        self.bool_checksum = None

    def set_options (self, trame):
        self.options = trame
        return None

    def affichage_src_port (self) : 
        t = ''.join(self.src_port)
        dec = int(t, 16)
        print ( "\tSource Port :     ", dec)
        return None

    def affichage_dest_port (self) : 
        t = ''.join(self.dest_port)
        dec = int(t, 16)
        print ("\tDestination Port :     ", dec)
        return None

    def affichage_sequence (self) : 
        t = ''.join(self.sequence)
        dec = int(t, 16)
        print ("\tSequence number :     ", dec)
        return None

    def affichage_ackowledgment (self) : 
        t = ''.join(self.acknowledgment)
        dec = int(t, 16)
        print ("\tAcknowledgment number :     ", dec)
        return None


    def affichage_offset (self) :
        b = bin(int(self.offset,16))[2:].zfill(8)
        b = b[:4]
        dec = int(b, 2)
        print ("\t" + b + " ....  = Header length : ", dec * 4 , " bytes (", dec ,")") 
        return None

    def taille_options_TCP (self) : 
        b = bin(int(self.offset,16))[2:].zfill(8)
        b = b[:4]
        dec = int(b, 2)
        if dec == 5 :
            return 0
        return (dec - 5 ) * 4




    def affichage_flags (self) : 
        print("\t Flags :")
        t = ''.join(self.flags)
        b = bin(int(t,16))[2:].zfill(16)
        b = b[4:]
        if any (x != '0' for x in b[:6] ):
            print("ERROR! Reserved bit not 0!!")
            return None

        print ("\t\t0000 00.. .... = Reserved bit : Not set")

        c = "Set" if b[6] == '1' else "Not Set"
        print ( "\t\t.... .." , b[6],  ". .... = Urgent  : " + c , sep = '')   

        c = "Set" if b[7] == '1' else "Not Set"
        print ( "\t\t.... ..." , b[7],  " .... = Acknowledgement  : " + c, sep = '')

        c = "Set" if b[8] == '1' else "Not Set"
        print ( "\t\t.... .... " , b[8],  "... = Push : " + c, sep = '')

        c = "Set" if b[9] == '1' else "Not Set"
        print ( "\t\t.... .... ." , b[9],  ".. = Reset : " + c, sep = '')

        c = "Set" if b[10] == '1' else "Not Set"
        print ( "\t\t.... .... .." , b[10],  ". = Syn  : " + c, sep = '')

        c = "Set" if b[11] == '1' else "Not Set"
        print ( "\t\t.... .... ..." , b[11],  " = Fin  : " + c, sep = '')
        return None



    def affichage_window (self) : 
        t = ''.join(self.window)
        dec = int(t, 16)
        print ("\tWindow size value :     ", dec)
        return None


    def verification_checksum (self, trame ) :
        max = len(trame)
        est_pair = True
        if max%2 == 1 :
            est_pair = False
            max -= 1
        cpt = 0 
        for i in range( 0, max, 2) :
            t = ''.join(trame[i:i+2])
            cpt = cpt + int(t,16)
        if not est_pair :
        	cpt = cpt + int(trame[max]+"00",16) 
        b = bin(cpt)[2:].zfill(16)

        lsb_16 = len(b) - 16
        res =  int(b[lsb_16:],2) + int(b[:lsb_16],2)
        if bin(res)[2:].zfill(16) == "1111111111111111" :
            self.bool_checksum = True
            return None
        self.bool_checksum = False
        
    def affichage_checksum (self) : 
        t = ''.join(self.checksum)
        ok = self.bool_checksum
        if ok :
            s = "Verified"
        elif ok == False :
            s = "Bad checksum! ERROR"
        else :
            s = "Unverified"
        print("\tChecksum : " + "0x" + t + " " + s )
        return None

    def affichage_urgent_pointer (self) : 
        t = ''.join(self.urgent_pointer)
        c = ''.join(self.flags)
        b = bin(int(c,16))[2:].zfill(16)
        b = b[4:]
        if b[6] == '0' and any(x == '1' for x in t) :
            print ("ERROR! Urgent pointer in use with URG Flag Not Set")

        print("\tUrgent Pointer :     " + "0x" + t)
        return None
        
        


    def version_options(self, trame):
        octets = trame[0]
        if octets == "00" : 
            print( "\t\tTCP Option - End of Options List (EOL) ")
            return 0
        elif octets == "01" :
            print( "\t\tTCP Option - No-Operation (NOP) (1 byte)")
            return 0
        elif octets == "02" :
            t = ''.join(trame[2:4])
            print("\t\tTCP Option - Maximun segment size", int(t,16), "bytes" )
            print("\t\t\tKind : Maximum segment size (2)")
            print("\t\t\tLength : 4")
            print("\t\t\tMSS Value : ", int(t,16) )
            return 3
        elif octets == "03" :
            print("\t\tTCP Option -  Window scale", int(trame[2],16))
            print("\t\t\tKind : Window Scale (3)")
            print("\t\t\tLength : 3")
            print("\t\t\tShift count : ",int(trame[2],16) )

            
            return 2
        elif octets == "04" : 
            print("\t\tTCP Option - SACK permitted")
            print("\t\t\tKind : SACK permitted (4)")
            print("\t\t\tLength : 2")
            return 1
        elif octets == "08" :
            t2 = ''.join(trame[2:6])
            t3 = ''.join(trame[6:10])
            print("\t\tTCP Option - Timestamps :")
            print("\t\t\tKind : Time Stamp Option (8)", sep='')
            print("\t\t\tLength : 10")
            print("\t\t\tTimestamp value : ", int (t2,16))
            print("\t\t\tTimestamp echo reply : ", int (t3,16))
            return 9
        elif octets == "09" :
            print("\t\tPartial Order Connection Permitted")
            return 3 
        else :
            print("\t\tUnknown Option")
            return 0

    def analyse_option(self) :
        trame = self.options
        taille = len( trame  )
        i = 0
        while i != taille :
            length_option = self.version_options(trame[i:])
            i = i + length_option
            i += 1
        return None

    def affichage_options (self) : 
        taille = self.taille_options_TCP()
        if taille == 0 :
            print("\t Pas d'options")
            return None
        bytes_options = taille
        print("\t Options: (", bytes_options," bytes)", sep='')
        self.analyse_option()
        return None


    def affichage (self) :
        print ("\nTransmission Control Protocol ")
        self.affichage_src_port ()
        self.affichage_dest_port ()
        self.affichage_sequence ()
        self.affichage_ackowledgment ()
        self.affichage_offset ()
        self.affichage_flags ()
        self.affichage_window ()
        self.affichage_checksum ()
        self.affichage_urgent_pointer ()
        self.affichage_options ()
        return None


    def affichage_bouton(self, fichier, debut ):
        b = bin(int(self.offset,16))[2:].zfill(8)
        b= b[:4]
        dec = int(b, 2)
        taille_TCP = 4 * dec
        str_debut = str(debut)
        str_fin = str(debut + taille_TCP)
        t = str_debut + " " + str_fin +"\n"
        t = t + str(debut) + " " + str(debut+2) +"\n"
        t = t + str(debut+2) + " " + str(debut+4) +"\n"
        t = t + str(debut+4) + " " + str(debut+8) +"\n"
        t = t + str(debut+8) + " " + str(debut+12) +"\n"
        t = t + str(debut+12) + " " + str(debut+13) +"\n"
        t = t + str(debut+12) + " " + str(debut+14) +"\n"
        t = t + str(debut+14) + " " + str(debut+16) +"\n"
        t = t + str(debut+16) + " " + str(debut+18) +"\n"
        t = t + str(debut+18) + " " + str(debut+20) +"\n"
        t = t + str(debut+20) + " " + str_fin +"\n"
        fichier.write(t)
        return None
