class IP :

    def __init__ (self, version, ihl, tos, total_length, ident, flags, fragment_offset, ttl, protocol, header_cks ,src, dest, options) :
        self.version = version
        self.ihl = ihl
        self.tos = tos
        self.total_length = total_length
        self.ident = ident 
        self.flags = flags
        self.fragment_offset = fragment_offset
        self.ttl = ttl
        self.protocol = protocol
        self.header_cks = header_cks 
        self.src = src
        self.dest = dest
        self.options = options 
        self.bool_checksum = None

    def set_options (self, trame):
        self.options = trame
        return None

    def affichage_version (self) :
        print("\tVersion :     " + self.version)
        return None


    def affichage_ihl (self) :
        print("\tHeader Length :     ", 4 * int(self.ihl,16) , " bytes (", int(self.ihl,16) ,")",sep='')
        return None

    def taille_options_IP (self) : 
        if int(self.ihl,16) == 5 :
            return 0
        return (int(self.ihl,16) - 5 ) * 4


    def affichage_tos (self) :
        print("\tDifferentiated Services Field :     " + "0x" + self.tos[0])
        return None


    def affichage_total_length (self) :
        t = ''.join(self.total_length)
        print("\tTotal Length :    " , int(t,16)  )
        return None


    def affichage_ident (self) :
        t = ''.join(self.ident)
        print("\tIdentification :     " + "0x" + t + " (", int(t,16), ")", sep='')
        return None


    def affichage_flags (self) :
        t = ''.join(self.fragment_offset)
        print("\tFlags :     0x"+t)
        b = bin(int(self.flags,16))[2:].zfill(8)
        if b[0] != '0' :
            print("ERROR! Reserved bit of flag not 0!!")
            return None
        print ("\t\t 0... .... .... .... = Reserved bit : Not set")
        c = "Set" if b[1] == '1' else "Not Set"
        print ( "\t\t ." , b[1] ,  ".. .... .... .... = Don't Fragment : " + c, sep = '')
        c = "Set" if b[2] == '1' else "Not Set"
        print ( "\t\t .." , b[2],  ". .... .... .... = More Fragment : " + c, sep = '')
        return None


    def affichage_fragment_offset (self) :
        t = ''.join(self.fragment_offset)
        b = bin(int( t ,16))[2:].zfill(8)
        if b[1] == '0' and any(c != '0' for c in b[3:]) :
            print("ERROR! Fragment detected when not allowed!")
            return None
        print("\tFragment offset :     ", int(b[3:],2) )
        return None
        

    def affichage_ttl (self) :
        print("\tTime to live :     ", int(self.ttl,16 ) )
        return None


    def affichage_protocol (self) :
        t = self.protocol
        text = "\tProtocol :     "
        if t == "06" :
            print(text + " TCP (6)")
        elif t == "11":
            print(text + " UDP (17)")
        elif t == "01":
            print(text + " ICMP (1)")
        elif t == "02":
            print(text + " IGMP (2)")
        elif t == "08":
            print(text + " EGP (8)")
        elif t == "09":
            print(text + " IGP (9)")
        elif t == "24":
            print(text + " XTP (36)")
        elif t == "2E" or t == "2e":
            print(text + " RSVP (47)")
        else :
            print("\tProtocole non reconnu")
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
  


    def affichage_header_cks (self) :
        t = ''.join(self.header_cks)
        ok = self.bool_checksum
        if ok :
            s = "Verified"
        elif ok == False :
            s = "Bad checksum! ERROR"
        else :
            s = "Unverified"
        print("\tHeader checksum :     " + "0x" + t + " " + s )
        return None

    def affichage_src (self) :
        dec = [str(int (x, 16)) for x in self.src]
        src = '.'.join(dec)  
        print ( "\tSource :         ", src)
        return None

    def affichage_dest (self) :
        dec = [str(int (x, 16)) for x in self.dest]
        dest = '.'.join(dec)  
        print ( "\tDestination:     ", dest)
        return None

    def version_options(self, trame):
        octets = trame[0]
        if octets == "00" : 
            print( "\t\tOption IP - End of Options List (EOL) ")
            return 0
        elif octets == "01" :
            print( "\t\tOption IP - No-Operation (NOP) (1 byte)")
            return 0
        elif octets == "07" :
            taille = int(trame[1],16)
            pointeur = int(trame[2],16)
            print( "\t\tOption IP - Record route (RR) ")
            print("\t\t\tType : 7")
            print("\t\t\tLength : ", taille)
            print("\t\t\tPointer : ", pointeur)
            for i in range( 3 , taille, 4 ) :
                t1 = int( trame[i] ,16) 
                t2 = int( trame[i+1] ,16) 
                t3 = int( trame[i+2] ,16) 
                t4 = int( trame[i+3] ,16) 
                print( "\t\t\tRecorded Route : ", t1,".",t2,".",t3,".",t4,sep='')
            return taille - 2 
        elif octets == "83" :
            taille = int(trame[1],16)
            pointeur = int(trame[2],16)
            print( "\t\tOption IP - Loose Source Record Route (LSRR)")
            print("\t\t\tType : 131")
            print("\t\t\tLength : ", taille)
            print("\t\t\tPointer : ", pointeur)
            for i in range( 3 , taille, 4 ) :
                t1 = int( trame[i] ,16) 
                t2 = int( trame[i+1] ,16) 
                t3 = int( trame[i+2] ,16) 
                t4 = int( trame[i+3] ,16) 
                print( "\t\t\tRecorded Route : ", t1,".",t2,".",t3,".",t4,sep='')
            return taille - 2 
        elif octets == "89" :
            taille = int(trame[1],16)
            pointeur = int(trame[2],16)
            print( "\t\tOption IP - Strict Source Record Route (SSRR) ")
            print("\t\t\tType : 139")
            print("\t\t\tLength : ", taille)
            print("\t\t\tPointer : ", pointeur)
            for i in range( 3 , taille, 4 ) :
                t1 = int( trame[i] ,16) 
                t2 = int( trame[i+1] ,16) 
                t3 = int( trame[i+2] ,16) 
                t4 = int( trame[i+3] ,16) 
                print( "\t\t\tRecorded Route : ", t1,".",t2,".",t3,".",t4,sep='')
            return taille - 2
        elif octets == "44" :
            print( "\t\tOption IP - TimeStamp (TS) ")
            return 0
        else : 
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
        taille = self.taille_options_IP()
        if taille == 0 :
            print("\tPas d'options")
            return None
        bytes_options = taille
        print("\tOptions: (", bytes_options," bytes)", sep='')
        self.analyse_option()
        return None

    
    def affichage (self) : 
        print( "\nInternet Protocol Version 4")
        self.affichage_version ()
        self.affichage_ihl ()
        self.affichage_tos ()
        self.affichage_total_length ()
        self.affichage_ident ()
        self.affichage_flags ()
        self.affichage_fragment_offset ()
        self.affichage_ttl ()
        self.affichage_protocol ()
        self.affichage_header_cks ()
        self.affichage_src ()
        self.affichage_dest ()
        self.affichage_options ()
        
    def affichage_bouton(self, fichier ):
        taille_IP = 14 +  4 * int(self.ihl,16)
        t = "14 "+ str( taille_IP )+"\n"
        t = t + "14 15\n"
        t = t + "14 15\n"
        t = t + "15 16\n"
        t = t + "16 18\n"
        t = t + "18 20\n"
        t = t + "20 21\n"
        t = t + "20 22\n"
        t = t + "22 23\n"
        t = t + "23 24\n"
        t = t + "24 26\n"
        t = t + "26 30\n"
        t = t + "30 34\n"
        t = t + "34 " + str ( taille_IP) + "\n"
        fichier.write(t)
        return None
