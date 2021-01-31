import string
import os
import re
import sys




class Ethernet :

    def __init__(self, dest, src, type_protocole)  :
        self.dest = dest
        self.src = src 
        self.type_protocole = type_protocole
    

    def affichage_dest(self) :
        dest = ':'.join(self.dest)  
        print ( "\tDestination (Adresse MAC) : ", dest )
        return None

    def affichage_src(self) :
        src = ':'.join(self.src)  
        print ( "\tSource (Adresse MAC) : ", src)
        return None

    @staticmethod
    def version_type ( t ) :
        if  t ==  "0800"  :
            print( " (IPv4)" )
        elif  t == "0806"  :
            print (  " (ARP)" )
        elif  t == "8035"  :
            print ( " (RARP)")
        elif t == "8090" :
            print( " (Appletalk)")
        elif t == "0805" :
            print( " (X.25 niveau 3)")

        elif t == "86dd" or t == "86DD" :
            print( " (IPv6)")
        else :
            print(" Non reconnu")
        return None
            
    def affichage_type_protocole (self) :
        t = ''.join(self.type_protocole)
        t1 = "0x"+t
        print ( "\tType :      " , t1, end = '')
        self.version_type ( t )
        return None

    def affichage(self) :
        print ("\nEthernet II")
        self.affichage_dest()
        self.affichage_src()
        self.affichage_type_protocole()  
        
    def affichage_bouton(self, fichier ):
        t = "*\n0 14\n"
        t = t + "0 6\n"
        t = t + "6 12\n"
        t = t + "12 14\n"
        fichier.write(t)

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
            print("\t\tTCP Option - Timestamp :")
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

class HTTP :

    def __init__ ( self, data ) :
        self.data = data

      

    def affichage_data (self) :
        t = "\t"
        tmp = 0
        tmp1 = 0
        for x in self.data :
            if ( 13 == int(x,16) ) :
                if tmp == 10 :
                    tmp1 = 10
                
            elif ( 10 == int(x,16) ) :
                if tmp1 == 10 :
                    break
                else :
                    tmp = 10 
            else :
                tmp = 0 
                tmp1 = 0  
            t = t + chr( int(x,16) )
            if tmp == 10 :
                t = t + "\t"

        try:
            t.encode('ASCII')
        except UnicodeEncodeError:
            print ("\tIt was not a ascii-encoded unicode string")
        else:
            print ( t )
        return None


    def affichage( self) :
        print( "Hypertext Transfer Protocol")
        self.affichage_data()
        return None

    def affichage_bouton(self, fichier, debut) :
        t = str(debut) + " " + str(debut + len(self.data))+"\n"
        fichier.write(t)
        return None




def affichage_liste_ligne( L ) :
    """ list[octects] -> None
    Affiche une ligne de la trame recupere """
    print(L)
    return None

def affichage_plusieurs_listes_lignes( L ) :
    """ list[list[octects]] -> None
    Affiche plusieurs lignes de la trame """
    for i in L :
        affichage_liste_ligne(i)
    return None

def affichage_trame (trame) :
    """ list[octects] -> None
    Affiche la trame """
    print(trame)
    return None

def affichage_plusieurs_trames( liste_trame ) :
    """liste(tuple(list[octects],bool,int,int))  -> None
    Affiche plusieurs trames"""
    print ("\n ********************** AFFICHAGE DES TRAMES **************************** \n")
    for L in liste_trame :
        trame, ok, ligne_erreur,taille = L
        print ( L )
        print("\n")
    return None

def creation_listes_lignes( nom_fichier ):
    """ str -> list ( list ( octects ) )
    Retourne une liste de toutes les lignes du fichier en supprimant tous les caractères 
    non hexadecimaux, et y compris les caracteres hexadecimaux se situant apres ces caracteres
    non hexadecimaux"""

    f = open(nom_fichier)

    # lines_list : list [str]
    lines_list = list(f.read().splitlines())        # split le fichier en une liste de lignes  
    
    f.close() 

    # _element_lignes : list [ list (str) ]
    element_lignes = []
    
    # split les lignes avec des espaces
    element_lignes = [[ n for n in k.split(' ') if n != '' ] for k in lines_list]
    
    # nombre de lignes totales
    ligne_len = len( element_lignes) 

    # i : int
    i = 0
      
    # while il y a des lignes a parcourir faire :
    while i < ligne_len :
        # k : int  <- nombre d'element de la ligne i 
        k = len(element_lignes[i]) 
        
        # parcours de la ligne i
        for j in range(k):
            # if caractere ligne[i][j] est un hexa then ok = True
            ok = all (c in string.hexdigits for c in element_lignes[i][j]) 
            # else suppression de tous les caracteres apres le premier element identifié comme non hexadecimal
            if not ok :
                del element_lignes[i][j:]
                break
        
        # if il y a une ligne sans caractere hexa ou seulement un seul, then supprimer cette ligne 
        if element_lignes[i] == [] or len(element_lignes[i]) == 1 :
            element_lignes.pop(i)
            ligne_len -= 1
        else:
            i += 1
    # return une liste des lignes du fichier apres avoir filtre tous les caracteres non hexa
    return element_lignes

  
def make_list_offset_decimal( trame ) :
    """ list[list[octects]] -> list[int]
    Retourne une liste de tous les offset convertis en decimal
    Si les offsets ne sont pas ranges dans l'ordre croissant then return []
    la trame est donc erronee"""
    # liste_offset : list [int]
    liste_offset = [0]
    # offset : int          <- offset courant
    offset = 0
    # n : int 
    n = 0
    # parcours tous les offsets de la trame
    for L in trame [1:] :
        n = int( L[0], 16)
        # if n est superieur au precedent offset 
        if  offset < n :
            liste_offset.append(n)
            offset = n
        # else la trame est erronee
        else :
            return []
    # return la liste d'offset en decimal
    return liste_offset


def decoupage_plusieurs_trames ( L ):
    """ list[lignes] -> list[list[lignes]]
    Retourne une liste de differente trame sectionne grace a l'offset 0x0"""
    
    # liste_trame : list[list[lignes]]
    liste_trame = [] 
    # trame : list[lignes]
    trame = []
    # lignes_totale : int
    nombre_lignes_totale = len(L)
    # cpt_lignes : int 
    cpt_lignes = 0
    # n : int       <- offset en decimal
    n = int(L[0][0], 16)
    
    # while on trouve un offset a 0
    while  n != 0 :
        # on compte le nombre de lignes parcourues
        cpt_lignes += 1
        n = int(L[cpt][0], 16)
    
    # Ajout de la premiere ligne de la premier trame
    trame.append(L[cpt_lignes])
    # parcours de toutes les lignes suivantes
    for i in range (cpt_lignes + 1,nombre_lignes_totale) :
        # n recupere l'offset de la ligne i
        n = int(L[i][0], 16)
        # if offset == 0 then on passe a une nouvelle trame
        if (n == 0) :
            liste_trame.append(trame)
            trame = []
        trame.append(L[i])
    # ajout de la derniere trame
    liste_trame.append(trame)   

    # return la liste des listes de chaque trame
    return liste_trame 


def creation_trame ( L , liste_offset ) :
    """ list[list[octects]] ,list[int] -> tuple(list[octects], bool, int ,int)
    Creation de la trame a partir des lignes de L et la liste des offset"""
    # si la L est errone 
    if liste_offset ==[] :
        return [],False,-1,0
    
    # trame : tuple(list[octects], bool, int ,int)       # Trame finale
    trame = [] 
    # add : list[octects]
    add = []
    # len_offset : int 
    len_offset = len(liste_offset)-1
    # diff : list [int]       creation de la difference entre tous les offsets pour savoir le nombre d'octects par ligne
    diff = [ liste_offset[x+1]- liste_offset[x] for x in range(len_offset)]
    # k : int           Nombre de ligne de L - 1
    k = len( L ) - 1 
    
    for i in range (k) :
        # add recupere les octects necessaires pour completer la ligne en fonction de la valeur de l'offset
        add = L[i][1:diff[i]+1]
        trame = trame + add
        
        # Si il manque des octects 
        if (len(add) != diff[i] ) :
            # return error avec la ligne de l'erreur
            taille = len(trame)
            return (trame, False, i+1, taille)
            
    # rajout des derniers octets de la trame
    trame = trame + L[k][1:]
    # taille : int          <- renvoie le nombre d'octets de la trame
    taille = len(trame) 

    return (trame, True, -1, taille)





def parser( nom_fichier ) :
    """ str -> list [ tuple(list[octects], bool, int ,int) ] 
    Renvoie une liste de trames a partir du fichier en parametre """
    
    # liste_trame : list[tuple()]
    liste_trame = []
    # liste_lignes_fichiers : list[lignes]
    liste_lignes_fichiers = creation_listes_lignes ( nom_fichier )
    # res : list[list[lignes]]      <- split les trames du fichiers
    res = decoupage_plusieurs_trames( liste_lignes_fichiers )

    for L in res :

        # Recuperation des offsets de chaque ligne et suppression si lignes ne commencant pas par un offset
        liste_offset = make_list_offset_decimal(L)
        # Creation de la trame
        liste_trame.append( creation_trame( L , liste_offset)  )

    return liste_trame


def ecrire_trame_gui( liste_trames ) :
    """ tuple(list[octects], bool, int ,int) -> None 
    Ecris dans le fichier trame_gui.txt les trames pour l'interface graphique"""

    # text : str
    text = ""
    # Parcours de toutes les trames
    for tuple_trame in liste_trames :
        # offset : int      <- Reset a chaque tour de boucles
        offset = 0

        trame, ok, ligne_erreur, taille = tuple_trame
        # if la trame est errone 
        if trame == [] :
            text = text + "!!!!\n*\n"
            continue
        
        # lignes : int 
        lignes = taille//16
        # reste: int 
        reste = taille % 16

        # Parcours des lignes de chaques trames pour l'affichage dans l'interface graphique
        for i in range ( 0, lignes, 1) :
            str_offset = (hex(offset))[2:].zfill(4)
            text = text + str_offset + " " + ' '.join(trame[i*16:i*16+16]) + "\n"
            offset = offset + 16
         
        if trame[lignes*16:] == [] :
            text = text + "*\n"
            continue
        
        str_offset = (hex(offset))[2:].zfill(4)
        text = text + str_offset + " " + ' '.join(trame[lignes*16:])
        text = text + "\n*\n"

    # ouverture / ecriture / fermeture du fichiers
    file =os.path.dirname( os.path.abspath(__file__))
    f = open(file+"/.trames_gui.txt", "w+")
    f.write(text)
    f.close()
    return None


def est_IPv4 ( trame ) :
    """ Si la trame utlise le protocole IPV4 return True else return False"""
    if  "0800" == ''.join(trame[12:14]) :
        return True
    return False

def est_TCP ( trame ) :
    """ Si la trame utlise le protocole TCP return True else return False"""
    if "06"  == trame[23] :
        return True
    return False

def est_HTTP ( trame, port_src, port_dest ) :
    """ Si la trame utlise le protocole HTTP return True else return False"""
    int_port_src = int( ''.join(port_src),16)
    int_port_dest = int( ''.join(port_dest),16)
    if 80 == int_port_dest or 80 == int_port_src :
        return True
    return False
def nombre_octects_exacts ( taille, length_IP ):
    """ Si le nombre d'octets de la trame == Total legth annoncee dans IP
    then return True else return False"""
    if taille == length_IP + 14 :
        return True
    return False


def analyses_toute_les_trames ( Liste_trames , fichier ) :
    """list [ tuple(list[octects], bool, int ,int) ] -> None
    Analyse toutes les trames recuperees """
    
    length = len(Liste_trames) # nombre de trames recuperees

    # Parcours de toutes les trames recuperees
    for i in range( length ) :

        Trame, ok, ligne_erreur, taille = Liste_trames[i]

        print ( "\n********************* Analyse de la trame", i+1, "******************** \n")
        
        # if la trame est errone en raison des offsets invalides
        if Trame == [] :
            print(" \nLa trame" , i, "est erronee car l'offset n'est pas dans l'ordre croissant\n")
            fichier.write("*\n!\n" )
            continue

        # if il manque des octets dans la trame
        if not ok : 
            print("      \nLa trame" , i, "a rencontré une erreur à la ligne ",ligne_erreur, " de sa trame\n")
            fichier.write("*\n!\n" )
            continue

        print (taille, " octets de donnees")

        # donne des noms differents a chaque trame et leurs composantes
        str_num = str(i)
        str_Ethernet = "Ethernet_" + str_num
        str_IP = "IP_" + str_num
        str_TCP = "TCP_" + str_num
        str_HTTP = "HTTP_" + str_num
        
        # Entete Ethernet
        dest_mac =       Trame[:6]            # Destination (Adresse MAC)
        src_mac =        Trame[6:12]          # Soruce (Adresse MAC)
        type_ethernet =  Trame[12:14]         # Type Ethernet

        str_Ethernet = Ethernet( dest_mac, src_mac, type_ethernet )
        str_Ethernet.affichage()
        str_Ethernet.affichage_bouton(fichier)

        # If la trame n'est pas IPv4 then aller à la trame suivante
        if not est_IPv4( Trame ) :
            print("Notre analyseur ne prend pas en compte le protocole 0x" + ''.join(Trame[12:14] ) )
            fichier.write("14 " + str(taille))
            continue
        
        # Entete IPv4
        version = Trame[14][0]              # Version
        header_length_ip = Trame[14][1]     # Header Length
        dsf =  Trame[15]                    # Differentiated Sevices Field
        total_length = Trame[16:18]         # Total Length
        id = Trame[18:20]                   # Identification
        flags_ip = Trame[20]                # Flags
        offset = Trame[20:22]               # Framgment offset
        ttl = Trame[22]                     # Time to live
        protocol = Trame[23]                # Protocol
        checksum_ip =  Trame[24:26]         # Header Checksum
        src_ip = Trame[26:30]               # Source IP
        dest_ip = Trame[30:34]              # Destination IP
        options_ip = []                     # Options IP
        
        str_IP = IP ( version, header_length_ip, dsf , total_length, id, flags_ip, offset, ttl, protocol, checksum_ip, src_ip, dest_ip, options_ip)
        
        taille_options_IP = str_IP.taille_options_IP()      # Recupere la taille des options IP si elles existent
        fin_IP =  34 + taille_options_IP                    # Recupere le dernier octect de l'entete IP
        str_IP.set_options( Trame[34 : fin_IP ]  )          # Affectation des options de IP
        str_IP.verification_checksum(Trame[14:fin_IP] )     # Check le checksum
        
        str_IP.affichage()
        str_IP.affichage_bouton(fichier)


        # if la trame recuperee n'est pas de la taille de totale_length
        if not nombre_octects_exacts( taille, int(''.join(str_IP.total_length),16)):
            print("La trame contient ",taille,"octets alors qu'elle devrait en contenir",int(''.join(str_IP.total_length),16)+14)
            continue

        # if la trame n'est pas TCP then aller à la trame suivante
        if not est_TCP( Trame ) :
            print("\nNotre analyseur ne prend pas en compte le protocole 0x" + ''.join(Trame[23] ) )
            fichier.write(str(fin_IP) +" " + str(taille) + "\n")
            continue

        # Entete TCP
        debut_TCP = fin_IP                                      # premier octer du segment TCP
        src_port = Trame[debut_TCP:debut_TCP+2]                 # Source Port
        dest_port = Trame[debut_TCP+2:debut_TCP+4]              # Destination Port
        sequence = Trame[debut_TCP+4:debut_TCP+8]               # Sequence number
        acknowledgment = Trame[debut_TCP+8:debut_TCP+12]        # acknowledgment number
        header_length_tcp = Trame[debut_TCP+12]                 # Header Length
        flags_tcp = Trame[debut_TCP+12:debut_TCP+14]            # Flags
        window = Trame[debut_TCP+14:debut_TCP+16]               # Window
        checksum_tcp = Trame[debut_TCP+16:debut_TCP+18]         # Checksum    
        urgent_pointer = Trame[debut_TCP+18:debut_TCP+20]       # Urgent pointer
        options_tcp = []                                        # Options
        TCP_length = str ( hex( int( ''.join(str_IP.total_length),16 ) - 20 - taille_options_IP )[2:].zfill(4)) # Taille du segment TCP
        

        str_TCP = TCP ( src_port, dest_port, sequence, acknowledgment, header_length_tcp, flags_tcp, window, checksum_tcp, urgent_pointer, options_tcp)
        str_TCP.set_options( Trame[debut_TCP+20 : debut_TCP+20+str_TCP.taille_options_TCP() ]  )
        str_TCP.verification_checksum( src_ip + dest_ip  + ["00"] + [protocol] + [TCP_length[0:2]] + [TCP_length[2:4]] +  Trame[debut_TCP:])    # Check le checksum
        str_TCP.affichage()
        str_TCP.affichage_bouton(fichier, debut_TCP) 

        taille_options_TCP = str_TCP.taille_options_TCP()          # Recupère la taille des options TCP si elles existent
        fin_TCP = debut_TCP + 20 + taille_options_TCP              # Recupere le dernier octect de l'entete IP

        # if pas de data then aller a la trame suivante
        if fin_TCP == taille :
            continue

        # if la trame n'est pas HTTP then aller à la trame suivante
        if not est_HTTP( Trame, src_port, dest_port) :
            print("\nNotre analyseur ne peut pas lire le contenu de ce segment (pas HTTP)")
            continue
        
        debut_HTTP = fin_TCP    # Récupère le premier octet du segment HTTP
        str_HTTP = HTTP ( Trame[debut_HTTP:])
        str_HTTP.affichage()
        str_HTTP.affichage_bouton(fichier, debut_HTTP)

    return None
    




if __name__ == "__main__":

    orig_stdout = sys.stdout
    file =os.path.dirname( os.path.abspath(__file__))
    
    f = open(file+"/out.txt", "w",  encoding="utf-8")
    f_bouton = open(file+"/.f_bouton.txt", 'w',  encoding="utf-8")
    
    sys.stdout = f
    fileSrc = sys.argv[1]
    Liste_trames = parser(fileSrc)

    analyses_toute_les_trames (Liste_trames,f_bouton)


    sys.stdout = orig_stdout
    f_bouton.close()

    f.close()
    ecrire_trame_gui(Liste_trames)
