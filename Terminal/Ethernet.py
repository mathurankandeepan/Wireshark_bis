

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
