from Ethernet import *
from IP import *
from TCP import *
from HTTP import *

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
    
