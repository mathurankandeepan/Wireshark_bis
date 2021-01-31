import string
import os
import re
import sys 

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
    f = open(file+"/trames_gui.txt", "w+")
    f.write(text)
    f.close()
    return None
