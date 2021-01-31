from parser import *
from analyse import *
import string
import os
import re
import sys 
   
   
    
   
orig_stdout = sys.stdout
file =os.path.dirname( os.path.abspath(__file__))
   
f = open(file+"/out.txt", "w",  encoding="utf-8")
f_bouton = open(file+"/f_bouton.txt", 'w',  encoding="utf-8")
    
sys.stdout = f

fileSrc = sys.argv[1]

Liste_trames = parser(fileSrc)

analyses_toute_les_trames (Liste_trames,f_bouton)

sys.stdout = orig_stdout

f_bouton.close()
f.close()


ecrire_trame_gui(Liste_trames)
