# Wireshark_bis

*Wireshark_bis est un analyseur de protocoles réseaux offline comme son père Wireshark developpé en Python et en C#.
Cet analyseur peut reconnaitre presque tous les protocoles existants (joke)*

## Installation

Lire le fichier **HowTo** fourni ci-joint.


## Utilisation


Une premiere fenêtre devrait s'ouvrir demandant d'importer un ficher texte contenant des trames.

Après avoir importé le fichier, Wireshark_bis devrait s'ouvrir. Son utilisation est très similaire à Wireshark: cliquez sur une trame dans le tableau du haut pour afficher l'analyse de la trame  sous forme d'arborescence dans la partie du milieu. Bien sûr, les octects de la trame selectionnée sont affichées la partie inférieure de la fenêtre. Si vous double-cliquez sur une ligne de l'arborescence, les octects correspondant devrait se distinguer dans le tableau  du bas.

Bref, cette application porte bien son nom. Pour toute informations complémentaires, merci de contact le support technique.

## Explications

Notre project est divisé en trois parties distinctes.

Dans un premier temps, nous avons un parser, codé en Python, situé dans le fichier *parser*. Celui-ci permet de lire les données du fichier trace (format texte) contenant les octects bruts, fourni par l'utilisateur. En depit des lignes de textes entre les traces ou entre les lignes de la même trace, des offsets invalides ou encore des valeurs textuelles données en fin de ligne (y compris les chiffres hexadecimaux), notre analyseur recupere les octets bruts. 
Nous avons fait l'hypothèse que les offsets sont rangés dans l'ordre croissant. Si ce n'est pas le cas, alors notre analyseur informe l'utilisateur qu'une trame est erronée.

Dans un second temps, nous analysons les differentes trames grâce aux fonctions codées dans *analyse*. Si la trame est erronée ou si il manque des octects, la trame n'est pas analysée. 
Au niveau de la couche liaison, notre analyseur reconnait les protocoles **IPv4, IPv6, ARP, RARP, Appletalk**, et **X.25 niveau 3** mais il ne peut cependant analyser que les paquets IPv4.

Au niveau de la couche IP, notre analyseur reconnait les protocoles **TCP, UDP, ICMP, IGMP, EGP, IGP, XTP, RSVP** mais ne peut qu'analyser que les segments **TCP**. Il analyse aussi certaines options de IP comme le **Record Route** (7).

Au niveau de la couche transport, Wireshark_bis analyse presque toutes les options du protocol **TCP**, c'est-à-dire **MSS, Window scale, SACK permitted** ou encore **Timestamp**. 

Pour les couches IP et transport, des fonctions de vérification de checksum ont été implémentées pour vérifier la fiabilité des trames (fiabilité non pas à 100% mais c'est mieux que rien).

Enfin, concernant la couche 7, notre analyseur affiche les entêtes des trames si celle-ci sont font parties du protocole HTTP. Si la requête est en ASCII, alors elle sera affiché à l'écran.

Finalement, nous arrivons dans la dernière partie du projet : l'interface graphique. En fonction de votre système d'exploitation, vous n'aurez pas le même affichage. Comme vous avez pu le constater, nous avons essayer de recopier le plus fidèlement possible Wireshark. Nous espérons que Wireshark ne nous attaquera pas en justice pour plagiat...


## Support

Contacts :
[Clara CIOCAN](clara.ciocan@etu.sorbonne-universite.fr)
[Mathuran KANDEEPAN](mathuran.kandeepan@etu.sorbonne-universite.fr)


## Authors

[Clara CIOCAN](clara.ciocan@etu.sorbonne-universite.fr)
[Mathuran KANDEEPAN](mathuran.kandeepan@etu.sorbonne-universite.fr)
