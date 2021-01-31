# How to install Wireshark_bis



Tout d'abord, merci de nous faire confiance et de donner tous les droits d'administrateurs pour ouvrir l'application (nous avons pas le niveau pour infecter votre ordinateur avec des logiciels malveillants). Nous avons besoin des droits pour lire et écrire dans un fichier pour rendre en sortie une version de notre affichage.

## Windows

Pour ouvrir l'application, vous aurez besoin de quatre choses :

- *python3* si vous ne l'avez déjà pas (https://www.python.org/downloads/) 
- *.NET 5.0*  (https://dotnet.microsoft.com/download)
- *Mono 32-bit* et *Gtk#* (https://www.mono-project.com/download/stable/)

Il ne vous reste plus qu'à exécuter *Wireshark_bis.exe*.

Si tous s'est bien passé, une fenêtre devrait s'ouvrir et le résultat de l'analyse des trames sous format texte devrait se trouver dans le fichier *out.txt*...
sinon lire la partie **Terminal**

## Mac

Pour ouvrir l'application, vous aurez besoin de trois choses :

- *python3* si vous ne l'avez déjà pas (https://www.python.org/downloads/) 
- *.NET 5.0*  (https://dotnet.microsoft.com/download)
- *Mono 6.12.0 (Visual Studio channel)* (https://www.mono-project.com/download/stable/)

Une fois chaque logiciel installée, vous n'avez rien à faire (aucune commande à taper dans le terminal) 

Ensuite, Clique droit sur *Wireshark_bis.app", *Afficher le contenu du paquet*, puis dans *./Contents/MacOS/*, Clique droit sur *Wireshark_bis*, puis *Ouvrir avec Terminal*... 

Si tous s'est bien passé, une fenêtre devrait s'ouvrir et le résultat de l'analyse des trames sous format texte devrait se trouver dans le fichier *out.txt* dans le dossier *Ressource*...
sinon lire la partie **Terminal**

## Linux

Pour ouvrir l'application, vous aurez besoin de trois choses :

- *python3* si vous ne l'avez déjà pas (https://www.python.org/downloads/) 
- *.NET 5.0*  (https://dotnet.microsoft.com/download)
- *Mono* (https://www.mono-project.com/download/stable/)

Vous aurez aussi besoin de la librairie GTK# :

```bash
sudo apt-get install libgtk2.0-cil-dev
```
Pour lancer l'application, tapez la commande suivante dans un terminal à l'emplacement du dossier contenant *Wireshark_exe*  : 
```bash
mono Wireshark_bis.exe
```
Si tous s'est bien passé, une fenêtre devrait s'ouvrir et le résultat de l'analyse des trames sous format texte devrait se trouver dans le fichier *out.txt*...

## Terminal 

Si vous lisez cette partie, c'est que vous avez rencontré un problème quelque part lors de votre installation.

Vous n'aurez donc pas la chance de voir le futur Wireshark...

Mais vous pouvez quand même analyser un ficher texte de trames. Exécutez la commande :
```py
python3 Wireshark_bis.py <nom_du_fichier_choisi>
```
Le résultat de l'analyse se trouve dans le fichier *out.txt* qui vient de se créer. 

Si cela ne marche pas toujours pas... contentez vous de la vidéo ;) (mais cela devrait marchait)





