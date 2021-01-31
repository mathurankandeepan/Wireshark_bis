import string


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

