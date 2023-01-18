from kivy.app import App
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen
import SAE_DB as DB

Builder.load_file("EtudiantDossier.kv")

class Login(Screen):
    def Verify(self):
        user = self.ids.Login.text                                      #Récupère la variable user entrer dans le Formulaire
        mdp = self.ids.Password.text                                    #Récupère la variable mdp entrer dans le Formulaire
        credentials = DB.Get_Cred(user,mdp)                             #Transforme nos variable en crédential pour leurs manip
        if DB.log(credentials) == "Error!":
            self.ids.error.size_hint = 0.2,0.2
            self.ids.error.text = "Mauvais mdp ou login"
        else:
            self.manager.current = "formulaire"
        pass

class Formulaire(Screen):
    def chngbckgrnd(self,x):
        self.ids['nav'+str(x)].background_color = 0, 0.6, 0.8, 1.0
    
    def restbckgrnd(self,x):
        self.ids['nav'+str(x)].background_color = "black"

    def addData(self):
        noms = self.ids.nom_input.text                                                                   #Variable nom
        annee = self.ids.annee_input.text                                                               #Variable annee
        math = self.manager.get_screen("moyennes").ids.maths_input.text                                 #Variable moy_math
        info = self.manager.get_screen("moyennes").ids.info_input.text                                  #Variable moy_infor
        anglais = self.manager.get_screen("moyennes").ids.anglais_input.text                            #Variable moy_anglais
        photo = self.manager.get_screen("files").ids.fc.selection[0]                                    #Variable photo
        DB.Insert_stud(noms, annee, photo, math, info, anglais)
        self.manager.get_screen("submit").ids.response.text = f"l'étudiant {noms} a bien été ajouté "
        self.manager.get_screen("submit").ids.response.color = "green"
        self.manager.get_screen("submit").ids.nav2.color = "white"
        self.manager.get_screen("submit").ids.nav3.color = "white"
        self.ids.nom_input.text = ""
        self.ids.annee_input.text = ""
        self.manager.get_screen("files").ids.fc.selection[0] = ""
        self.manager.get_screen("files").ids.apercu.source = "A_black_image.jpg"
        self.manager.get_screen("files").ids.apercu.size_hint = 0, 0
        self.manager.get_screen("moyennes").ids.maths_input.text = ""
        self.manager.get_screen("moyennes").ids.info_input.text = ""
        self.manager.get_screen("moyennes").ids.anglais_input.text = ""

    def checkferrors(self):
        if self.ids.nom_input.text == "" or self.ids.annee_input.text == "" or self.manager.get_screen("files").ids.fc.selection == [] or self.manager.get_screen("moyennes").ids.maths_input.text == "" or self.manager.get_screen("moyennes").ids.info_input.text == "" or self.manager.get_screen("moyennes").ids.anglais_input.text == "":
            self.manager.get_screen("submit").ids.response.text = "Il manque des informations, veulliez compléter"
            self.manager.get_screen("submit").ids.response.color = "red"
            self.manager.get_screen("submit").ids.nav2.color = "red"
            self.manager.get_screen("submit").ids.nav3.color = "red"
        else:
            self.addData()

class Files(Screen):
    def selectPhoto(self,filename):
        try:
            self.ids.apercu.source = filename[0]
            self.ids.apercu.size_hint = 1, 1
        except IndexError:
                pass

    def addPhoto(self,filename):
        try:
            self.convertToBinaryData(str(filename[0]))
        except IndexError:
            pass
        pass

    def convertToBinaryData(self,filename):
        try:
            with open(filename, 'rb') as file:
                blobData = file.read()
            return(blobData)
        except FileNotFoundError:
            pass

class Moyennes(Screen):
    def chngbckgrnd(self,x):
        self.ids['nav'+str(x)].background_color = 0, 0.6, 0.8, 1.0
    
    def restbckgrnd(self,x):
        self.ids['nav'+str(x)].background_color = "black"


Etu = "taz"      #definition de la variable global etu
ele_Etu = []
class BD(Screen):
    items = DB.Get_Users()

    def chngbckgrnd(self,x):
        self.ids['nav'+str(x)].background_color = 0, 0.6, 0.8, 1.0
    
    def restbckgrnd(self,x):
        self.ids['nav'+str(x)].background_color = "black"

    def getSpinner(self):
        if self.ids.spinner.text != "Choisissez un étudiant parmi la liste":
            global Etu
            global ele_Etu
            Etu = self.ids.spinner.text
            ele_Etu = DB.Get_photo(Etu)
        pass

    def actualSpinner(self):
        self.ids.spinner.values = DB.Get_Users()

    def chngdata(self):
        print(Etu)
        *noms, prenom = Etu.split()
        print(prenom)
        nom = ""
        for element in noms:
            nom += " " + str(element)
        print(nom,prenom)
        moyennes = DB.Get_Moyennes(nom,prenom)
        self.manager.get_screen("bdres").ids.Name.text = " "*12 + "{}".format(Etu)
        self.manager.get_screen("bdres").ids.Year.text =  str(ele_Etu[3])
        self.manager.get_screen("bdres").ids.MeanM.text = str(moyennes[1])
        self.manager.get_screen("bdres").ids.MeanI.text = str(moyennes[2])
        self.manager.get_screen("bdres").ids.MeanA.text = str(moyennes[0])
        self.manager.get_screen("bdres").ids.Photo.source = ele_Etu[4]
        print(Etu)
    
    def emptySpinner(self):
        self.ids.spinner.text = "Choisissez un étudiant parmi la liste"


class Aide(Screen):
    def chngbckgrnd(self,x):
        self.ids['nav'+str(x)].background_color = 0, 0.6, 0.8, 1.0
    
    def restbckgrnd(self,x):
        self.ids['nav'+str(x)].background_color = "black"

    def disconnect(self):
        self.manager.get_screen("login").ids.error.size_hint = 0.1,0.1
        self.manager.get_screen("login").ids.error.text = ""
        self.manager.get_screen("login").ids.Login.text = ""
        self.manager.get_screen("login").ids.Password.text = ""
        pass

class Submit(Screen):
    response = ""
    def chngbckgrnd(self,x):
        self.ids['nav'+str(x)].background_color = 0, 0.6, 0.8, 1.0
        BD.items = DB.Get_Users()
    
    def restbckgrnd(self,x):
        self.ids['nav'+str(x)].background_color = "black"


class BDres(Screen):

    def chngbckgrnd(self,x):
        self.ids['nav'+str(x)].background_color = 0, 0.6, 0.8, 1.0
    
    def restbckgrnd(self,x):
        self.ids['nav'+str(x)].background_color = "black"

    def emptySpinner(self):
        self.manager.get_screen("bd").ids.spinner.text = "Choisissez un étudiant parmi la liste"

class MyScreenManager(ScreenManager):
    pass

class DossierEtudiant(App):
    def build(self):
        return MyScreenManager()

if __name__ == '__main__':
    DossierEtudiant().run()
