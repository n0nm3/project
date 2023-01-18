import mysql.connector
import base64
import os

#Obtient les credential de connection
def Get_Cred(user,mdp):
    credential = (user,mdp)
    return credential

#connection à la base de donnée par authentification
def log(credentials):
    user = credentials[0]
    mdp = credentials[1]
    try:
        db = mysql.connector.connect(                   
                host = "localhost",                                   #hote de la bdd
                user = user,                                            #user pour se connecter 
                password = mdp,                                         #mdp pour se connecter
                database = "TEST"                                       #Base de donnée précédemment créer
            )               
    except mysql.connector.Error :                                      #Si mauvaise pair identifiant / mdp on renvoie une erreur
        print("Mauvaise pair identifiant / mot de passe")
        err = "Error!"
        return err
    else:                                                               #Sinon on dit que la connection est bonne
        print("connection succès")
        return db


#Exemple
#----------------------------------------------------------------------
# #Connection à la base de donnée simple
def connect():
    try:
        db = mysql.connector.connect(
            host = "localhost",
            user = "gigachad",
            password = "mdp",
            database = "TEST"
        )
    except mysql.connector.Error as e:
        print(f"Except : {e}")
        return "Error"
    else:
        return db

#----------------------------------------------------------------------

#Creation des tables dans la base de données
def create_tables(credentials):
    db = log(credentials)
    if db == "Error!":
        err = "Error"
        return err
    query = "USE TEST;"
    cursor = db.cursor(buffered=True)
    cursor.execute(query)
    query = "SHOW TABLES;"
    cursor.execute(query)
    table_1 = "CREATE TABLE etudiant(EtuID INT NOT NULL AUTO_INCREMENT, nom varchar(100), prenom varchar(100), annee int, photo BLOB, PRIMARY KEY (EtuID));"
    cursor.execute(table_1)
    table_2 = "CREATE TABLE Math(EtuID int, Moyenne_m float(4,2), Prof varchar(100),FOREIGN KEY (EtuID) REFERENCES etudiant(EtuID));"
    cursor.execute(table_2) 
    db.commit()
    table_3 = "CREATE TABLE Anglais(EtuID int, Moyenne_a float(4,2), Prof varchar(100), FOREIGN KEY (EtuID) REFERENCES etudiant(EtuID));"
    cursor.execute(table_3) 
    db.commit()
    table_4 = "CREATE TABLE Programmation(EtuID int, Moyenne_p float(4,2), Prof varchar(100), FOREIGN KEY (EtuID) REFERENCES etudiant(EtuID));"
    cursor.execute(table_4)
    db.commit()
    view = "CREATE VIEW Dos AS SELECT etudiant.EtuID, nom, prenom, annee, Moyenne_m/3+Moyenne_a/3+Moyenne_p/3 FROM etudiant,Anglais,Math,Programmation WHERE  Anglais.EtuID=Programmation.EtuID AND Anglais.EtuID=Math.EtuID AND etudiant.EtuID=Anglais.EtuID;"
    cursor.execute(view)
    db.commit()
    #for element in open("eleve.txt",'r'):
    #    print(element)
    #for element in cursor:
    #    print(element) 
    return cursor


def db_exist(credentials):
    db = log(credentials)
    if db == "Error!":
        err = "Error"
        return err
    cursor = db.cursor()
    query = "SHOW TABLES;"
    cursor.execute(query)
    r = cursor.fetchall()
    db.close()
    if len(r) == 0:
        create_tables(credentials)
    return len(r)

#print(db_exist(("gigachad","mdp")))



#Convertisseur d'image en binaire pour la photo de l'étudiant
def convertToBinaryData(filename):                                       
    with open(filename, 'rb') as file:                                   #Ouvre l'image en read binary
        blobData = file.read()                                           #met le fichier binaire dans une variable
    return blobData                                                      #revoie la variable

#Le adduser mais avec la photo fonctionnel
def Insert_stud(noms,annee,image, math, info, anglais):                                               
    db = connect()                                                          #Lance la fonction pour se connecter à la bdd
    *noms, prenom = noms.split()                                            #transforme en chaine de charactère le nom et le sépare en 2 variable nom et prénom
    print(noms)
    nom = ""                                                                
    for element in noms:                                                    #Récupérateur de nom pour eux ayant des espaces famille espacé
        nom += " " + element
    #nom, prenom = str(nom)                                                          
    cursor = db.cursor()                                                    #met le cursor dans la base de donnée
    if image != None:                                                       #si il y a une photo on la change en binaire 
        Photo = convertToBinaryData(image)                                  
    else:                                                                   #Autrement on ne fait rien
        Photo = None                                                        
    query = 'INSERT INTO etudiant (nom, prenom, annee, photo) VALUES (%s, %s, %s, %s);'  #On initie la query 
    try:                                                                    
        cursor.execute(query, (nom, prenom, annee, Photo))                          #On lance la query avec les paramètre
        db.commit()                                                                 #On commit notre query                                                          #Puis on ferme la connection à la bdd
    except mysql.connector.Error as e:                                      
        print(f'Problème provenant de {e}')                                 #Si il y a une erreur on la rend
    id = Get_id(nom,prenom)                                                      #puis on finit en insérant les moyennes
    profs = ('Hovsepian','Houssain','Wurbel')
    query = 'INSERT INTO Math(EtuID,Moyenne_m,prof) VALUES(%s, %s, %s)'
    cursor.execute(query,(id,math,profs[0]))
    db.commit()
    query = 'INSERT INTO Anglais(EtuID,Moyenne_a,prof) VALUES(%s, %s, %s)'
    cursor.execute(query,(id,anglais,profs[1]))
    db.commit()
    query = 'INSERT INTO Programmation(EtuID,Moyenne_p,prof) VALUES(%s, %s, %s)'
    cursor.execute(query,(id,info,profs[2]))
    db.commit()
    db.close()

#recuperation d'une photo depuis la bdd
def Get_photo(etu):
    db = connect()
    for element in Get_Users():
        if element != etu:
            pass
        else:
            if not os.path.exists('./Photo_etu'):
                os.mkdir('Photo_etu')
            *noms, prenom = etu.split()
            nom = ""
            for element in noms:                                                    #Récupérateur de nom pour eux ayant des espaces famille espacé
                nom += " " + element
            cursor = db.cursor()
            r = "done"
            query = f'SELECT * FROM etudiant WHERE nom="{nom}" AND prenom="{prenom}"'
            cursor.execute(query)
            etu = cursor.fetchall()
            for element in etu:
                print(element)
                Etu_id = element[0]
                nom = element[1]
                prenom = element[2]
                annee = element[3]
                photo = element[4]
            r = [Etu_id,nom,prenom,annee]
            r.append(None)
            if photo != None:
                dir_photo = str(os.getcwd()+'/Photo_etu'+'/photo_{}_{}_{}.png'.format(Etu_id,nom,annee))
                with open(dir_photo, "wb") as fd:
                    fd.write(photo)
                r.pop()
                r.append(dir_photo)
            return r


#Exemple
#----------------------------------------------------------------------
#permet d'obtenir les tables (script de test)
def Get_Tables():
    db = connect()
    cursor = db.cursor()
    query = f'SHOW tables;'
    cursor.execute(query)
    print(cursor)
    r = cursor.fetchall()
    print(r)
    db.close()
#----------------------------------------------------------------------





#permet d'obtenir tout les utilisateurs de la table etudiant
#----------------------------------------------------------------------
#def Get_Users():
#    db = connect()
#    cursor = db.cursor()
#    query = f'SELECT nom FROM etudiant'
#    cursor.execute(query)
#    e = cursor.fetchall()
#    db.close
#    r = []
#    for element in e:
#        r.append(element[0])
#    return r
#----------------------------------------------------------------------



#permet d'obtenir tout les utilisateurs(nom et prenom) de la table etudiant
def Get_Users():
    db = connect()
    cursor = db.cursor()
    query = f'SELECT nom,prenom FROM etudiant;'
    cursor.execute(query)
    print(cursor)
    e = cursor.fetchall()
    db.close
    i = 0
    r = []
    for element in e:
        i += 1
        nom = element[0] + " " + element[1]
        r.append(nom)
    return r
print(Get_Users())




#permet d'obtenir tout les attributs d'un utilisateur de la table etudiant
def Get_User(name):
    db = connect()
    nom, prenom = name
    cursor = db.cursor()
    query = f'SELECT * FROM etudiant where nom="{nom}" AND prenom={prenom}'
    cursor.execute(query)
    print(cursor)
    r = cursor.fetchall()
    db.close
    return r




#permet d'obtenir l'id d'un utilisateur de la table etudiant
def Get_id(nom,prenom):
    db = connect()
    cursor = db.cursor()
    query = f'SELECT EtuID FROM etudiant where nom="{nom}" AND prenom="{prenom}"'
    cursor.execute(query)
    r = None
    for element in cursor:
        r = element[0]
    db.close
    return r


#fonction pour obtenir la moyenne d'un étudiant
def Get_Moyennes(nom,prenom):
    db = connect()
    cursor = db.cursor()
    id = Get_id(nom,prenom)
    print(id)
    query = f'SELECT moyenne_m FROM Math WHERE EtuID="{id}";'
    cursor.execute(query)
    r = cursor.fetchall()
    for element in r:
        math = element
    print(math)
    query = f'SELECT moyenne_p FROM Programmation WHERE EtuID="{id}";'
    cursor.execute(query)
    r = cursor.fetchall()
    for element in r:
        prog = element
    query = f'SELECT moyenne_a FROM Anglais WHERE EtuID="{id}";'
    cursor.execute(query)
    r = cursor.fetchall()
    for element in r:
        Anglais = element
    moyennes=[Anglais,math,prog]
    return moyennes


#fonction permettant de lire un fichier blob(une photo) d'un étudiant 
def Read_Blob(Nom):
    db = connect()
    cursor = db.cursor()
    query = f'SELECT photo FROM etudiant WHERE nom="{Nom}";'
    cursor.execute(query)
    picture = cursor.fetchall()
    return picture


