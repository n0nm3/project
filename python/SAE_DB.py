import mysql.connector
import base64


#Connection à la base de donnée
def connect():
    try:
        db = mysql.connector.connect(
            host = "10.97.85.41",
            user = "gigachad",
            password = "mdp",
            database = "TEST"
        )
    except mysql.connector.Error as e:
        print(f"Except : {e}")
    else:
        return db

#Convertisseur d'image en binaire pour la photo de l'étudiant
def convertToBinaryData(filename):
    with open(filename, 'rb') as file:
        blobData = file.read()
    return blobData


#Le adduser mais avec la photo fonctionnel
def Convert_png(nom,annee,image):
    db = connect()
    nom = str(nom)
    cursor = db.cursor()
    if image != None:
        Photo = convertToBinaryData(image)
    else:
        Photo = None
    query = 'INSERT INTO etudiant (nom, annee, foto) VALUES (%s, %s, %s)'
    try:
        cursor.execute(query, (nom, annee, Photo))
        db.commit()
        db.close()
    except mysql.connector.Error as e:
        print(f'Problème provenant de {e}')

def Get_Tables():
    db = connect()
    cursor = db.cursor()
    query = f'SHOW tables;'
    cursor.execute(query)
    print(cursor)
    r = cursor.fetchall()
    print(r)
    db.close()

def Get_Users():
    db = connect()
    cursor = db.cursor()
    query = f'SELECT * FROM etudiant'
    cursor.execute(query)
    print(cursor)
    r = cursor.fetchall()
    print(r)
    db.close

def Get_User(name):
    db = connect()
    cursor = db.cursor()
    query = f'SELECT * FROM etudiant where nom="{name}"'
    cursor.execute(query)
    print(cursor)
    r = cursor.fetchall()
    print(r)
    db.close

def Get_id(name):
    db = connect()
    cursor = db.cursor()
    query = f'SELECT EtuID FROM etudiant where nom="{name}"'
    cursor.execute(query)
    for element in cursor:
        r = element[0]
    db.close
    return r

"""
#Fonction optionnel 
def Get_Moyenne(name):
    db = connect()
    cursor = db.cursor()
    query = f'SELECT * FROM etudiant where nom={name};'
    cursor.execute(query)
    id = 1
    return id
    #query = f'SELECT * from matiere where id_etu={id};'
    #return id
"""

def Add_Etu(nom,année,photo):
    db = connect()
    cursor = db.cursor()
    query = f'INSERT INTO etudiant (nom,annee,foto) VALUES ("{nom}",{année},{photo});'
    print(query)
    cursor.execute(query)
    db.commit()
    db.close()

def Read_Blob(Nom):
    db = connect()
    cursor = db.cursor()
    query = f'SELECT foto FROM etudiant WHERE name = {Nom}'
    cursor.execute(query)
    return Nom


print(Get_User('Toto'))
#print(Get_Users())
print(Get_id('Test'))
Read_Blob('Test')
#Convert_png("Test", 2001, "/users/stud/2A/collot/Bureau/table.png")