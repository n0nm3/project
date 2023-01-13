import mysql.connector



db = mysql.connector.connect(
        host="localhost",
<<<<<<< HEAD
        user="gigachad",
        password="mdp",
        database="Formulaire"
=======
        user="kali",
        password="kali"
        #database="Formulaire"
>>>>>>> a78e0c768a109d72386d426a3e4c2e9c27cc1047
)

class database():
    def __init__(self):
        self.cursor = db.cursor
    def get_etudiant(self):
        etu = etu.root      #faut caller l'id de l'étudiant définit dans kivy
        query = f"SELECT * from etudiant where NomEtu={etu}"
        r = db.cursor.execute(query)
        db.close
        return r
    def get_list(self):
        query = f"SELECT * from etudiant"
        r = db.cursor.execute(query)
        db.close
        return r
        

def main():
    cursor = db.cursor()
    query = 'SELECT * FROM Form2'
    r = cursor.execute(query)
    return r



    main()
