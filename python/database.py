import mysql.connector



db = mysql.connector.connect(
        host="localhost",
        user="kali",
        password="kali"
        #database="Formulaire"
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





if '__name__' == '__main__':
    main()
