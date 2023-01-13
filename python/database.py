import mysql.connector



mydb = mysql.connector.connect(
        host="localhost",
        user="gigachad",
        password="mdp",
        database="Formulaire"
)


def main():
    cursor = db.cursor()
    query = 'SELECT * FROM Form2'
    r = cursor.execute(query)
    return r



    main()
