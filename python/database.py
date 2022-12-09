import mysql.connector



mydb = mysql.connector.connect(
        host="localhost",
        user="kali",
        password="kali",
        database="Formulaire"
)


def main():
    cursor = db.cursor()
    query = 'SELECT * FROM Form2'
    r = cursor.execute(query)
    return r





if '__name__' == '__main__':
    main()
