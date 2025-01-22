import sqlite3

con = sqlite3.connect('forum.db')
cursor = con.cursor()
cursor.execute("Insert into users()")
row = cursor.fetchone()
print(row[4])
con.commit()
con.close()