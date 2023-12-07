from src.config import Config
from src.extension import db
import mysql.connector


def fetch_data(query_string):
    if db.connection is None:
        con = get_connection_outside_flask_app()
    else:
        con = db.connection

    cur = con.cursor()
    use_db = 'Use ' + Config.KEYCLOAK_MYSQL_DB
    cur.execute(use_db)
    cur.execute(query_string)
    data = cur.fetchall()
    cur.close()
    return data


def get_connection_outside_flask_app():
    config = {
        'user': 'root',
        'password': 'myoianhyeuemnl',
        'host': 'localhost',
        'database': 'keycloak',
    }

    # Establish a connection to the MySQL server
    connection = mysql.connector.connect(**config)
    print("okok321",connection)
    return connection
