from app import app
import psycopg2


##########################################################
## DATABASE ACCESS
##########################################################

def db_connection():
    db = psycopg2.connect(
        user='aulaspl',
        password='aulaspl',
        host='127.0.0.1', # não sei se ta certo
        port='5432',
        database='ProjetoBD'
    )

    return db

 
# MySQL configurations
app.config['PG_DATABASE_USER'] = 'aulaspl'
app.config['PG_DATABASE_PASSWORD'] = 'aulaspl'
app.config['PG_DATABASE_DB'] = 'ProjetoBD'
app.config['PG_DATABASE_HOST'] = '127.0.0.1'
app.config['PG_PORT'] = '127.0.0.1'
mysql.init_app(app)

