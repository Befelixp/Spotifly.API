import flask
import psycopg2
import logging
import time
import logging


app = flask.Flask(__name__)

StatusCodes = {
    'success': 200,
    'api_error': 400,
    'internal_error': 500
}


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


def user_exists(username):
    conn = db_connection()
    cur = conn.cursor()

    try:
        # Verificar se o usuário já existe na tabela de usuários
        cur.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
        count = cur.fetchone()[0]

        if count > 0:
            return True  # O usuário já existe
        else:
            return False  # O usuário não existe

    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(f'Error checking user existence: {error}')
        return False

    finally:
        if conn is not None:
            conn.close()


def validate_password(password):
    # Verificar se a senha possui pelo menos 6 caracteres
    if len(password) < 6:
        return False

    # Verificar se a senha contém letras maiúsculas, minúsculas e números
    has_uppercase = any(char.isupper() for char in password)
    has_lowercase = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)

    if not (has_uppercase and has_lowercase and has_digit):
        return False

    return True



def create_user(username, password,email,name,address):
    conn = db_connection()
    cur = conn.cursor()
    
    try:
        # Inserir informações do usuário na tabela de usuários
        cur.execute("INSERT INTO users (username, password, email, name, address) VALUES (%s, %s, %s, %s, %s)", (username, password,email,name,address))
        conn.commit()
        
        return True  # Indica que a criação de conta foi bem-sucedida
    
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(f'Error creating user: {error}')
        conn.rollback()
        return False  # Indica que ocorreu um erro ao criar a conta
    
    finally:
        if conn is not None:
            conn.close()


@app.route('/register', methods=['POST'])
def register():
    
    payload = flask.request.get_json()

    username= payload['nickname']
    password= payload['password']
    email = payload['email']
    name = payload['name']
    address = payload['address']
    birthday = payload['birthday']



    


