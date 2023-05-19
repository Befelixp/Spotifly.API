import flask
import psycopg2
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
        database='DBPROJECT'
    )

    return db


def user_exists(username):
    conn = db_connection()
    cur = conn.cursor()

    try:
        # Verificar se o usuário já existe na tabela de usuários
        cur.execute("SELECT COUNT(*) FROM users WHERE nickname = %s", (username))
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

    username = payload['nickname']
    password = payload['password']
    email = payload['email']
    name = payload['name']
    address = payload['address']
    birthday = payload['birthday']

    # Verificar se o usuário já existe
    if user_exists(username):
        response = {'error': 'O usuário já existe'}
        return flask.jsonify(response), 400

    # Validar a senha
    if not validate_password(password):
        response = {'error': 'A senha deve ter pelo menos 6 caracteres, incluindo letras maiúsculas, minúsculas e números'}
        return flask.jsonify(response), 400

    # Inserir informações do usuário no banco de dados
    if create_user(username, password, email, name, address, birthday):
        response = {'message': 'Registro de conta bem-sucedido'}
        return flask.jsonify(response), 200
    else:
        response = {'error': 'Erro ao registrar a conta'}
        return flask.jsonify(response), 500


def get_user_password(username):
    conn = db_connection()
    cur = conn.cursor()

    try:
        # Retrieve the password for the given username from the users table
        cur.execute("SELECT password FROM users WHERE username = %s", (username,))
        result = cur.fetchone()

        if result is not None:
            return result[0]  # Return the password

    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(f'Error retrieving user password: {error}')

    finally:
        if conn is not None:
            conn.close()

    return None  # Return None if the password is not found or an error occurs

@app.route('/login', methods=['POST'])
def login():
    payload = flask.request.get_json()

    username = payload['username']
    password = payload['password']

    # Verificar se o usuário existe
    if not user_exists(username):
        response = {'error': 'Usuário não encontrado'}
        return flask.jsonify(response), 404

    # Obter a senha armazenada no banco de dados para o usuário
    stored_password = get_user_password(username)

    # Verificar se a senha fornecida corresponde à senha armazenada
    if password != stored_password:
        response = {'error': 'Senha incorreta'}
        return flask.jsonify(response), 401

    # Autenticação bem-sucedida
    response = {'message': 'Login bem-sucedido'}
    return flask.jsonify(response), 200



