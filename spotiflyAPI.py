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
        database='SpotiflyDB'
    )

    return db


def user_exists(nickname):
    conn = db_connection()
    cur = conn.cursor()

    try:
        # Verificar se o usuário já existe na tabela de usuários
        cur.execute("SELECT COUNT(*) FROM users WHERE nickname = %s", (nickname))
        count = cur.fetchone()[0]

        if count > 0:
            return True  # O usuário já existe
        else:
            return False  # O usuário não existe

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'Error checking user existence: {error}')
        return False

    finally:
        if conn is not None:
            conn.close()


## Spotifly
##
## Add a new editora in a JSON payload
##
## To use it, you need to use postman or curl:
##
## curl -X POST http://localhost:8080/editora/ -H 'Content-Type: application/json' -d '{'Nome': 'Abril'}'
##

@app.route('/editora', methods=['POST'])
def add_editora():
    logger.info('POST /editora')
    payload = flask.request.get_json()

    conn = db_connection()
    cur = conn.cursor()

    logger.debug(f'POST /nome - payload: {payload}')

    # do not forget to validate every argument, e.g.,:
    if 'nome' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'nome value not in payload'}
        return flask.jsonify(response)

    # parameterized queries, good for security and performance
    statement = 'INSERT INTO editora (nome) VALUES (%s) RETURNING idlabel'
    values = (payload['nome'],)


    try:
        #cursor.execute('insert into bank_records values(%s,%s)', (deposit_amount, dt,))
        cur.execute(statement, values)
        id = cur.fetchone()[0]
        # commit the transaction
        conn.commit()
        response = {'status': StatusCodes['success'], 'results': f'Inserted editora {payload["nome"]}'}

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'POST /editora - error: {error}')
        response = {'status': StatusCodes['internal_error'], 'errors': str(error)}

        # an error occurred, rollback
        conn.rollback()

    finally:
        if conn is not None:
            conn.close()

    return flask.jsonify(response)


## Spotifly
##
## Add a new profiles in a JSON payload
##
## To use it, you need to use postman or curl:
##
## curl -X POST http://localhost:8080/profiles/ -H 'Content-Type: application/json' -d '{'Nome': 'Artista'}'
##

@app.route('/profiles', methods=['POST'])
def add_profiles():
    logger.info('POST /profiles')
    payload = flask.request.get_json()

    conn = db_connection()
    cur = conn.cursor()

    logger.debug(f'POST /name - payload: {payload}')

    # do not forget to validate every argument, e.g.,:
    if 'name' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'name value not in payload'}
        return flask.jsonify(response)

    # parameterized queries, good for security and performance
    statement = 'INSERT INTO profiles (name) VALUES (%s) RETURNING profileid'
    values = (payload['name'],)


    try:
        #cursor.execute('insert into bank_records values(%s,%s)', (deposit_amount, dt,))
        cur.execute(statement, values)
        id = cur.fetchone()[0]
        # commit the transaction
        conn.commit()
        response = {'status': StatusCodes['success'], 'results': f'Inserted profiles {payload["name"]}'}

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'POST /profiles - error: {error}')
        response = {'status': StatusCodes['internal_error'], 'errors': str(error)}

        # an error occurred, rollback
        conn.rollback()

    finally:
        if conn is not None:
            conn.close()

    return flask.jsonify(response)

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



def create_user(nickname, password,email,address,birthday):
    conn = db_connection()
    cur = conn.cursor()
    
    try:
        # Inserir informações do usuário na tabela de usuários
        cur.execute("INSERT INTO users (nickname, password, email, address,birthday) VALUES (%s, %s, %s, %s, %s)", (nickname, password,email,address, birthday))
        conn.commit()
        
        return True  # Indica que a criação de conta foi bem-sucedida
    
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'Error creating user: {error}')
        conn.rollback()
        return False  # Indica que ocorreu um erro ao criar a conta
    
    finally:
        if conn is not None:
            conn.close()


@app.route('/register', methods=['POST'])
def register():
    payload = flask.request.get_json()
    if 'nickname' not in payload or 'password' not in payload or 'email' not in payload or 'birthday' not in payload or 'address' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'nome value not in payload'}
        return flask.jsonify(response)
    
    nickname = payload['nickname']
    password = payload['password']
    email = payload['email']
    address = payload['address']
    birthday = payload['birthday']

    # Verificar se o usuário já existe
    if user_exists(nickname):
        response = {'error': 'O usuário já existe'}
        return flask.jsonify(response), 400

    # Validar a senha
    if not validate_password(password):
        response = {'error': 'A senha deve ter pelo menos 6 caracteres, incluindo letras maiúsculas, minúsculas e números'}
        return flask.jsonify(response), 400

    # Inserir informações do usuário no banco de dados
    if create_user(nickname, password, email, address, birthday):
        response = {'message': 'Registro de conta bem-sucedido'}
        return flask.jsonify(response), 200
    else:
        response = {'error': 'Erro ao registrar a conta'}
        return flask.jsonify(response), 500


def get_user_password(nickname):
    conn = db_connection()
    cur = conn.cursor()

    try:
        # Retrieve the password for the given nickname from the users table
        cur.execute("SELECT password FROM users WHERE nickname = %s", (nickname,))
        result = cur.fetchone()

        if result is not None:
            return result[0]  # Return the password

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'Error retrieving user password: {error}')

    finally:
        if conn is not None:
            conn.close()

    return None  # Return None if the password is not found or an error occurs

@app.route('/login', methods=['POST'])
def login():
    payload = flask.request.get_json()

    nickname = payload['nickname']
    password = payload['password']

    # Verificar se o usuário existe
    if not user_exists(nickname):
        response = {'error': 'Usuário não encontrado'}
        return flask.jsonify(response), 404

    # Obter a senha armazenada no banco de dados para o usuário
    stored_password = get_user_password(nickname)

    # Verificar se a senha fornecida corresponde à senha armazenada
    if password != stored_password:
        response = {'error': 'Senha incorreta'}
        return flask.jsonify(response), 401

    # Autenticação bem-sucedida
    response = {'message': 'Login bem-sucedido'}
    return flask.jsonify(response), 200


#@app.route('/musica',methods=['POST'])
#def criamusica():
#    logger.info('POST /musica')
#    payload = flask.request.get_json()
#    header = flask.request.headers.get('Authorization')
#    logger.debug(f'POST /musica - payload: {payload}')

#    if 'genre' not in payload or 'title' not in payload or 'duration' not in payload or 'other_artists' not in payload:
#        response = {'status': 'api_error', 'results': 'Missing required fields'}
#        return flask.jsonify(response)


def create_music(music_data):
    connection = db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            "INSERT INTO musica (titulo_musica, genero, duracao, data_de_lancamento, users_userid, editora_idlabel) "
            "VALUES (%s, %s, %s, %s, %s, %s) RETURNING idmusica",
            (music_data['titulo_musica'], music_data['genero'], music_data['duracao'],
             music_data['data_de_lancamento'], music_data['users_userid'], music_data['editora_idlabel'])
        )
        connection.commit()
        music_id = cursor.fetchone()[0]

        logger.info("Música criada com sucesso")
        logger.debug(f"Música ID: {music_id}")

        return music_id
    
    except Exception as e:
        logger.error(f"Error creating music: {e}")
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


@app.route('/musica', methods=['POST'])
def create_music_route():
    try:
        music_data = flask.request.get_json()
        music_id = create_music(music_data)
        response = {'message': 'Música criada com sucesso', 'music_id': music_id}
        return flask.jsonify(response), 201
    except Exception as e:
        logger.error(f"Error creating music: {e}")
        response = {'error': 'Erro ao criar música'}
        return flask.jsonify(response), 500


def create_editora(nome, endereco, telefone):
    conn = db_connection()
    cur = conn.cursor()

    try:
        cur.execute("INSERT INTO editora (nome, endereco, telefone) VALUES (%s, %s, %s) RETURNING ideditora",
                    (nome, endereco, telefone))
        conn.commit()
        editora_id = cur.fetchone()[0]

        logger.info("Editora criada com sucesso")
        logger.debug(f"ID da Editora: {editora_id}")

        return editora_id

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f"Erro ao criar editora: {error}")
        conn.rollback()
        raise

    finally:
        if conn is not None:
            conn.close()




if __name__ == '__main__':

    # set up logger
    logging.basicConfig(filename='log_file.log')
    logger = logging.getLogger('logger')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('%(asctime)s [%(levelname)s]:  %(message)s', '%H:%M:%S')
    ch.setFormatter(formatter)
    logger.addHandler(ch)


    host = '127.0.0.1'
    port = 8080
    app.run(host=host, debug=True, threaded=True, port=port)
    logger.info(f'API v1.0 online: http://{host}:{port}')
