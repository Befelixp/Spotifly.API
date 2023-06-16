from functools import wraps
import flask
import psycopg2
import logging
import datetime
import jwt
from flask import Flask, request, jsonify
from requests import session
from datetime import datetime, timedelta
import os
import json
import random

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


def check_jwt():
    # Gets token from request header and tries to get it's payload
    # Will raise errors if token is missing, invalid or expired 
    token = request.headers.get('Authorization')
    if not token:
        raise Exception('Missing access token')
    jwt = token.split('Bearer ')[1]
    try:
        return decode_jwt(jwt)
    except Exception as e:
        raise Exception(f'Invalid access token: {e}')

def auth_guard(roles=None):
    def wrapper(route_function):
        def decorated_function(*args, **kwargs):
            # Authentication gate
            try:
                user_data = check_jwt()
            except Exception as e:
                return jsonify({"message": f'{e}', "status": 401}), 401
            # Authorization gate
            if roles and not any(role in user_data['roles'] for role in roles):
                return jsonify({"message": 'Authorization required.', "status": 403}), 403
            
              
            # Proceed to original route function
            return route_function(*args, **kwargs)
        decorated_function.__name__ = route_function.__name__
        return decorated_function
    return wrapper

def autenticado(nickname,password):
    
    conn = db_connection()
    cur = conn.cursor()

    try:

        # Obter a senha armazenada no banco de dados para o usuário
        stored_password = get_user_password(nickname)

        if stored_password != password:
            return False

        # Pesquisar o usuário pelo email e senha fornecidos
        cur.execute("SELECT * FROM users WHERE nickname = %s", (nickname,))
        user = cur.fetchone()

        if user is not None:
            # Obter os perfis associados a esse usuário
            cur.execute("""SELECT up.users_userid,
	                    p.name
                          FROM profiles p,
  	                    users_profiles up
                        WHERE p.profileid = up.profiles_profileid
                        AND up.users_userid = %s""", (user[0],))
            
            
            profiles = cur.fetchall()

            # Construir o objeto de autenticação com as informações do usuário e perfis
            authentication = {
                'userid': user[0],
                'username': user[1],
                'roles': [profile[1] for profile in profiles]
            }

            return authentication
        else:
            return False

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'Error authenticating user: {error}')

    finally:
        if conn is not None:
            conn.close()

    return False  # Caso o usuário não seja autenticado ou ocorra um erro


def generate_jwt(payload):
    # Gerar um token JWT para o usuário
    if os.environ.get('JWT_EXPIRATION_DELTA'):
        intMinutes=int(os.environ.get('JWT_EXPIRATION_DELTA'))
        payload['exp'] = (datetime.now() + timedelta(minutes=intMinutes)).timestamp()
    return jwt.encode(payload, os.environ.get('SECRET_KEY'), algorithm="HS256")


def get_user_password(nickname):
    conn = db_connection()
    cur = conn.cursor()

    try:
        # Recuperar a senha para o nickname fornecido da tabela de usuários
        cur.execute("SELECT password FROM users WHERE nickname = %s", (nickname,))
        result = cur.fetchone()

        if result is not None:
            return result[0]  # Retorna a senha

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'Error retrieving user password: {error}')

    finally:
        if conn is not None:
            conn.close()

    return None  # Retorna None se a senha não for encontrada ou ocorrer um erro




def user_exists(nickname):
    conn = db_connection()
    cur = conn.cursor()

    statement = 'SELECT COUNT(*) FROM users WHERE nickname = %s'
    values = (nickname,)



        #cursor.execute('insert into bank_records values(%s,%s)', (deposit_amount, dt,))
      
    try:
        cur.execute(statement, values)
        # Verificar se o usuário já existe na tabela de usuários
        #cur.execute('SELECT COUNT(*) FROM users WHERE nickname = %s', nickname)
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

@app.route('/dbproj/user', methods=['POST'])
def register():
    payload = request.get_json()
    if 'nickname' not in payload or 'password' not in payload or 'email' not in payload or 'birthday' not in payload or 'address' not in payload:
        response = {'status': 'error', 'message': 'Invalid payload'}
        return jsonify(response), 400
    
    nickname = payload['nickname']
    password = payload['password']
    email = payload['email']
    address = payload['address']
    birthday = payload['birthday']

    # Verificar se o usuário já existe
    if user_exists(nickname):
        response = {'error': 'O usuário já existe'}
        return jsonify(response), 400

    # Validar a senha
    if not validate_password(password):
        response = {'error': 'A senha deve ter pelo menos 6 caracteres, incluindo letras maiúsculas, minúsculas e números'}
        return jsonify(response), 400

    user_id = create_user(nickname, password, email, address, birthday)
    # Inserir informações do usuário no banco de dados
    if user_id is not None:
        # Gerar token JWT para o usuário registrado

        response = {'status': StatusCodes['success'],'results' : f'User insert id = {user_id}'}
      
        return jsonify(response), 200
    else:
        response = {'error': 'Erro ao registrar a conta'}
        return jsonify(response), 500



@app.route('/dbproj/user', methods=['PUT'])
def login():
    payload = flask.request.get_json()

    nickname = payload['nickname']
    password = payload['password']
    
    if not nickname or not password:
        return jsonify({"message": "Nickname or password missing", "status": 400}), 400


    # Verificar se o usuário existe
    #if not user_exists(nickname):
    #    response = {'error': 'Usuário não encontrado'}
    #    return flask.jsonify(response), 404

    
    user_data = autenticado(nickname,password)


    if not user_data:
        return jsonify({"message": "Invalid credentials", "status": 400}), 400

    

    # Autenticação bem-sucedida, gerar token JWT
    token = generate_jwt(user_data)

    # Retornar o token JWT para o cliente
    response = {'token': token}
    return flask.jsonify(response), 200



@app.route('/dbproj/editora', methods=['POST'])
@auth_guard(['Admin','Artista'])
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
@auth_guard("Admin")
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
        
        cur.execute("SELECT userid FROM users WHERE nickname = %s", (nickname,))
        user_id = cur.fetchone()[0]
        return user_id  # Indica que a criação de conta foi bem-sucedida
    
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'Error creating user: {error}')
        conn.rollback()
        return None  # Indica que ocorreu um erro ao criar a conta
    
    finally:
        if conn is not None:
            conn.close()

    
def generate_token(username):
    token = jwt.encode({'username': username}, os.environ.get('SECRET_KEY'), algorithm='HS256')
    return token.decode('utf-8')

def verify_token(token):
    try:
        decoded_token = jwt.decode(token, os.environ.get('SECRET_KEY'), algorithms=['HS256'])
        username = decoded_token['username']
        return username
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def decode_jwt(token):
    # Tries to retrieve payload information inside of a existent JWT token (string)
    # Will throw an error if the token is invalid (expired or inconsistent)
    return jwt.decode(token, os.environ.get('SECRET_KEY'), algorithms=["HS256"])



def verifica_perfil(nickname):
    #Preciso verificar a tabela de perfis e a tabela de subscriçao para aquele userid
    #Na tabela de perfis verifico se é artista e se é adminstrador
    #Na tabela de subscriçao verifico se é VIP
    #Exemplo: Se o user 'jpedro' for artista tem um perfil de artista e se ao mesmo tempo
    # for um subcstritor ativo tambem será um VIP assim sendo temos a session
    # session['user_persmissions'] =  ['artista', 'vip']
    # session['user_permissions']  = ['administrator', 'artista']
    session['user_permissions']  = [ 'artista','vip']


@app.route('/dbproj/song', methods=['POST'])
@auth_guard(['Admin'])
def add_song():

    try:

        # Obter os dados da requisição
        data = request.get_json()
        song_name = data['song_name']
        release_date = data['release_date']
        publisher_id = data['publisher']
        other_artists = data['other_artists']

        # Salvar a música no banco de dados
        song_id = save_song(song_name, release_date, publisher_id, other_artists)

        # Responder com o ID da música criada
        response = {
            'status': 200,
            'errors': None,
            'results': song_id
        }
        return jsonify(response)
    except Exception as e:
        # Tratar exceções
        logger.error(str(e))
        response = {
            'status': 500,
            'errors': str(e),
            'results': None
        }
        return jsonify(response)

def save_song(song_name, release_date, publisher_id, other_artists):
    conn = db_connection()
    cur = conn.cursor()

    # Inserir a música na tabela "musica"
    cur.execute(
        "INSERT INTO musica (titulo_musica, data_de_lancamento, users_userid) "
        "VALUES (%s, %s, %s) RETURNING idmusica",
        (song_name, release_date, publisher_id)
    )
    song_id = cur.fetchone()[0]

    # Inserir os artistas adicionais na tabela de relacionamento "musica_artistas"
    for artist_id in other_artists:
        cur.execute(
            "INSERT INTO musica_artistas (musica_idmusica, artistas_artistid) "
            "VALUES (%s, %s)",
            (song_id, artist_id)
        )

    conn.commit()
    conn.close()

    return song_id

def user_exists_by_id(user_id):
    conn = db_connection()
    cur = conn.cursor()

    try:
        # Verificar se o usuário existe na tabela de usuários
        cur.execute("SELECT COUNT(*) FROM users WHERE userid = %s", (user_id,))
        count = cur.fetchone()[0]

        if count > 0:
            return True  # O usuário existe
        else:
            return False  # O usuário não existe

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'Error checking user existence: {error}')
        return False

    finally:
        if conn is not None:
            conn.close()


@app.route('/user/<int:user_id>', methods=['GET'])
@auth_guard()
def get_user(user_id):
    if user_exists_by_id(user_id):
        conn = db_connection()
        cur = conn.cursor()

        try:
            # Obter os detalhes do usuário a partir do ID
            cur.execute("SELECT * FROM users WHERE userid = %s", (user_id,))
            user = cur.fetchone()

            # Converter a linha de resultado em um dicionário
            user_details = {
                'user_id': user[0],
                'name': user[1],
                'email': user[2],
                # Adicionar outros campos do usuário, se houver
            }

            response = {'user': user_details}
            return flask.jsonify(response), 200

        except (Exception, psycopg2.DatabaseError) as error:
            logger.error(f'Error retrieving user details: {error}')
            response = {'error': 'Erro ao obter os detalhes do usuário'}
            return flask.jsonify(response), 500

        finally:
            if conn is not None:
                conn.close()

    else:
        response = {'error': 'Usuário não encontrado'}
        return flask.jsonify(response), 404


def profile_exists_by_id(profile_id):
    conn = db_connection()
    cur = conn.cursor()

    try:
        # Verificar se o perfil existe na tabela de perfis
        cur.execute("SELECT COUNT(*) FROM profiles WHERE profileid = %s", (profile_id,))
        count = cur.fetchone()[0]

        if count > 0:
            return True  # O perfil existe
        else:
            return False  # O perfil não existe

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'Error checking profile existence: {error}')
        return False

    finally:
        if conn is not None:
            conn.close()

@app.route('/profile/<int:profile_id>', methods=['GET'])
def get_profile(profile_id):
    if profile_exists_by_id(profile_id):
        conn = db_connection()
        cur = conn.cursor()

        try:
            # Obter os detalhes do perfil a partir do ID
            cur.execute("SELECT * FROM profiles WHERE profileid = %s", (profile_id,))
            profile = cur.fetchone()

            # Converter a linha de resultado em um dicionário
            profile_details = {
                'profile_id': profile[0],
                'name': profile[1],
                # Adicionar outros campos do perfil, se houver
            }

            response = {'profile': profile_details}
            return flask.jsonify(response), 200

        except (Exception, psycopg2.DatabaseError) as error:
            logger.error(f'Error retrieving profile details: {error}')
            response = {'error': 'Erro ao obter os detalhes do perfil'}
            return flask.jsonify(response), 500

        finally:
            if conn is not None:
                conn.close()

    else:
        response = {'error': 'Perfil não encontrado'}
        return flask.jsonify(response), 404

def create_user_profile(user_id, profile_id):
    conn = db_connection()
    cur = conn.cursor()

    try:
        # Verificar se o usuário e o perfil existem
        cur.execute("SELECT COUNT(*) FROM users WHERE userid = %s", (user_id,))
        user_exists = cur.fetchone()[0] > 0

        cur.execute("SELECT COUNT(*) FROM profiles WHERE profileid = %s", (profile_id,))
        profile_exists = cur.fetchone()[0] > 0

        if not user_exists:
            raise Exception(f"User with ID {user_id} does not exist")
        
        if not profile_exists:
            raise Exception(f"Profile with ID {profile_id} does not exist")

        # Verificar se a associação já existe
        cur.execute(
            "SELECT COUNT(*) FROM users_profiles WHERE users_userid = %s AND profiles_profileid = %s",
            (user_id, profile_id)
        )
        association_exists = cur.fetchone()[0] > 0

        if association_exists:
            raise Exception("User and profile association already exists")

        # Criar a associação entre o usuário e o perfil
        cur.execute(
            "INSERT INTO users_profiles (users_userid, profiles_profileid) VALUES (%s, %s)",
            (user_id, profile_id)
        )

        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

@app.route('/users_profiles', methods=['POST'])
def add_users_profiles():
    logger.info('POST /users_profiles')
    payload = flask.request.get_json()

    conn = db_connection()
    cur = conn.cursor()

    logger.debug(f'POST /users_profiles - payload: {payload}')

    if 'users_userid' not in payload or 'profiles_profileid' not in payload:
        response = {'status': StatusCodes['api_error'], 'results': 'users_userid or profiles_profileid value not in payload'}
        return flask.jsonify(response)

    try:
        user_id = payload['users_userid']
        profile_id = payload['profiles_profileid']

        if user_exists_by_id(user_id) and profile_exists_by_id(profile_id):
            if create_user_profile(user_id, profile_id):
                response = {'status': StatusCodes['success'], 'results': 'Perfil de usuário criado com sucesso'}
            else:
                response = {'status': StatusCodes['internal_error'], 'errors': 'Erro ao criar perfil de usuário'}
        else:
            response = {'status': StatusCodes['api_error'], 'errors': 'user_id or profile_id not found'}

        return flask.jsonify(response)

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'POST /users_profiles - error: {error}')
        response = {'status': StatusCodes['internal_error'], 'errors': str(error)}

        conn.rollback()

    finally:
        if conn is not None:
            conn.close()


import logging

@app.route('/dbproj/card', methods=['POST'])
@auth_guard(['Admin'])
def generate_cards():
    try:
        user_data = check_jwt()
        data = request.get_json()
        conn = db_connection()
        cur = conn.cursor()
        number_cards = int(data['number_cards'])
        card_price = int(data['card_price'])
        cards = []

        for _ in range(number_cards):
            cardnumber = generate_card_id()
            card_info = {
                'cardnumber': cardnumber,
                'price': card_price,
                'userid': user_data['userid']
            }
            cards.append(save_card_info(card_info))
        
        results = [card[0] for card in cards]
        response = {
            'status': 200,
            'errors': None,
            'results': results
        }
        return jsonify(response)
    except Exception as e:
        logging.error(f"An error occurred during card generation: {str(e)}")
        response = {
            'status': 500,
            'errors': 'An error occurred during card generation',
            'results': []
        }
        return jsonify(response), 500


def generate_card_id():
    return random.randint(100000, 999999)


def save_card_info(card_info):
    try:
        conn = db_connection()
        cur = conn.cursor()
        query = "INSERT INTO cartao (cardnumber, saldo, users_userid) VALUES (%s, %s, %s) RETURNING cardid"
        values = (card_info['cardnumber'], card_info['price'], card_info['userid'])
        cur.execute(query, values)
        cardIdCreated = cur.fetchall()[0]
        conn.commit()
        return cardIdCreated
    except Exception as e:
        logging.error(f"An error occurred while saving card information: {str(e)}")
        raise


def get_all_cards():
    try:
        query = "SELECT cardid FROM cartao"
        conn = db_connection()
        cur = conn.cursor()
        cur.execute(query)
        return cur.fetchall()
    except Exception as e:
        logging.error(f"An error occurred while retrieving all cards: {str(e)}")
        raise


# Função para verificar a existência de um usuário
def verificar_existencia_usuario(users_userid):
    try:
        conn = db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE userid = %s", (users_userid,))
        count = cursor.fetchone()[0]
        return count > 0
    except Exception as e:
        logging.error(f"An error occurred while verifying user existence: {str(e)}")
        raise
    finally:
        conn.close()






def create_users_musica(user_id, music_id):
    conn = db_connection()
    cur = conn.cursor()

    try:
        cur.execute("INSERT INTO users_musica (users_userid, musica_idmusica) VALUES (%s, %s)", (user_id, music_id))
        conn.commit()

        logger.info("Relacionamento entre usuário e música criado com sucesso")
        return True

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f"Erro ao criar relacionamento entre usuário e música: {error}")
        conn.rollback()
        return False

    finally:
        if conn is not None:
            conn.close()

def music_exists_by_id(music_id):
    conn = db_connection()
    cur = conn.cursor()

    try:
        # Check if the music exists in the music table
        cur.execute("SELECT COUNT(*) FROM musica WHERE idmusica = %s", (music_id,))
        count = cur.fetchone()[0]

        if count > 0:
            return True  # The music exists
        else:
            return False  # The music does not exist

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(f'Error checking music existence: {error}')
        return False

    finally:
        if conn is not None:
            conn.close()


@app.route('/users/musica', methods=['POST'])
def criar_relacionamento():
    try:
        user_id = flask.request.json['users_userid']
        music_id = flask.request.json['musica_idmusica']

        # Verifica se o user_id e o music_id existem
        if user_exists_by_id(user_id) and music_exists_by_id(music_id):
            if create_users_musica(user_id, music_id):
                logger.info('Relacionamento criado com sucesso')
                return flask.jsonify({'message': 'Relacionamento criado com sucesso'}), 201
            else:
                logger.error('Erro ao criar relacionamento')
                return flask.jsonify({'message': 'Erro ao criar relacionamento'}), 500
        else:
            logger.debug('UserID ou MusicID inexistente')
            return flask.jsonify({'message': 'UserID ou MusicID inexistente'}), 500

    except KeyError:
        logger.error('Dados inválidos')
        return flask.jsonify({'message': 'Dados inválidos'}), 400


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


