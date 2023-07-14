from datetime import date, timedelta
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
from dateutil.relativedelta import relativedelta

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
@auth_guard(['Admin'])
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



@app.route('/dbproj/addartist', methods=['PUT'])
@auth_guard(['Admin'])
def add_artist():
    try:
        data = request.get_json()
        userid = data['userid']
        artisticname = data['artisticname']
        conn = db_connection()
        cur = conn.cursor()

        cur.execute(
            """UPDATE users 
            SET artisticname=%s
            WHERE userid=%s""",
            (artisticname, userid)
        )
        conn.commit()
        cur.execute(
            "INSERT INTO users_profiles (users_userid, profiles_profileid) "
            "VALUES (%s, %s)",
            (userid, 3)
        )
        conn.commit()

        response = {
            'status': 200,
            'errors': None,
            'results': f"Usuário: {userid} agora é artista"
        }
        return jsonify(response)

    except Exception as e:
        logger.error(str(e))
        response = {
            'status': 500,
            'errors': str(e),
            'results': None
        }
        return jsonify(response)


@app.route('/dbproj/song', methods=['POST'])
@auth_guard(['Artista'])
def add_song():

    try:

        # Obter os dados da requisição
        data = request.get_json()
        song_name = data['song_name']
        release_date = data['release_date']
        publisher_id = data['publisher']
        other_artists = data['other_artists']
        genero = data['genero']
        duracao = data['duracao']

        # Salvar a música no banco de dados
        song_id = save_song(song_name, release_date, publisher_id, other_artists,genero,duracao)

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

def save_song(song_name, release_date, publisher_id, other_artists,genero,duracao):
    conn = db_connection()
    cur = conn.cursor()
    user_data = check_jwt()
    # Inserir a música na tabela "musica"
    cur.execute(
        "INSERT INTO musica (titulo_musica, data_de_lancamento, editora_idlabel, users_userid, genero,duracao) "
        "VALUES (%s, %s, %s, %s, %s, %s) RETURNING idmusica",
        (song_name, release_date, publisher_id, user_data['userid'],genero, duracao)
    )
    song_id = cur.fetchone()[0]

    # Inserir os artistas adicionais na tabela de relacionamento "musica_artistas"
    for artist_id in other_artists:
        cur.execute(
            "INSERT INTO users_musica (musica_idmusica, users_userid) "
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
        vencimento = data['vencimento']
        cards = []

        if card_price not in [10,25,50]:
            raise Exception('Invalid price for card')

        for _ in range(number_cards):
            cardnumber = generate_card_id()
            card_info = {
                'cardnumber': cardnumber,
                'price': card_price,
                'userid': user_data['userid'],
                'vencimento': vencimento
            }
            cards.append(save_card_info(card_info))
        
        results = [card for card in cards]
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
    return random.randrange(10**16, 10**17)


def save_card_info(card_info):
    try:
        conn = db_connection()
        cur = conn.cursor()
        query = "INSERT INTO cartao (cardnumber, saldo, valor, users_userid, vencimento) VALUES (%s, %s, %s,%s, %s) RETURNING cardid"
        values = (card_info['cardnumber'], card_info['price'],card_info['price'], card_info['userid'],card_info['vencimento'])
        cur.execute(query, values)
        cardIdCreated = cur.fetchone()[0]
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


@app.route('/dbproj/playlist', methods=['POST'])
@auth_guard()
def create_playlist():
    try:
        data = request.get_json()
        playlist_name = data.get('playlist_name')
        visibility = data.get('visibility')
        songs = data.get('songs')
        current_user = check_jwt()

        # Verify if playlist_name, visibility, and songs are provided
        if not playlist_name or not visibility or not songs:
            raise Exception('Playlist name, visibility, and songs are required')

        # Verify if the user is a premium consumer
        if not is_premium_user():
            raise Exception('Only premium consumers can create playlists')

        conn = db_connection()
        cur = conn.cursor()
        if visibility == "private":
            visibilidade = False
        elif visibility == "public":
            visibilidade = True
        else:
            raise Exception('Invalid visibility value')

        # Insert the playlist data into the database
        cur.execute(
            """INSERT INTO playlist (nome_da_playlist, privada, users_userid)
               VALUES (%s, %s, %s)
               RETURNING idplaylist""",
            (playlist_name, visibilidade, current_user['userid'])
        )
        playlist_id = cur.fetchone()[0]

        # Insert the songs into the playlist
        for song_id in songs:
            cur.execute(
                """INSERT INTO posicaoplay (playlist_idplaylist, musica_idmusica)
                   VALUES (%s, %s)""",
                (playlist_id, song_id)
            )

        conn.commit()
        conn.close()

        response = {
            'status': 200,
            'errors': None,
            'results': playlist_id
        }
        return jsonify(response)

    except Exception as e:
        logging.error(str(e))
        response = {
            'status': 500,
            'errors': str(e),
            'results': None
        }
        return jsonify(response)


def is_premium_user():
    user_data = check_jwt()
    user_id = user_data['userid']
    
    conn = db_connection()
    cur = conn.cursor()

    cur.execute("SELECT active FROM subscriptions WHERE users_userid = %s", (user_id,))
    subscription = cur.fetchone()

    if subscription:
        active = subscription[0]
        return active if active is not None else False
    else:
        # Usuário não possui uma assinatura
        return False

@app.route('/dbproj/artist_info/<artist_id>', methods=['GET'])
@auth_guard()
def get_artist_info(artist_id):
    try:
        conn = db_connection()
        cur = conn.cursor()
    	
        # Retrieve artist's name
        cur.execute("SELECT artisticname FROM users WHERE userid = %s", (artist_id,))
        artist_name = cur.fetchone()[0]

        # Retrieve artist's songs
        cur.execute("""
            SELECT idmusica
            FROM musica
            WHERE users_userid = %s
        """, (artist_id,))
        songs = [row[0] for row in cur.fetchall()]

        # Retrieve artist's albums
        cur.execute("""
            SELECT albumid
            FROM album
            WHERE users_userid = %s
        """, (artist_id,))
        albums = [row[0] for row in cur.fetchall()]

        # Retrieve public playlists containing the artist's songs
        cur.execute("""
            SELECT p.idplaylist
            FROM playlist p
            INNER JOIN posicaoplay pp ON p.idplaylist = pp.playlist_idplaylist
            INNER JOIN musica m ON pp.musica_idmusica = m.idmusica
            WHERE p.privada = FALSE AND m.users_userid = %s
        """, (artist_id,))
        playlists = [row[0] for row in cur.fetchall()]

        conn.close()

        artist_info = {
            'name': artist_name,
            'songs': songs,
            'albums': albums,
            'playlists': playlists
        }

        response = {
            'status': 200,
            'errors': None,
            'results': artist_info
        }
        return jsonify(response)

    except Exception as e:
        logging.error(str(e))
        response = {
            'status': 500,
            'errors': str(e),
            'results': None
        }
        return jsonify(response)

@app.route('/dbproj/comments/<song_id>', methods=['POST'])
@auth_guard()
def add_comment(song_id):
    try:
        conn = db_connection()
        cur = conn.cursor()
        current_user = check_jwt()
        comment = request.json.get('comment')

        # Insert the comment into the database
        cur.execute("""
            INSERT INTO comentarios (comentario, musica_idmusica, users_userid,)
            VALUES (%s, %s, %s,%s,%s,%s)
            RETURNING idcomentario
        """, (comment, song_id, current_user['userid'],0,0,0))
        comment_id = cur.fetchone()[0]
        conn.commit()
        conn.close()

        response = {
            'status': 200,
            'errors': None,
            'results': comment_id
        }
        return jsonify(response)

    except Exception as e:
        logging.error(str(e))
        response = {
            'status': 500,
            'errors': str(e),
            'results': None
        }
        return jsonify(response)


@app.route('/dbproj/comments/<song_id>/<parent_comment_id>', methods=['POST'])
@auth_guard()
def reply_to_comment(song_id, parent_comment_id):
    try:
        conn = db_connection()
        cur = conn.cursor()
        current_user = check_jwt()

        comment = request.json.get('comment')

        # Insert the reply comment into the database
        cur.execute("""
            INSERT INTO comentarios (comentario, musica_idmusica, users_userid, comentarios_idcomentario)
            VALUES (%s, %s, %s, %s)
            RETURNING idcomentario
        """, (comment, song_id, current_user['userid'], parent_comment_id))
        comment_id = cur.fetchone()[0]
        conn.commit()
        conn.close()

        response = {
            'status': 200,
            'errors': None,
            'results': comment_id
        }
        return jsonify(response)

    except Exception as e:
        logging.error(str(e))
        response = {
            'status': 500,
            'errors': str(e),
            'results': None
        }
        return jsonify(response)


@app.route('/dbproj/song/<keyword>', methods=['GET'])
@auth_guard()
def search_song(keyword):
    try:
        conn = db_connection()
        cur = conn.cursor()

        # SQL query to retrieve songs that contain the provided keyword
        cur.execute("""
            SELECT m.titulo_musica, array_agg(u.artisticname) AS artists, array_agg(a.albumid) AS albums
            FROM musica m
            LEFT JOIN users_musica um ON m.idmusica = um.musica_idmusica
            LEFT JOIN users u ON um.users_userid = u.userid
            LEFT JOIN musica_album ma ON m.idmusica = ma.musica_idmusica
            LEFT JOIN album a ON ma.album_albumid = a.albumid
            WHERE m.titulo_musica ILIKE %s
            GROUP BY m.idmusica
        """, ('%' + keyword + '%',))

        results = []
        for row in cur.fetchall():
            song_title = row[0]
            artists = row[1] or []  # If there are no associated artists, return an empty list
            albums = row[2] or []  # If there are no associated albums, return an empty list

            song_data = {
                'title': song_title,
                'artists': artists,
                'albums': albums
            }
            results.append(song_data)

        conn.close()

        response = {
            'status': 200,
            'errors': None,
            'results': results
        }
        return jsonify(response)

    except Exception as e:
        logging.error(str(e))
        response = {
            'status': 500,
            'errors': str(e),
            'results': None
        }
        return jsonify(response)

@app.route('/dbproj/album', methods=['POST'])
@auth_guard(['Artista'])
def add_album():
    try:
        data = request.get_json()
        album_name = data.get('name')
        release_date = data.get('release_date')
        publisher_id = data.get('publisher')
        songs = data.get('songs')
        lenmusica = len(songs)
        user_data= check_jwt()
        userid = user_data['userid']

        # Validate required fields
        if not album_name or not release_date or not publisher_id or not songs:
            raise Exception('Missing required fields')

        conn = db_connection()
        cur = conn.cursor()
        
        # Insert album into the database
        cur.execute(
            "INSERT INTO album (nomealbum, lancamento, editora_idlabel,users_userid,lenmusicas) VALUES (%s, %s, %s, %s,%s) RETURNING albumid",
            (album_name, release_date, publisher_id,userid,lenmusica)
        )
        album_id = cur.fetchone()[0]

        # Insert songs into the database and associate them with the album
        for song in songs:

            if isinstance(song, dict):
                # New song with details provided
                song_name = song.get('song_name')
                song_release_date = song.get('release_date')
                song_publisher_id = song.get('publisher')
                other_artists = song.get('other_artists')

                # Validate required song fields
                if not song_name or not song_release_date or not song_publisher_id:
                    raise Exception('Missing required song fields')

                # Insert the new song into the database
                cur.execute(
                    "INSERT INTO musica (users_userid,titulo_musica, data_de_lancamento, editora_idlabel) VALUES (%s,%s, %s, %s) RETURNING idmusica",
                    (userid,song_name, song_release_date, song_publisher_id)
                )
                new_song_id = cur.fetchone()[0]

                # Associate the new song with the album
                cur.execute(
                    "INSERT INTO musica_album (album_albumid, musica_idmusica) VALUES (%s, %s)",
                    (album_id, new_song_id)
                )

                # Associate other artists with the song
                if other_artists:
                    for artist_id in other_artists:
                        cur.execute(
                            "INSERT INTO users_musica (musica_idmusica, users_userid) VALUES (%s, %s)",
                            (new_song_id, artist_id)
                        )

            else:
                # Existing song ID provided
                existing_song_id = song

                # Check if the artist is associated with the existing song
                cur.execute(
                    "SELECT * FROM users_musica WHERE musica_idmusica = %s AND users_userid = %s",
                    (existing_song_id, publisher_id)
                )
                existing_song_artist = cur.fetchone()

                if not existing_song_artist:
                    raise Exception('Artist is not associated with the selected existing song')

                # Associate the existing song with the album
                cur.execute(
                    "INSERT INTO musica_album (album_albumid, musica_idmusica) VALUES (%s, %s)",
                    (album_id, existing_song_id)
                )

        conn.commit()
        conn.close()

        response = {
            'status': 200,
            'errors': None,
            'results': album_id
        }
        return jsonify(response)

    except Exception as e:
        logging.error(str(e))
        response = {
            'status': 500,
            'errors': str(e),
            'results': None
        }
        return jsonify(response)

def check_song_artist(song_id, artist_id):
    conn = db_connection()
    cur = conn.cursor()

    # Verificar se a música está associada ao artista
    cur.execute(
        "SELECT * FROM users_musica WHERE musica_idmusica = %s AND users_userid = %s",
        (song_id, artist_id)
    )
    existing_song_artist = cur.fetchone()

    conn.close()

    if not existing_song_artist:
        raise Exception('Artist is not associated with the selected song')



@app.route('/dbproj/subscription', methods=['POST'])
@auth_guard()
def subscribe():
    try:
        request_data = request.get_json()
        period = request_data.get('period')
        card_numbers = request_data.get('cards')

        # Verifica se o período e os números de cartão foram fornecidos
        if not period or not card_numbers:
            raise Exception('Period and card numbers are required')

        # Verifica se o período é válido
        if period not in ['month', 'quarter', 'semester']:
            raise Exception('Invalid subscription period')

        conn = db_connection()
        cur = conn.cursor()

        user_data = check_jwt()
        user_id = user_data['userid']

        # Verifica se o usuário já possui uma assinatura ativa
        cur.execute("SELECT subscritpionid, expires FROM subscriptions WHERE users_userid = %s AND active = TRUE", (user_id,))
        current_subscription = cur.fetchone()

        if current_subscription:
            # Se houver uma assinatura ativa, define a data de início como o final da assinatura atual
            start_time = current_subscription[1] + timedelta(days=1)
        else:
            # Se não houver uma assinatura ativa, define a data de início como a data atual
            start_time = date.today()

        # Calcula a data de expiração com base no período escolhido
        # Mapeia os valores de período para o número de meses correspondente
        period_mapping = {
            'month': 1,
            'quarter': 3,
            'semester': 6
        }

                # Verifica se o período é válido e calcula a data de expiração
        if period in period_mapping:
            months = period_mapping[period]
            expires = start_time + timedelta(days=30 * months)
        else:
            raise Exception('Invalid subscription period')


        total_payment_value = calculate_payment_value(period)
        remaining_payment_value = total_payment_value

        # Insere os dados da assinatura na tabela
        cur.execute(
    """INSERT INTO subscriptions (starttime, expires, active, meses, payvalue, users_userid)
       VALUES (%s, %s, TRUE, %s, %s, %s)
       RETURNING subscritpionid""",
    (start_time, expires, months, total_payment_value, user_data['userid']))

        subscription_id = cur.fetchone()[0]


        # Insere os dados de pagamento com base nos cartões fornecidos
        for card_number in card_numbers:
            # Verifica se o cartão pertence ao usuário
            cur.execute("SELECT cardid, saldo FROM cartao WHERE cardnumber = %s", (card_number,))
            card_info = cur.fetchone()

            if not card_info:
                raise Exception('Card does not exist')

            card_id, saldo = card_info

            # Check if the card-user relationship exists
            cur.execute("SELECT * FROM cartao_users WHERE cartao_cardid = %s", (card_id,))
            card_user_relationship = cur.fetchone()

            if card_user_relationship:
                # Check if the user inserting the card matches the associated user ID
                if card_user_relationship[1] != user_id:
                    raise Exception('Card already associated with a different user')

            if saldo >= remaining_payment_value:
                # Se o saldo do cartão for suficiente para pagar o valor restante
                cur.execute(
                    """INSERT INTO payment (paymentdate, paymentvalue, subscriptions_subscritpionid, cartao_cardid)
                       VALUES (%s, %s, %s, %s)""",
                    (date.today(), remaining_payment_value, subscription_id, card_id)
                )
                remaining_payment_value = 0
                new_saldo = saldo - remaining_payment_value
            else:
                # Se o saldo do cartão for insuficiente, utiliza o saldo disponível e atualiza o restante a ser pago
                cur.execute(
                    """INSERT INTO payment (paymentdate, paymentvalue, subscriptions_subscritpionid, cartao_cardid)
                       VALUES (%s, %s, %s, %s)""",
                    (date.today(), saldo, subscription_id, card_id)
                )
                remaining_payment_value -= saldo
                new_saldo = 0

            # Atualiza o saldo do cartão
            cur.execute("UPDATE cartao SET saldo = %s WHERE cardid = %s", (new_saldo, card_id))

            # Cria a relação entre o cartão e o usuário, caso ainda não exista
            cur.execute("INSERT INTO cartao_users (cartao_cardid, users_userid) VALUES (%s, %s) ON CONFLICT DO NOTHING", (card_id, user_id))

        # Verifica se o valor total foi pago
        if remaining_payment_value > 0:
            raise Exception('Insufficient funds in the associated cards')

        conn.commit()
        conn.close()

        response = {
            'status': 200,
            'errors': None,
            'results': subscription_id
        }
        return jsonify(response)

    except Exception as e:
        logging.error(str(e))
        response = {
            'status': 500,
            'errors': str(e),
            'results': None
        }
        return jsonify(response)


def calculate_payment_value(period):
    if period == 'month':
        return 10
    elif period == 'quarter':
        return 25
    elif period == 'semester':
        return 40
    else:
        raise Exception('Invalid subscription period')




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