from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import os
import secrets
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import traceback
from flask_jwt_extended import decode_token, exceptions as jwt_exceptions 

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Model per gli utenti
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


# Inizializzazione del database e popolamento dei prodotti
@app.before_request
def setup_database():
    # Crea tutte le tabelle nel database
    db.create_all()

# CORS handling

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

    
# Registrazione
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if 'username' not in data or 'email' not in data or 'password' not in data:
            return jsonify({'message': 'Missing fields'}), 400

        # Check if username or email already exists
        existing_user = User.query.filter((User.username == data['username']) | (User.email == data['email'])).first()
        if existing_user:
            return jsonify({'message': 'Username or email already exists'}), 400

        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(username=data['username'], email=data['email'], password=hashed_password)
        db.session.add(user)
        db.session.commit()

        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 400

# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    print('Login data received:', data)  # Log received data
    if 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Missing fields'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if user:
        print('User found:', user)  # Log user found
        if bcrypt.check_password_hash(user.password, data['password']):
            access_token = create_access_token(identity=str(user.id))
            return jsonify({'token': access_token})
        else:
            print('Password check failed')  # Log password check failure
    else:
        print('User not found')  # Log user not found

    return jsonify({'message': 'Invalid credentials'}), 401





# Get user info
@app.route('/user', methods=['GET'])
def user():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"message": "Token mancante o formato non valido"}), 401

    token = auth_header.split(" ")[1]  # Estrarre il token
    print(f"Token ricevuto: {token}")

    try:
        # Decodifica il token manualmente
        decoded_token = decode_token(token)
        print(f"Token decodificato: {decoded_token}")

        # Assicurati che il campo 'sub' sia presente nel payload
        user_id = decoded_token.get('sub')
        if not user_id:
            print("ID utente mancante nel token decodificato.")
            return jsonify({"message": "Token non valido: ID utente mancante"}), 401

        # Cerca l'utente nel database
        user = User.query.get(user_id)
        if not user:
            print(f"Utente con ID {user_id} non trovato.")
            return jsonify({"message": "Utente non trovato"}), 404

        # Risposta con i dati dell'utente
        return jsonify({
            "username": user.username,
            "email": user.email
        })
    except jwt_exceptions.JWTDecodeError:
        print("Errore: Impossibile decodificare il token.")
        return jsonify({"message": "Token non valido"}), 401
    except Exception as e:
        # Stampa il traceback completo per il debug
        print("Errore imprevisto:", traceback.format_exc())
        return jsonify({"message": "Errore del server"}), 500


if __name__ == '__main__':
    app.run(port=5002, debug=True)
