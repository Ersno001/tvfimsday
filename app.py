from flask import Flask, request, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import stripe
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'секрет'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['JWT_SECRET_KEY'] = 'jwt-секрет'
db = SQLAlchemy(app)
jwt = JWTManager(app)

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
DOMAIN = os.getenv('DOMAIN', 'http://localhost:5000')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    subscription_until = db.Column(db.DateTime)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if User.query.filter_by(email=data['email']).first():
        return jsonify(message='Пользователь уже существует'), 409
    user = User(email=data['email'], password=data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify(message='Успешная регистрация')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email'], password=data['password']).first()
    if not user:
        return jsonify(message='Неверный логин или пароль'), 401
    token = create_access_token(identity=user.email)
    return jsonify(token=token)

@app.route('/subscribe', methods=['POST'])
@jwt_required()
def create_checkout():
    email = get_jwt_identity()
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'rub',
                'product_data': {'name': 'Подписка DAYDREAM'},
                'unit_amount': 50000,
                'recurring': {'interval': 'month'},
            },
            'quantity': 1,
        }],
        mode='subscription',
        success_url=f'{DOMAIN}/success?session_id={{CHECKOUT_SESSION_ID}}',
        cancel_url=f'{DOMAIN}/cancel',
        metadata={'email': email}
    )
    return jsonify(url=session.url)

@app.route('/success')
def success():
    return 'Оплата прошла успешно'

@app.route('/cancel')
def cancel():
    return 'Оплата отменена'

@app.route('/video-url')
@jwt_required()
def video_url():
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()
    if user.subscription_until and user.subscription_until > datetime.utcnow():
        return jsonify(url='https://example.com/secured-video.m3u8')
    return jsonify(message='Нет активной подписки'), 403

@app.route('/user')
@jwt_required()
def get_user():
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()
    return jsonify(email=user.email, subscription_until=user.subscription_until.strftime('%Y-%m-%d') if user.subscription_until else None)

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('stripe-signature')
    endpoint_secret = os.getenv('STRIPE_WEBHOOK_SECRET')

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except Exception as e:
        return str(e), 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        email = session['metadata']['email']
        user = User.query.filter_by(email=email).first()
        if user:
            user.subscription_until = datetime.utcnow() + timedelta(days=30)
            db.session.commit()

    return '', 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)