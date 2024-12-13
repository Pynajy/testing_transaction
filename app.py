from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_migrate import Migrate
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, DecimalField, IntegerField, URLField, SubmitField, PasswordField, SelectField
from wtforms.validators import DataRequired, NumberRange, URL, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import click
from datetime import datetime, timedelta
import requests
from celery import Celery
from celery.schedules import crontab
from flasgger import Swagger

from data.wallet.wallet import Wallet

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = 'Gfj3&#jfdsnHDUSDF733SD#'
app.config['broker_url'] = 'redis://localhost:6379/0'
app.config['result_backend'] = 'redis://localhost:6379/0'

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
migrate = Migrate(app, db)

celery = Celery(app.name)
celery.conf.broker_url = app.config['broker_url']
celery.conf.result_backend = app.config['result_backend']
celery.conf.beat_schedule = {
    'check-pending-transactions-every-3-minutes': {
        'task': 'check_pending_transactions',
        'schedule': crontab(minute='*/3'),
    },
}

swagger = Swagger(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user') 
    balance = db.Column(db.Float, nullable=False, default=0.0)
    commission_rate = db.Column(db.Float, nullable=False, default=0.01) 
    wallet = db.Column(db.String(256), nullable=True)
    webhook_url = db.Column(db.String(256), nullable=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f'<User {self.id}: Роль={self.role}, Баланс={self.balance}, Cтавка комиссии={self.commission_rate}, Webhook={self.webhook_url}>'

class TypeTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(256), nullable=True)
    
    def __repr__(self):
        return f'Транзакция {self.title}'

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    commission = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='ожидание')
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())

    type_transaction_id = db.Column(db.Integer, db.ForeignKey('type_transaction.id'), nullable=False)
    type_transaction = db.relationship('TypeTransaction', backref=db.backref('transactions', lazy=True))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('transactions', lazy=True))

    def __repr__(self):
        return f'<Транзакция {self.id}: Сумма={self.amount}, Комиссия={self.commission}, статус={self.status}>'

class StatusToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(256), nullable=True)


class AppTokenUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(256), nullable=True)

    status_token_id = db.Column(db.Integer, db.ForeignKey('status_token.id'), nullable=False)
    status_token = db.relationship('StatusToken', backref=db.backref('transactions', lazy=True))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('app_token_user', lazy=True))

    def generate_app_token(self, session):
        self.token = "token-" + ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        session.commit()

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    auto_update = db.Column(db.String(20), nullable=False, default='10 сек')

    def __repr__(self):
        return  f'<Настройки: Автообновление={self.auto_update}>'


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('user', 'User')], validators=[DataRequired()])
    submit = SubmitField('Register')

class TransactionForm(FlaskForm):
    submit = SubmitField('Register')

class UserForm(FlaskForm):
    submit = SubmitField('Register')

class SettingsForm(FlaskForm):
    submit = SubmitField('Register')

@app.cli.command("create-admin")
@click.argument('username')
@click.argument('password')
def create_admin(username, password):
    "Create a default admin user"
    admin = User(username=username, role='admin', balance=0.0, commission_rate=0.0)
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()
    print(f"Admin user created with username: {admin.username}")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print(form.username.data)
        print(form.password.data)
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('admin_dashboard') if user.role == 'admin' else url_for('admin_transactions'))
        return "Invalid username or password", 403
    
    if not form.validate_on_submit():
        print(form.errors)

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if session.get('role') != 'admin':
        if session.get('role') != 'user':
            return redirect(url_for('login'))
        else:
            return redirect(url_for('admin_transactions'))
    form = SettingsForm()
    user_count = User.query.count()
    transaction_count = Transaction.query.count()
    total_transaction_sum = db.session.query(db.func.sum(Transaction.amount)).filter(Transaction.created_at >= datetime.now().date()).scalar() or 0.0
    recent_transactions = Transaction.query.order_by(Transaction.created_at.desc()).limit(5).all()
    settings = Settings.query.get_or_404(1)

    if request.method == 'POST':
        settings.auto_update = str(request.form['auto_update'])
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template(
        'dashboard.html', 
        user_count=user_count, 
        transaction_count=transaction_count, 
        total_transaction_sum=total_transaction_sum, 
        recent_transactions=recent_transactions, 
        form=form, 
        settings=settings
        )

@app.route('/admin/users')
def admin_users():
    if session.get('role') != 'admin':
        if session.get('role') != 'user':
            return redirect(url_for('login'))
        else:
            return redirect(url_for('admin_transactions'))
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if session.get('role') != 'admin':
        if session.get('role') != 'user':
            return redirect(url_for('login'))
        else:
            return redirect(url_for('admin_transactions'))
    form = UserForm()
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.balance = float(request.form['balance'])
        user.commission_rate = float(request.form['commission_rate'])
        user.role = str(request.form['role'])
        user.webhook_url = request.form['webhook_url']
        user.wallet = request.form['wallet']
        db.session.commit()
        return redirect(url_for('admin_users'))
    return render_template('edit_user.html', user=user, form=form)

@app.route('/admin/users/add', methods=['GET', 'POST'])
def add_user():
    if session.get('role') != 'admin':
        if session.get('role') != 'user':
            return redirect(url_for('login'))
        else:
            return redirect(url_for('admin_transactions'))
    form = RegistrationForm()
    if request.method == 'POST':
        user = User(
            username = str(request.form['username']),
            balance = float(request.form['balance']), 
            commission_rate = float(request.form['commission_rate']), 
            webhook_url = request.form['webhook_url']
            )
        user.set_password(request.form['password'])
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('admin_users'))
    return render_template('add_user.html', form=form)

@app.route('/admin/user/<int:user_id>/token/', methods=['GET'])
def user_app_token(user_id):
    if session.get('role') != 'admin' or (session.get('role') == 'user' and int(session.get('user_id')) == int(user_id)):
        return redirect(url_for('admin_transactions'))
    query = AppTokenUser.query
    query = query.filter_by(user_id=user_id)
    user_app_token_list = query.all()

    return render_template('user_token.html', user_app_tokens=user_app_token_list, user_id=user_id)

@app.route('/admin/user/<int:user_id>/token/add/', methods=['GET'])
@csrf.exempt
def add_user_app_token(user_id):
    if session.get('role') != 'admin' or (session.get('role') == 'user' and int(session.get('user_id')) == int(user_id)):
        return redirect(url_for('admin_transactions'))
    user = User.query.get_or_404(user_id)
    app_user_token = AppTokenUser(
        user_id = user_id,
        status_token_id = 1
        )
    db.session.add(app_user_token)
    db.session.commit()
    app_user_token.generate_app_token(db.session)
    return redirect(url_for('user_app_token', user_id=user_id))

@app.route('/admin/user/<int:user_id>/token/delete/<int:token_id>', methods=['POST'])
@csrf.exempt
def delete_user_app_token(user_id, token_id):
    if session.get('role') != 'admin' or (session.get('role') == 'user' and int(session.get('user_id')) == int(user_id)):
        return redirect(url_for('admin_transactions'))
    token = AppTokenUser.query.get_or_404(token_id)
    db.session.delete(token)
    db.session.commit()
    return redirect(url_for('user_app_token', user_id=user_id))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@csrf.exempt
def delete_user(user_id):
    if session.get('role') != 'admin':
        if session.get('role') != 'user':
            return redirect(url_for('login'))
        else:
            return redirect(url_for('admin_transactions'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin_users'))

@app.route('/admin/users/wallet/create/<int:user_id>', methods=['POST'])
@csrf.exempt
def create_wallet(user_id):
    if session.get('role') != 'admin':
        if session.get('role') != 'user':
            return redirect(url_for('login'))
        else:
            return redirect(url_for('admin_transactions'))
    wallet = Wallet().generate_testnet_wallet()
    user = User.query.get_or_404(user_id)
    user.wallet = wallet
    db.session.commit()
    return redirect(url_for('edit_user', user_id=user_id))

@app.route('/admin/transactions')
def admin_transactions():
    user_id = session.get('user_id')
    role = session.get('role')

    if role not in ['admin', 'user']:
        return redirect(url_for('login'))

    filter_wallet_id = request.args.get('wallet_id')
    filter_status = request.args.get('status')
    type_transaction = request.args.get('type_transaction')

    query = Transaction.query.order_by(desc(Transaction.id))
    type_transaction_id = TypeTransaction.query.filter_by(title=type_transaction).first()

    if role == 'user':
        query = query.filter_by(user_id=user_id)

    if filter_wallet_id:
        user = User.query.filter_by(wallet=filter_wallet_id).first()
        query = query.filter_by(user_id=(user.id if user else 0))

    if filter_status:
        query = query.filter_by(status=filter_status)
    
    if type_transaction:
        query = query.filter_by(type_transaction_id=type_transaction_id.id)

    transactions = query.all()

    settings = Settings.query.get_or_404(1)

    return render_template('transactions.html', transactions=transactions, settings=(int(str(settings.auto_update).split()[0]) if str(settings.auto_update).split()[1] == "сек" else int(str(settings.auto_update).split()[0])*60))

@app.route('/admin/transactions/<int:transaction_id>', methods=['GET', 'POST'])
def transaction_detail(transaction_id):
    if session.get('role') != 'admin':
        if session.get('role') != 'user':
            return redirect(url_for('login'))
    form = TransactionForm()
    transaction = Transaction.query.get_or_404(transaction_id)
    if request.method == 'POST':
        status = request.form['status']
        if transaction.status == 'ожидание' and status in ['подтвеждена', 'отменена']:
            if status == "подтвеждена":
                if transaction.type_transaction_id == 1:
                    transaction.user.balance += transaction.amount
                    transaction.user.balance -= transaction.commission
                else:
                    if transaction.user.balance >= (transaction.amount + transaction.commission):
                        transaction.user.balance -= (transaction.amount + transaction.commission)
                    else:
                        transaction.status = "Недостаточно средств"
            transaction.status = status
            db.session.commit()
        return redirect(url_for('admin_transactions'))
    return render_template('transaction_detail.html', transaction=transaction, form=form)

@app.route('/create_transaction', methods=['POST'])
@csrf.exempt
def create_transaction():
    """
    Создать транзакцию
    ---
    consumes:
      - application/json
    parameters:
      - name: id
        in: body
        schema:
          type: object
          properties:
            wallet:
              type: integer
              description: wallet ID
              example: testnet-8l5SB6YVXsPtTdMt1RLWwG7BJvEecq3Z
            amount:
              type: number
              description: Сумма транзакции
              example: 100.50
            type_transaction:
              type: number
              description: Сумма транзакции
              example: 1
        required: true
    responses:
      201:
        description: Transaction created
      400:
        description: Missing parameters
      404:
        description: User not found
    """
    if not request.is_json:
        return jsonify({"error": "Unsupported Media Type. Use application/json."}), 415

    data = request.get_json()
    user_wallet = data.get('wallet')
    amount = data.get('amount')
    type_transaction = data.get('type_transaction')

    if not user_wallet or not amount or not type_transaction:
        return jsonify({"error": "User ID, amount and type_transaction are required."}), 400

    user = User.query.filter_by(wallet=user_wallet).first()
    type_transaction = TypeTransaction.query.get(type_transaction)

    if not user:
        return jsonify({"error": "Wallet not found."}), 404
    
    if not type_transaction:
        return jsonify({"error": "Type transaction not found."}), 404

    commission = amount * user.commission_rate
    transaction = Transaction(amount=amount, commission=commission, user_id=user.id, type_transaction_id=type_transaction.id)
    if type_transaction.id == 2 and user.balance < (amount + commission):
        transaction.status = "Недостаточно средств"
        
    
    # if type_transaction.id == 1:
    #     user.balance += amount
    #     user.balance -= commission
    # else:
    #     if user.balance >= (amount + commission):
    #         user.balance -= amount
    #         user.balance -= commission
    #     else:
    #         transaction.status = "Недостаточно средств"

    db.session.add(transaction)
    db.session.commit()

    return jsonify({
        "transaction_id": transaction.id,
        "amount": transaction.amount,
        "commission": transaction.commission,
        "status": transaction.status
    }), 201

@app.route('/cancel_transaction', methods=['POST'])
@csrf.exempt
def cancel_transaction():
    """
    Закрыть транзакцию
    ---
    consumes:
      - application/json
    parameters:
      - name: transaction_id
        in: body
        schema:
          type: object
          properties:
            transaction_id:
              type: integer
              description: ID транзакции
              example: 1
        required: true
    responses:
      200:
        description: Transaction canceled
      400:
        description: Missing parameters
      404:
        description: Transaction not found
    """
    if not request.is_json:
        return jsonify({"error": "Unsupported Media Type. Use application/json."}), 415

    data = request.get_json()
    transaction_id = data.get('transaction_id')

    if not transaction_id:
        return jsonify({"error": "Transaction ID is required."}), 400

    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        return jsonify({"error": "Transaction not found."}), 404

    if transaction.status != 'ожидание':
        return jsonify({"error": "Only pending transactions can be canceled."}), 400

    transaction.status = 'истекла'
    db.session.commit()

    return jsonify({
        "transaction_id": transaction.id,
        "status": transaction.status
    }), 200

@app.route('/check_transaction', methods=['GET'])
@csrf.exempt
def check_transaction():
    """
    Получить транзакцию
    ---
    parameters:
      - name: transaction_id
        in: query
        type: integer
        required: true
        description: ID транзакции
    responses:
      200:
        description: Transaction status
      400:
        description: Missing parameters
      404:
        description: Transaction not found
    """
    transaction_id = request.args.get('transaction_id')

    if not transaction_id:
        return jsonify({"error": "Transaction ID is required."}), 400

    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        return jsonify({"error": "Transaction not found."}), 404

    return jsonify({
        "transaction_id": transaction.id,
        "user": transaction.user.id,
        "amount": transaction.amount,
        "commission": transaction.commission,
        "status": transaction.status,
        "type_transaction": str(transaction.type_transaction),
        "created_at": transaction.created_at
    }), 200

@celery.task(name='check_pending_transactions')
def check_pending_transactions():
    print("Running check_pending_transactions...")
    with app.app_context():
        now = datetime.utcnow()
        expired_time = now - timedelta(minutes=3)
        pending_transactions = Transaction.query.filter(Transaction.status == 'ожидание', Transaction.created_at < expired_time).all()

        for transaction in pending_transactions:
            transaction.status = 'истекла'
            db.session.commit()

            user = User.query.get(transaction.user_id)
            if user and user.webhook_url:
                try:
                    print(f"Отправка webhook для транзакции {transaction.id}")
                    requests.post(user.webhook_url, json={"transaction_id": transaction.id, "status": transaction.status})
                except requests.RequestException as e:
                    print(f"Ошибка отправки webhook для транзакции {transaction.id}: {e}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("База данных инициализирована")
