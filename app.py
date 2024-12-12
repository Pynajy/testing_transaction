from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, IntegerField, URLField, SubmitField
from wtforms.validators import DataRequired, NumberRange, URL
import click
from datetime import datetime, timedelta
import requests
from celery import Celery
from celery.schedules import crontab
from flasgger import Swagger

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['broker_url'] = 'redis://localhost:6379/0'
app.config['result_backend'] = 'redis://localhost:6379/0'

db = SQLAlchemy(app)
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
    balance = db.Column(db.Float, nullable=False, default=0.0)
    commission_rate = db.Column(db.Float, nullable=False, default=0.01)
    webhook_url = db.Column(db.String(256), nullable=True)

    def __repr__(self):
        return f'<User {self.id}: Баланс={self.balance}, Cтавка комиссии={self.commission_rate}, Webhook={self.webhook_url}>'

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    commission = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='ожидание')
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('transactions', lazy=True))

    def __repr__(self):
        return f'<Transaction {self.id}: Сумма={self.amount}, Комиссия={self.commission}, статус={self.status}>'

@app.cli.command("create-admin")
@click.argument('balance', type=float, default=0.0)
def create_admin(balance):
    "Create a default admin user"
    admin = User(balance=balance, commission_rate=0.0, webhook_url=None)
    db.session.add(admin)
    db.session.commit()
    print(f"Админ создан с ID: {admin.id}")

@app.route('/admin')
def admin_dashboard():
    user_count = User.query.count()
    transaction_count = Transaction.query.count()
    total_transaction_sum = db.session.query(db.func.sum(Transaction.amount)).filter(Transaction.created_at >= datetime.now().date()).scalar() or 0.0
    recent_transactions = Transaction.query.order_by(Transaction.created_at.desc()).limit(5).all()
    return render_template('dashboard.html', user_count=user_count, transaction_count=transaction_count, total_transaction_sum=total_transaction_sum, recent_transactions=recent_transactions)

@app.route('/admin/users')
def admin_users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.balance = float(request.form['balance'])
        user.commission_rate = float(request.form['commission_rate'])
        user.webhook_url = request.form['webhook_url']
        db.session.commit()
        return redirect(url_for('admin_users'))
    return render_template('edit_user.html', user=user)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin_users'))

@app.route('/admin/transactions')
def admin_transactions():
    transactions = Transaction.query.all()
    return render_template('transactions.html', transactions=transactions)

@app.route('/admin/transactions/<int:transaction_id>', methods=['GET', 'POST'])
def transaction_detail(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    if request.method == 'POST':
        status = request.form['status']
        if transaction.status == 'ожидание' and status in ['подтвеждена', 'истекла']:
            transaction.status = status
            db.session.commit()
        return redirect(url_for('admin_transactions'))
    return render_template('transaction_detail.html', transaction=transaction)

@app.route('/create_transaction', methods=['POST'])
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
            id:
              type: integer
              description: User ID
              example: 1
            amount:
              type: number
              description: Сумма транзакции
              example: 100.50
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
    user_id = data.get('id')
    amount = data.get('amount')

    if not user_id or not amount:
        return jsonify({"error": "User ID and amount are required."}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    commission = amount * user.commission_rate
    transaction = Transaction(amount=amount, commission=commission, user_id=user.id)

    db.session.add(transaction)
    db.session.commit()

    return jsonify({
        "transaction_id": transaction.id,
        "amount": transaction.amount,
        "commission": transaction.commission,
        "status": transaction.status
    }), 201

@app.route('/cancel_transaction', methods=['POST'])
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
        "amount": transaction.amount,
        "commission": transaction.commission,
        "status": transaction.status,
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
