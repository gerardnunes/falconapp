from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

app = Flask(__name__)
DATABASE_URL = "postgresql://postgres:jxIhRbNjprIDGypFMqjJPJZrXXkgCjjF@shortline.proxy.rlwy.net:33514/railway"

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# se não achar no Railway, usa SQLite local
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL or "sqlite:///falcon_digital.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  

db = SQLAlchemy(app)
# Modelos de dados
# Modelos de dados
class User(db.Model):
    __tablename__ = 'users'  # Evita conflito com palavra reservada
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='client')  # 'client' ou 'dev'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relações explícitas
    client_tickets = db.relationship('Ticket', foreign_keys='Ticket.client_id', backref='client_user', lazy=True)
    dev_tickets = db.relationship('Ticket', foreign_keys='Ticket.dev_id', backref='dev_user', lazy=True)


class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='open')  # 'open', 'in_progress', 'closed'
    client_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    dev_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = db.Column(db.DateTime)


class ServicePackage(db.Model):
    __tablename__ = 'service_packages'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    features = db.Column(db.Text, nullable=False)


class TicketMessage(db.Model):
    __tablename__ = 'ticket_messages'
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relações
    user = db.relationship('User', backref='messages')
    ticket = db.relationship('Ticket', backref='messages')




print("Desenvolvedor inserido com sucesso!")
# Rotas principais
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/projects')
def projects():
    return render_template('projects.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')
# API para mensagens dos tickets
@app.route('/api/tickets/<int:ticket_id>/messages', methods=['POST'])
def add_ticket_message(ticket_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401
    
    data = request.get_json()
    message = data.get('message')
    
    if not message:
        return jsonify({'error': 'Mensagem é obrigatória'}), 400
    
    new_message = TicketMessage(
        ticket_id=ticket_id,
        user_id=session['user_id'],
        message=message
    )
    
    db.session.add(new_message)
    db.session.commit()
    
    return jsonify({'message': 'Mensagem adicionada com sucesso'})

@app.route('/api/tickets/<int:ticket_id>/messages', methods=['GET'])
def get_ticket_messages(ticket_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401
    
    messages = TicketMessage.query.filter_by(ticket_id=ticket_id).order_by(TicketMessage.created_at.asc()).all()
    
    return jsonify([{
        'id': m.id,
        'user_id': m.user_id,
        'user_name': m.user.name,
        'user_role': m.user.role,
        'message': m.message,
        'created_at': m.created_at.strftime('%d/%m/%Y %H:%M')
    } for m in messages])
# Rotas de autenticação
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_role'] = user.role
            
            if user.role == 'client':
                return redirect(url_for('client_dashboard'))
            else:
                return redirect(url_for('dev_dashboard'))
        else:
            return render_template('login.html', error='Credenciais inválidas')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role', 'client')
        
        if password != confirm_password:
            return render_template('register.html', error='As senhas não coincidem')
        
        if User.query.filter_by(email=email).first():
            return render_template('register.html', error='Email já cadastrado')
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(
            name=name,
            email=email,
            phone=phone,
            password=hashed_password,
            role=role
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Painéis de usuário
@app.route('/client/dashboard')
def client_dashboard():
    if 'user_id' not in session or session['user_role'] != 'client':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    tickets = user.client_tickets  # Alterado para usar a nova relação
    packages = ServicePackage.query.all()
    
    return render_template('client-dashboard.html', user=user, tickets=tickets, packages=packages)

@app.route('/dev/dashboard')
def dev_dashboard():
    if 'user_id' not in session or session['user_role'] != 'dev':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    tickets = Ticket.query.all()
    clients = User.query.filter_by(role='client').all()
    
    return render_template('dev-dashboard.html', user=user, tickets=tickets, clients=clients)

# API para tickets
@app.route('/api/tickets', methods=['POST'])
def create_ticket():
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401
    
    data = request.get_json()
    
    new_ticket = Ticket(
        title=data['title'],
        description=data['description'],
        client_id=session['user_id']
    )
    
    db.session.add(new_ticket)
    db.session.commit()
    
    return jsonify({'message': 'Ticket criado com sucesso', 'id': new_ticket.id})

@app.route('/api/tickets/<int:ticket_id>', methods=['PUT'])
def update_ticket(ticket_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Não autenticado'}), 401
    
    ticket = Ticket.query.get_or_404(ticket_id)
    data = request.get_json()
    
    if 'status' in data:
        ticket.status = data['status']
    
    if 'dev_id' in data and session['user_role'] == 'dev':
        ticket.dev_id = data['dev_id']
    
    db.session.commit()
    
    return jsonify({'message': 'Ticket atualizado com sucesso'})

# Inicialização do banco de dados
def init_db():
    with app.app_context():
        db.create_all()
        
        # Criar alguns pacotes de serviço iniciais
        if not ServicePackage.query.first():
            packages = [
                ServicePackage(
                    name='Pacote Básico',
                    description='Soluções essenciais para presença digital',
                    price=499.90,
                    features='Site institucional; SEO básico; Analytics configurado'
                ),
                ServicePackage(
                    name='Pacote Intermediário',
                    description='Presença digital completa com marketing',
                    price=999.90,
                    features='Site responsivo; Campanhas de tráfego pago; SEO avançado'
                ),
                ServicePackage(
                    name='Pacote Enterprise',
                    description='Soluções completas para grandes negócios',
                    price=2499.90,
                    features='E-commerce completo; CRM integrado; Analytics avançado; Suporte 24/7'
                )
            ]
            
            for package in packages:
                db.session.add(package)
            
            db.session.commit()


def create_dev_command():
    """Função para criar um desenvolvedor via linha de comando"""
    with app.app_context():
        # Verificar se já existe um desenvolvedor
        if User.query.filter_by(role='dev').first():
            print("Já existe um usuário desenvolvedor no sistema.")
            return
        
        # Criar usuário desenvolvedor padrão
        hashed_password = generate_password_hash('dev123')
        dev_user = User(
            name='Des',
            email='dev@falcondigital.com',
            phone='(11) 99999-9999',
            password=hashed_password,
            role='dev'
        )
        
        db.session.add(dev_user)
        db.session.commit()
        print("Desenvolvedor criado com sucesso!")
        print("Email: dev@falcondigital.com")
        print("Senha: dev123")
        print("IMPORTANTE: Altere a senha após o primeiro login!")

# Executar a criação do desenvolvedor quando o app iniciar
if __name__ == '__main__':
    with app.app_context():
        # Criar tabelas se não existirem
        db.create_all()
        
        # Criar usuário desenvolvedor se não existir
        if not User.query.filter_by(role='dev').first():
            create_dev_command()
        
        # Criar pacotes de serviço se não existirem
        if not ServicePackage.query.first():
            packages = [
                ServicePackage(
                    name='Pacote Básico',
                    description='Soluções essenciais para presença digital',
                    price=499.90,
                    features='Site institucional; SEO básico; Analytics configurado'
                ),
                ServicePackage(
                    name='Pacote Intermediário',
                    description='Presença digital completa com marketing',
                    price=999.90,
                    features='Site responsivo; Campanhas de tráfego pago; SEO avançado'
                ),
                ServicePackage(
                    name='Pacote Enterprise',
                    description='Soluções completas para grandes negócios',
                    price=2499.90,
                    features='E-commerce completo; CRM integrado; Analytics avançado; Suporte 24/7'
                )
            ]
            
            for package in packages:
                db.session.add(package)
            
            db.session.commit()
            print("Pacotes de serviço criados com sucesso!")
    
    app.run(debug=True)


