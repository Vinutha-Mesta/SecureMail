# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import datetime
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securemailxdr.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    email_submissions = db.relationship('EmailSubmission', backref='user', lazy=True)

class EmailSubmission(db.Model):
    __tablename__ = 'email_submissions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    email_content = db.Column(db.Text, nullable=False)
    classification = db.Column(db.String(20), nullable=False)
    suspicious_keywords = db.Column(db.Text)
    dangerous_keywords = db.Column(db.Text)
    suspicious_urls = db.Column(db.Text)
    sender_anomalies = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Email Classification Logic
class EmailAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'password', 'otp', 'verify', 'account', 'security', 'login',
            'credentials', 'bank', 'paypal', 'urgent', 'immediately',
            'suspended', 'limited', 'confirm', 'update', 'information',
            'click here', 'verify your', 'action required', 'security alert',
            'unauthorized', 'locked', 'compromised', 'phishing', 'hack'
        ]
        self.dangerous_keywords = [
            'wire transfer', 'social security', 'credit card', 'password reset',
            'account closure', 'immediate action', 'security breach',
            'bank account', 'ssn', 'social security number', 'credit score',
            'password change', 'account suspended', 'verify identity',
            'tax refund', 'irs', 'free money', 'lottery winner', 'inheritance'
        ]
    
    def analyze_email(self, content):
        content_lower = content.lower()
        
        # Check for suspicious keywords
        found_suspicious_keywords = []
        for keyword in self.suspicious_keywords:
            if keyword in content_lower:
                found_suspicious_keywords.append(keyword)
        
        # Check for dangerous keywords
        found_dangerous_keywords = []
        for keyword in self.dangerous_keywords:
            if keyword in content_lower:
                found_dangerous_keywords.append(keyword)
        
        # Check for suspicious URLs
        urls = self.extract_urls(content)
        suspicious_urls = []
        for url in urls:
            if self.is_suspicious_url(url):
                suspicious_urls.append(url)
        
        # Check for sender anomalies (simplified)
        sender_anomalies = self.check_sender_anomalies(content)
        
        # Determine classification
        if found_dangerous_keywords or len(suspicious_urls) > 0:
            classification = 'DANGEROUS'
        elif found_suspicious_keywords or sender_anomalies:
            classification = 'SUSPICIOUS'
        else:
            classification = 'SAFE'
        
        return {
            'classification': classification,
            'suspicious_keywords': found_suspicious_keywords,
            'dangerous_keywords': found_dangerous_keywords,
            'suspicious_urls': suspicious_urls,
            'sender_anomalies': sender_anomalies
        }
    
    def extract_urls(self, text):
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        return re.findall(url_pattern, text)
    
    def is_suspicious_url(self, url):
        # Check for non-HTTPS, shortened URLs, etc.
        if not url.startswith('https://'):
            return True
        if any(shortener in url for shortener in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']):
            return True
        return False
    
    def check_sender_anomalies(self, content):
        # Simple check for generic greetings and urgency
        lines = content.lower().split('\n')
        if any(line.startswith(('dear user', 'dear customer', 'dear member', 'dear valued', 'dear account')) for line in lines[:3]):
            return True
        if any('urgent' in line or 'immediate' in line or 'attention' in line or 'important' in line for line in lines):
            return True
        return False

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('register'))
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    submissions = EmailSubmission.query.filter_by(user_id=user_id).order_by(EmailSubmission.timestamp.desc()).all()
    
    # Prepare data for charts
    classification_counts = {'SAFE': 0, 'SUSPICIOUS': 0, 'DANGEROUS': 0}
    keyword_counts = {}
    
    for submission in submissions:
        classification_counts[submission.classification] += 1
        
        # Count keywords from all submissions
        if submission.suspicious_keywords:
            keywords = submission.suspicious_keywords.split(',')
            for keyword in keywords:
                keyword = keyword.strip()
                if keyword:
                    keyword_counts[keyword] = keyword_counts.get(keyword, 0) + 1
        
        if submission.dangerous_keywords:
            keywords = submission.dangerous_keywords.split(',')
            for keyword in keywords:
                keyword = keyword.strip()
                if keyword:
                    keyword_counts[keyword] = keyword_counts.get(keyword, 0) + 1
    
    # Get top 10 keywords
    top_keywords = sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    return render_template('dashboard.html', 
                         classification_counts=classification_counts,
                         top_keywords=top_keywords,
                         submissions=submissions)

@app.route('/analyze-email', methods=['GET', 'POST'])
def analyze_email():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    analysis_result = None
    
    if request.method == 'POST':
        email_content = request.form['email_content']
        
        if not email_content.strip():
            flash('Please enter email content to analyze')
            return redirect(url_for('analyze_email'))
        
        analyzer = EmailAnalyzer()
        analysis_result = analyzer.analyze_email(email_content)
        
        # Save to database
        new_submission = EmailSubmission(
            user_id=session['user_id'],
            email_content=email_content,
            classification=analysis_result['classification'],
            suspicious_keywords=','.join(analysis_result['suspicious_keywords']),
            dangerous_keywords=','.join(analysis_result['dangerous_keywords']),
            suspicious_urls=','.join(analysis_result['suspicious_urls']),
            sender_anomalies=analysis_result['sender_anomalies']
        )
        
        try:
            db.session.add(new_submission)
            db.session.commit()
            flash(f'Email classified as: {analysis_result["classification"]}')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while saving your analysis. Please try again.')
    
    return render_template('email_form.html', analysis_result=analysis_result)

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    submissions = EmailSubmission.query.filter_by(user_id=user_id).order_by(EmailSubmission.timestamp.desc()).all()
    
    return render_template('dashboard.html', submissions=submissions)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Initialize database
def init_db():
    with app.app_context():
        # Check if database needs to be recreated
        from sqlalchemy import inspect
        try:
            inspector = inspect(db.engine)
            
            # If email_submissions table exists but doesn't have dangerous_keywords column
            if 'email_submissions' in inspector.get_table_names():
                columns = [col['name'] for col in inspector.get_columns('email_submissions')]
                if 'dangerous_keywords' not in columns:
                    print("Database schema outdated. Please delete securemailxdr.db and restart.")
                    return False
        except:
            # If inspection fails, the database probably doesn't exist yet
            pass
        
        db.create_all()
        print("Database initialized successfully!")
        return True

# This should be at the very bottom, outside any function
if __name__ == '__main__':
    if not init_db():
        print("Please delete the securemailxdr.db file and restart the application.")
    else:
        app.run(debug=True)