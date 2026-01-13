from flask import Flask
from flask_socketio import SocketIO
import os

socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
    app.config['RESULTS_DIR'] = os.path.join(app.root_path, 'results')
    
    # Ensure results directory exists
    os.makedirs(app.config['RESULTS_DIR'], exist_ok=True)
    
    from app.main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    socketio.init_app(app, cors_allowed_origins="*")
    
    return app
