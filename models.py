from config.db import db
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from datetime import datetime, timezone 
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))  # provider user ID (like Google/GitHub UID)
    provider = db.Column(db.String(50), nullable=False, default='local')
    name = db.Column(db.String(100), nullable=False, default='User'+str(uuid.uuid4())[:4])
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))  # For local authentication
    avatar_url = db.Column(db.String(255))
    last_login = db.Column(db.DateTime )

    def set_password(self, password):
        #self.password_hash = generate_password_hash(password)
        self.password_hash = password
        
        
    
    def check_password(self, password):
           #return check_password_hash(self.password_hash, password)
              return self.password_hash == password
      
    def __repr__(self):
        
        return f"<User {self.email} from {self.provider}>"