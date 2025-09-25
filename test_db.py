from flask import Flask
from flask_pymongo import PyMongo
from datetime import datetime
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure MongoDB
app.config["MONGO_URI"] = os.getenv('MONGODB_URI')
mongo = PyMongo(app)

def test_connection():
    try:
        # Test MongoDB connection
        mongo.db.command('ping')
        print("MongoDB connection successful!")
        
        # Try to create a test document
        result = mongo.db.test.insert_one({'test': True, 'timestamp': datetime.utcnow()})
        print(f"Test document created with id: {result.inserted_id}")
        
        # Clean up by removing the test document
        mongo.db.test.delete_one({'_id': result.inserted_id})
        print("Test document cleaned up successfully")
        
        return True
    except Exception as e:
        print(f"Error connecting to MongoDB: {str(e)}")
        return False

if __name__ == "__main__":
    test_connection()
