from pymongo import MongoClient
from app.config import MONGO_URI

client = MongoClient(MONGO_URI)
db = client["pet_ecom_db"]

# Collections
users_collection = db["users"]

# Fetch user by email
def get_user_by_email(email: str):
    return users_collection.find_one({"email": email})

# Create a new user
def create_user(user_data: dict):
    return users_collection.insert_one(user_data)

# Update user's password
def update_user_password(email: str, new_hashed_password: str):
    result = users_collection.update_one(
        {"email": email},
        {"$set": {"password": new_hashed_password}}
    )
    return result.modified_count > 0

# Optional: Fetch user by ID
def get_user_by_id(user_id: str):
    return users_collection.find_one({"_id": user_id})
