from config import Database
import os

def init_db():
    db = Database()
    try:
        with open('setup_db.sql', 'r') as f:
            sql_script = f.read()
            db.execute_script(sql_script)
            print("Database initialized successfully.")
    except Exception as e:
        print(f"Error initializing database: {e}")

if __name__ == "__main__":
    init_db()
