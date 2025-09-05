# reset_db.py
import os

# Delete the database file if it exists
db_file = 'securemailxdr.db'
if os.path.exists(db_file):
    os.remove(db_file)
    print(f"Removed existing database: {db_file}")
else:
    print("Database file does not exist. It will be created when the app runs.")

print("Now run: python app.py")