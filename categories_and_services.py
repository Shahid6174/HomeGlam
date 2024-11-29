import sqlite3
import os

# Define the path to the SQLite database file in the instance folder
db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'homeglam.db')

# Connect to the SQLite database (or create it)
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create the tables for categories and services
cursor.execute('''
CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    FOREIGN KEY (category_id) REFERENCES categories (id),
    UNIQUE(category_id, name)  -- Prevent duplicate services under the same category
)
''')

# Insert predefined categories, ensuring no duplicates
categories = [
    "Home Repair & Maintenance",
    "Beauty & Personal Care",
    "Cleaning & Housekeeping",
    "Fitness & Health",
    "Construction & Renovation",
    "Outdoor & Gardening"
]

for category in categories:
    # Check if the category already exists before inserting
    cursor.execute("SELECT id FROM categories WHERE name = ?", (category,))
    if cursor.fetchone() is None:  # Only insert if not found
        cursor.execute("INSERT INTO categories (name) VALUES (?)", (category,))
    
conn.commit()

# Predefined prices for services
service_prices = {
    "Home Repair & Maintenance": {
        "Electrician": 1000,
        "Plumber": 1200,
        "Carpenter": 1500,
        "Painter": 1100,
        "Appliance Repair": 2000
    },
    "Beauty & Personal Care": {
        "Haircuts": 500,
        "Makeup Artist": 2500,
        "Facial": 1500,
        "Spa Services": 3000,
        "Manicure & Pedicure": 1000
    },
    "Cleaning & Housekeeping": {
        "Sofa Cleaning": 700,
        "House Cleaning": 1500,
        "Carpet Cleaning": 800,
        "Water Tank Cleaning": 1000
    },
    "Fitness & Health": {
        "Personal Trainer": 2000,
        "Yoga Instructor": 1500,
        "Dietitian": 1000,
        "Fitness Coach": 1800
    },
    "Construction & Renovation": {
        "Carpenter": 2000,
        "Painter": 1800,
        "Electrician": 2500,
        "Plumber": 2200,
        "Interior Designer": 3000
    },
    "Outdoor & Gardening": {
        "Gardener": 1000,
        "Pest Control": 1500,
        "Landscaper": 1800,
        "Outdoor Cleaning": 1200,
        "Lawn Maintenance": 1300
    }
}

# Insert services with predefined prices, ensuring no duplicates
for category_name, services in service_prices.items():
    cursor.execute("SELECT id FROM categories WHERE name = ?", (category_name,))
    category_id = cursor.fetchone()[0]  # Get the category ID
    
    for service_name, price in services.items():
        # Check if the service already exists under this category
        cursor.execute("SELECT id FROM services WHERE category_id = ? AND name = ?", (category_id, service_name))
        if cursor.fetchone() is None:  # Only insert if not found
            cursor.execute("INSERT INTO services (category_id, name, price) VALUES (?, ?, ?)", 
                           (category_id, service_name, price))

conn.commit()

# Fetch and display the inserted data to verify
cursor.execute('''
SELECT c.name as category, s.name as service, s.price
FROM services s
JOIN categories c ON s.category_id = c.id
ORDER BY c.id, s.id
''')

rows = cursor.fetchall()
for row in rows:
    print(f"Category: {row[0]}, Service: {row[1]}, Price: {row[2]}")

# Close the connection
conn.close()
