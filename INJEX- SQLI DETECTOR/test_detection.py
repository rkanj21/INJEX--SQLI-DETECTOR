"""
Test script to verify SQL injection detection and database logging
Run this to test if detection is working correctly
"""

import sqlite3
from sqli_detector import detect_sqli

# Test payloads
test_payloads = [
    "admin' OR 1=1--",
    "admin' UNION SELECT * FROM users--",
    "admin'; DROP TABLE users--",
    "admin' AND SLEEP(5)--",
    "admin' AND extractvalue(1, concat(version()))--",
    "normaluser123",  # Should NOT be detected
]

print("=" * 60)
print("TESTING SQL INJECTION DETECTION")
print("=" * 60)

for payload in test_payloads:
    print(f"\nTesting: {payload}")
    result = detect_sqli(payload)
    
    if result['is_sqli']:
        print(f"  ✅ DETECTED!")
        print(f"  Type: {result['attack_type']}")
        print(f"  Severity: {result['severity']}")
        print(f"  Pattern: {result['matched_pattern']}")
    else:
        print(f"  ✅ Clean (no attack detected)")

# Check database
print("\n" + "=" * 60)
print("CHECKING DATABASE")
print("=" * 60)

try:
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Check if attack_logs table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='attack_logs'")
    table_exists = cursor.fetchone()
    
    if table_exists:
        print("\n✅ attack_logs table exists")
        
        # Get table schema
        cursor.execute("PRAGMA table_info(attack_logs)")
        columns = cursor.fetchall()
        print("\nTable columns:")
        for col in columns:
            print(f"  - {col[1]} ({col[2]})")
        
        # Count records
        cursor.execute("SELECT COUNT(*) FROM attack_logs")
        count = cursor.fetchone()[0]
        print(f"\n📊 Total records in attack_logs: {count}")
        
        if count > 0:
            # Show last 5 records
            cursor.execute("""
                SELECT id, attack_type, severity, source_field, ip_address, timestamp 
                FROM attack_logs 
                ORDER BY id DESC 
                LIMIT 5
            """)
            records = cursor.fetchall()
            
            print("\nLast 5 attack records:")
            for record in records:
                print(f"  ID: {record[0]} | Type: {record[1]} | Severity: {record[2]} | Field: {record[3]} | IP: {record[4]} | Time: {record[5]}")
        else:
            print("\n⚠️  No records found in attack_logs table")
            print("   Try entering SQL injection payloads in the login form")
    else:
        print("\n❌ attack_logs table does NOT exist!")
        print("   Run: python app.py (it will create the database)")
    
    conn.close()
    
except sqlite3.OperationalError as e:
    print(f"\n❌ Database error: {e}")
    print("   Make sure database.db exists")
    print("   Run: python app.py to create it")
except Exception as e:
    print(f"\n❌ Error: {e}")

print("\n" + "=" * 60)
print("MANUAL TEST INSTRUCTIONS")
print("=" * 60)
print("""
1. Start the Flask app:
   python app.py

2. Open browser to: http://localhost:5000/login

3. Enter this in Username field:
   admin' OR 1=1--

4. Enter anything in Password field:
   test123

5. Click Login

6. You should see:
   - Red alert: "SQL Injection detected..."
   - Login should be blocked

7. Check database:
   python test_detection.py

8. Go to dashboard:
   http://localhost:5000/dashboard
   (You may need to login with valid credentials first)

Valid credentials:
- Username: admin
- Password: admin
OR
- Username: user  
- Password: user
""")