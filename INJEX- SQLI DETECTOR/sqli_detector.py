import re
import nltk
from nltk import pos_tag, word_tokenize

# Ensure required NLTK packages are downloaded
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('taggers/averaged_perceptron_tagger')
except LookupError:
    nltk.download('punkt')
    nltk.download('averaged_perceptron_tagger')

# SQL keywords and dangerous patterns
SQL_KEYWORDS = [
    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
    'UNION', 'WHERE', 'FROM', 'TABLE', 'DATABASE', 'EXEC', 'EXECUTE',
    'DECLARE', 'CAST', 'CONVERT', 'CHAR', 'VARCHAR', 'NCHAR', 'NVARCHAR'
]

SQL_FUNCTIONS = [
    'extractvalue', 'updatexml', 'concat', 'substring', 'ascii', 'char',
    'sleep', 'benchmark', 'waitfor', 'delay', 'load_file', 'into outfile',
    'into dumpfile', 'pg_sleep', 'dbms_lock', 'sys.fn_varbintohexstr'
]

# SQL Injection patterns
SQLI_PATTERNS = [
    r"('|\")(\s)*(OR|AND)(\s)+(\d+)(\s)*=(\s)*(\d+)",  # ' OR 1=1
    r"('|\")(\s)*(OR|AND)(\s)+('|\")\w+('|\")(\s)*=(\s)*('|\")\w+('|\")",  # ' OR 'a'='a'
    r"(--|#|\/\*|\*\/)",  # SQL comments
    r"(\bUNION\b.*\bSELECT\b)",  # UNION SELECT
    r"(\bSELECT\b.*\bFROM\b.*\bWHERE\b)",  # SELECT FROM WHERE
    r"(\bINSERT\b.*\bINTO\b)",  # INSERT INTO
    r"(\bDELETE\b.*\bFROM\b)",  # DELETE FROM
    r"(\bDROP\b.*\bTABLE\b)",  # DROP TABLE
    r"(\bEXEC\b|\bEXECUTE\b)",  # EXEC/EXECUTE
    r"(;.*(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b))",  # Stacked queries
    r"(\bINFORMATION_SCHEMA\b)",  # information_schema
    r"(@@version|@@servername|user\(\)|database\(\)|version\(\))",  # DB metadata functions
    r"(extractvalue|updatexml|concat|ascii|char|substring|sleep|benchmark|waitfor|delay)",  # Functions
    r"(0x[0-9a-fA-F]+)",  # Hex values
    r"(\bLIKE\b.*(%|_))",  # LIKE with wildcards in suspicious context
]

def detect_sqli(input_string):
    """
    Detects potential SQL injection attempts using pattern matching and POS tagging.
    
    Args:
        input_string: The user input string to check
        
    Returns:
        dict: {
            'is_sqli': bool,
            'attack_type': str,
            'severity': str (high/medium/low),
            'matched_pattern': str,
            'pos_analysis': dict
        }
    """
    if input_string is None or input_string.strip() == '':
        return {
            'is_sqli': False,
            'attack_type': None,
            'severity': None,
            'matched_pattern': None,
            'pos_analysis': {}
        }
    
    result = {
        'is_sqli': False,
        'attack_type': 'Unknown',
        'severity': 'low',
        'matched_pattern': None,
        'pos_analysis': {}
    }
    
    # Check for SQL injection patterns
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, input_string, re.IGNORECASE):
            result['is_sqli'] = True
            result['matched_pattern'] = pattern
            
            # Determine attack type and severity
            if re.search(r"\bUNION\b.*\bSELECT\b", input_string, re.IGNORECASE):
                result['attack_type'] = 'Union Based'
                result['severity'] = 'high'
            elif re.search(r"(extractvalue|updatexml)", input_string, re.IGNORECASE):
                result['attack_type'] = 'Error Based'
                result['severity'] = 'high'
            elif re.search(r"(sleep|benchmark|waitfor|delay)", input_string, re.IGNORECASE):
                result['attack_type'] = 'Time Based'
                result['severity'] = 'medium'
            elif re.search(r"('|\")(\s)*(OR|AND)(\s)+(\d+)(\s)*=(\s)*(\d+)", input_string, re.IGNORECASE):
                result['attack_type'] = 'Boolean Based'
                result['severity'] = 'medium'
            elif re.search(r"(\bDROP\b.*\bTABLE\b|\bDELETE\b.*\bFROM\b)", input_string, re.IGNORECASE):
                result['attack_type'] = 'Destructive'
                result['severity'] = 'high'
            else:
                result['attack_type'] = 'Generic SQLi'
                result['severity'] = 'medium'
            
            break
    
    # POS tagging analysis
    try:
        tokens = word_tokenize(input_string)
        pos_tags = pos_tag(tokens)
        
        # Store POS analysis
        for token, pos in pos_tags:
            result['pos_analysis'][token] = pos
        
        # Additional checks using POS tagging
        # Look for SQL keywords in the input
        for token, pos in pos_tags:
            if token.upper() in SQL_KEYWORDS:
                result['is_sqli'] = True
                if not result['matched_pattern']:
                    result['attack_type'] = 'Keyword Injection'
                    result['severity'] = 'low'
            
            # Check for SQL functions
            if token.lower() in [f.lower() for f in SQL_FUNCTIONS]:
                result['is_sqli'] = True
                if not result['matched_pattern']:
                    result['attack_type'] = 'Function Injection'
                    result['severity'] = 'medium'
        
        # Check for suspicious character sequences
        if any(char in input_string for char in ["'--", '"--', ';--', '/*', '*/']):
            result['is_sqli'] = True
            if not result['matched_pattern']:
                result['attack_type'] = 'Comment Injection'
                result['severity'] = 'medium'
        
    except Exception as e:
        print(f"Error in POS tagging: {e}")
    
    return result


def get_attack_explanation(attack_type):
    """
    Returns an explanation for the detected attack type.
    """
    explanations = {
        'Union Based': 'UNION-based SQL injection detected. Attacker is attempting to combine results from multiple SELECT statements to extract data.',
        'Boolean Based': 'Boolean-based blind SQL injection detected. Attacker is using TRUE/FALSE conditions to extract data bit by bit.',
        'Error Based': 'Error-based SQL injection detected. Attacker is using database error messages to extract information.',
        'Time Based': 'Time-based blind SQL injection detected. Attacker is using time delays to infer database information.',
        'Destructive': 'Destructive SQL injection detected. Attacker is attempting to DROP tables or DELETE data.',
        'Keyword Injection': 'SQL keyword injection detected. Input contains SQL keywords that may be used maliciously.',
        'Function Injection': 'SQL function injection detected. Input contains database functions that may be exploited.',
        'Comment Injection': 'SQL comment injection detected. Attacker is using SQL comments to bypass input validation.',
        'Generic SQLi': 'Generic SQL injection pattern detected. Input contains suspicious SQL-like syntax.'
    }
    return explanations.get(attack_type, 'Potential SQL injection detected.')