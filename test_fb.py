import os
from dotenv import load_dotenv
load_dotenv()
from backend import firebase_db
firebase_db.init_firebase()
import logging
logging.basicConfig(level=logging.ERROR)
try:
    print("Report:", firebase_db.report_malicious_url('https://test.com', 'test'))
except Exception as e:
    print("Exception report:", e)

try:
    print("Check:", firebase_db.get_community_trust('https://test.com'))
except Exception as e:
    print("Exception check:", e)
