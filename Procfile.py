web: gunicorn app:app --bind 0.0.0.0:10000
worker: python iso8583_server.py
