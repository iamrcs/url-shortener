import redis

# Redis connection for RQ
conn = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
