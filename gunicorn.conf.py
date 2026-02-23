# Gunicorn production configuration
bind = "0.0.0.0:5000"
workers = 2
worker_class = "gevent"   # 必须用 gevent 才能支持 WebSocket
timeout = 120
accesslog = "-"
errorlog = "-"
loglevel = "info"

# gevent worker 不要 preload，避免 monkey-patch 问题
# preload_app = True
