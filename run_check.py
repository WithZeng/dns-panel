from app import app
from monitor import check_all_instances
with app.app_context():
    check_all_instances()
