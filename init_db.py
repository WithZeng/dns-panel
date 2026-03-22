
import os
import secrets
from app import app, db, bootstrap_database
from models import User, EcsInstance
from werkzeug.security import generate_password_hash

with app.app_context():
    bootstrap_database()
    
    if not User.query.filter_by(username='admin').first():
        initial_password = os.environ.get('ADMIN_PASSWORD', '').strip() or secrets.token_urlsafe(16)
        admin = User(
            username='admin', 
            password_hash=generate_password_hash(initial_password),
            force_password_change=True,
        )
        db.session.add(admin)
        print(f"Admin user 'admin' created with password: {initial_password}")
        print("Please change this password immediately after first login.")
    
    # 录入你提供的深圳实例
    AK = os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_ID', '')
    SK = os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_SECRET', '')
    INST_ID = os.environ.get('ALIBABA_CLOUD_INSTANCE_ID', '')
    
    existing_inst = EcsInstance.query.filter_by(instance_id=INST_ID).first()
    if not existing_inst:
        inst = EcsInstance(
            name='Shenzhen-1',
            region_id='cn-shenzhen',
            instance_id=INST_ID,
            status='Running',
            traffic_strategy='life',
            life_total_limit=500,
            monitoring_enabled=True,
            auto_start_enabled=True
        )
        inst.set_ak_sk(AK, SK)
        db.session.add(inst)
        print(f"Instance {INST_ID} added to DB.")
    else:
        # 更新现有实例的 AK/SK
        existing_inst.set_ak_sk(AK, SK)
        print(f"Instance {INST_ID} credentials updated.")
    
    db.session.commit()
    print("Database Initialization/Update complete.")
