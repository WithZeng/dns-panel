
import os
from app import app, db, bootstrap_database
from models import User, EcsInstance
from werkzeug.security import generate_password_hash

with app.app_context():
    # 确保数据库表已创建并迁移
    bootstrap_database()
    
    # 创建默认管理员 (如果不存在)
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin', 
            password_hash=generate_password_hash('phg3can6hvw8BYW!dea'),
            force_password_change=False
        )
        db.session.add(admin)
        print("Admin user 'admin' created.")
    
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
