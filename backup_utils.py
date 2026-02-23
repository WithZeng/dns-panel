import os
import datetime
import logging
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SCOPES = ['https://www.googleapis.com/auth/drive.file']
SERVICE_ACCOUNT_FILE = 'service_account.json'
FOLDER_ID = '10sNijWM0SvN376TaHYUCH5qOZ4gX5GMJ' # Hardcoded Folder ID

def upload_to_drive():
    """
    Uploads the database file to Google Drive.
    """
    if not os.path.exists(SERVICE_ACCOUNT_FILE):
        logger.warning(f"Service account file '{SERVICE_ACCOUNT_FILE}' not found. Backup skipped.")
        return

    try:
        creds = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE, scopes=SCOPES)
        service = build('drive', 'v3', credentials=creds)

        # 1. Find DB file
        db_file = 'ecs_monitor.db'
        if not os.path.exists(db_file):
            # Check instance folder
            db_file = os.path.join('instance', 'ecs_monitor.db')
            if not os.path.exists(db_file):
                logger.error("Database file not found.")
                return

        # 2. Upload File (Directly using FOLDER_ID)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
        file_name = f"ecs_monitor_backup_{timestamp}.db"
        
        file_metadata = {
            'name': file_name,
            'parents': [FOLDER_ID]
        }
        media = MediaFileUpload(db_file, mimetype='application/x-sqlite3')
        
        file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
        logger.info(f"Backup successful: {file_name} (ID: {file.get('id')})")

        # 3. Cleanup Old Backups (>7 days)
        # Calculate threshold date
        threshold_date = datetime.datetime.now() - datetime.timedelta(days=7)
        # List files in specific folder
        query = f"'{FOLDER_ID}' in parents and trashed=false"
        results = service.files().list(q=query, fields="files(id, name, createdTime)").execute()
        files = results.get('files', [])

        for f in files:
            # Check filename format or createdTime
            # Google Drive createdTime is ISO format: 2023-10-27T10:00:00.000Z
            created_time_str = f.get('createdTime')
            if created_time_str:
                try:
                    # layout: 2023-10-27T10:00:00.000Z
                    created_time = datetime.datetime.strptime(created_time_str.split('.')[0], "%Y-%m-%dT%H:%M:%S")
                    if created_time < threshold_date:
                        service.files().delete(fileId=f['id']).execute()
                        logger.info(f"Deleted old backup: {f['name']}")
                except Exception as e:
                    logger.warning(f"Failed to parse time for {f['name']}: {e}")

    except Exception as e:
        logger.error(f"Backup failed: {e}") 
