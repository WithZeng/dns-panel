"""
Webhook notification module.
Supports: WeChat Work (企业微信), DingTalk (钉钉), Telegram Bot.
Includes retry logic (3 attempts) and notification logging.
"""
import json
import time
import logging
import urllib.request

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds between retries


def send_wechat(webhook_url, message):
    """Send message via WeChat Work webhook."""
    payload = json.dumps({
        "msgtype": "text",
        "text": {"content": message}
    }).encode()
    req = urllib.request.Request(webhook_url, data=payload,
                                headers={'Content-Type': 'application/json'})
    urllib.request.urlopen(req, timeout=10)


def send_dingtalk(webhook_url, message):
    """Send message via DingTalk webhook."""
    payload = json.dumps({
        "msgtype": "text",
        "text": {"content": message}
    }).encode()
    req = urllib.request.Request(webhook_url, data=payload,
                                headers={'Content-Type': 'application/json'})
    urllib.request.urlopen(req, timeout=10)


def send_telegram(webhook_url, message):
    """Send message via Telegram Bot API. webhook_url should be:
       https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>
    """
    payload = json.dumps({
        "text": message,
    }).encode()
    req = urllib.request.Request(webhook_url, data=payload,
                                headers={'Content-Type': 'application/json'})
    urllib.request.urlopen(req, timeout=10)


_SENDERS = {
    'wechat': send_wechat,
    'dingtalk': send_dingtalk,
    'telegram': send_telegram,
}


def _log_notification(instance_name, notify_type, message, success, error_msg='', attempts=1):
    """Write a NotificationLog entry. Must be called inside app context."""
    try:
        from models import db, NotificationLog
        log = NotificationLog(
            instance_name=instance_name,
            notify_type=notify_type,
            message=message[:2000],  # truncate very long messages
            success=success,
            error_message=error_msg[:500] if error_msg else '',
            attempts=attempts,
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log notification: {e}")


def send_alert(notify_type, webhook_url, message, instance_name=''):
    """Dispatch alert to the configured channel with retry (up to 3 attempts).
    Logs every attempt to NotificationLog.
    """
    sender = _SENDERS.get(notify_type)
    if not sender:
        logger.warning(f"Unknown notify type: {notify_type}")
        _log_notification(instance_name, notify_type, message, False, f"Unknown type: {notify_type}")
        return False

    last_error = ''
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            sender(webhook_url, message)
            logger.info(f"Alert sent via {notify_type} (attempt {attempt})")
            _log_notification(instance_name, notify_type, message, True, attempts=attempt)
            return True
        except Exception as e:
            last_error = str(e)
            logger.warning(f"Alert attempt {attempt}/{MAX_RETRIES} failed ({notify_type}): {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

    logger.error(f"Alert failed after {MAX_RETRIES} attempts ({notify_type}): {last_error}")
    _log_notification(instance_name, notify_type, message, False, last_error, MAX_RETRIES)
    return False
