import requests


class CloudflareManager:
    BASE_URL = 'https://api.cloudflare.com/client/v4'

    def __init__(self, api_token: str):
        self.api_token = api_token

    @property
    def _headers(self):
        return {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json',
        }

    def _request(self, method: str, path: str, **kwargs):
        url = f'{self.BASE_URL}{path}'
        resp = requests.request(method=method, url=url, headers=self._headers, timeout=15, **kwargs)
        data = resp.json()
        if not data.get('success'):
            errors = data.get('errors') or []
            msg = '; '.join([e.get('message', str(e)) for e in errors]) or f'HTTP {resp.status_code}'
            raise RuntimeError(msg)
        return data.get('result')

    def list_dns_records(self, zone_id: str, record_type: str = None, name: str = None):
        params = {}
        if record_type:
            params['type'] = record_type
        if name:
            params['name'] = name
        return self._request('GET', f'/zones/{zone_id}/dns_records', params=params)

    def create_dns_record(self, zone_id: str, name: str, record_type: str, content: str, ttl: int = 120, proxied: bool = False):
        payload = {
            'type': record_type,
            'name': name,
            'content': content,
            'ttl': ttl,
            'proxied': proxied,
        }
        return self._request('POST', f'/zones/{zone_id}/dns_records', json=payload)

    def update_dns_record(self, zone_id: str, record_id: str, name: str, record_type: str, content: str, ttl: int = 120, proxied: bool = False):
        payload = {
            'type': record_type,
            'name': name,
            'content': content,
            'ttl': ttl,
            'proxied': proxied,
        }
        return self._request('PUT', f'/zones/{zone_id}/dns_records/{record_id}', json=payload)

    def delete_dns_record(self, zone_id: str, record_id: str):
        return self._request('DELETE', f'/zones/{zone_id}/dns_records/{record_id}')

    def upsert_dns_record(self, zone_id: str, domain: str, record_type: str, content: str, ttl: int = 120, proxied: bool = False):
        existing = self.list_dns_records(zone_id=zone_id, record_type=record_type, name=domain)
        if existing:
            target = existing[0]
            return self.update_dns_record(
                zone_id=zone_id,
                record_id=target['id'],
                name=domain,
                record_type=record_type,
                content=content,
                ttl=ttl,
                proxied=proxied,
            )
        return self.create_dns_record(
            zone_id=zone_id,
            name=domain,
            record_type=record_type,
            content=content,
            ttl=ttl,
            proxied=proxied,
        )
