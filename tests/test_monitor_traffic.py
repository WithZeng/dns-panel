import json
import unittest

from monitor import (
    _coerce_traffic_details,
    _detail_traffic_bytes,
    _region_matches,
    get_total_traffic_gb,
    BillingQueryError,
)


class _FakeClient:
    def __init__(self, payload):
        self.payload = payload

    def do_action_with_exception(self, _request):
        return json.dumps(self.payload)


class _RaiseClient:
    def __init__(self, message):
        self.message = message

    def do_action_with_exception(self, _request):
        raise Exception(self.message)


class MonitorTrafficTests(unittest.TestCase):
    def test_region_matches_finance_alias(self):
        self.assertTrue(_region_matches('cn-shenzhen', 'cn-shenzhen-finance'))
        self.assertTrue(_region_matches('cn-shenzhen-finance', 'cn-shenzhen'))

    def test_coerce_traffic_details_dict_wrapper(self):
        wrapped = {'TrafficDetail': [{'BusinessRegionId': 'cn-shenzhen', 'Traffic': 1024}]}
        details = _coerce_traffic_details(wrapped)
        self.assertEqual(len(details), 1)
        self.assertEqual(details[0]['BusinessRegionId'], 'cn-shenzhen')

    def test_detail_traffic_bytes_fallback_to_product_details(self):
        detail = {
            'Traffic': 0,
            'ProductTrafficDetails': [
                {'Product': 'cbwp', 'Traffic': 100},
                {'Product': 'ipv6bandwidth', 'Traffic': 200},
            ],
        }
        self.assertEqual(_detail_traffic_bytes(detail), 300)

    def test_get_total_traffic_gb_sum_matched_region(self):
        payload = {
            'TrafficDetails': [
                {'BusinessRegionId': 'cn-shenzhen', 'Traffic': 1073741824},
                {'BusinessRegionId': 'cn-hangzhou', 'Traffic': 2147483648},
            ]
        }
        gb = get_total_traffic_gb(_FakeClient(payload), 'cn-shenzhen')
        self.assertAlmostEqual(gb, 1.0, places=6)

    def test_get_total_traffic_gb_single_row_fallback(self):
        payload = {
            'TrafficDetails': [
                {'BusinessRegionId': '', 'Traffic': 1073741824},
            ]
        }
        gb = get_total_traffic_gb(_FakeClient(payload), 'cn-shenzhen')
        self.assertAlmostEqual(gb, 1.0, places=6)

    def test_get_total_traffic_gb_raise_on_error_auth(self):
        with self.assertRaises(BillingQueryError) as cm:
            get_total_traffic_gb(_RaiseClient('InvalidAccessKeyId.NotFound: bad key'), 'cn-shenzhen', raise_on_error=True)
        self.assertEqual(cm.exception.error_code, 'AUTH_FAILED')

    def test_get_total_traffic_gb_raise_on_error_permission(self):
        with self.assertRaises(BillingQueryError) as cm:
            get_total_traffic_gb(_RaiseClient('Unauthorized operation denied'), 'cn-shenzhen', raise_on_error=True)
        self.assertEqual(cm.exception.error_code, 'PERMISSION_DENIED')


if __name__ == '__main__':
    unittest.main()
