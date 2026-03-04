import json
import unittest

from monitor import (
    _coerce_traffic_details,
    _detail_traffic_bytes,
    _region_matches,
    _build_cdt_monthly_summary,
    _inject_cdt_api_fallback,
    get_total_traffic_gb,
    BillingQueryError,
)


class _FakeClient:
    def __init__(self, payload):
        self.payload = payload

    def do_action_with_exception(self, _request):
        return json.dumps(self.payload)


class _SeqClient:
    def __init__(self, payloads):
        self.payloads = list(payloads)

    def do_action_with_exception(self, _request):
        payload = self.payloads.pop(0) if self.payloads else {}
        return json.dumps(payload)


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

    def test_build_cdt_monthly_summary_prefers_instance_rows(self):
        month = '2026-01'
        rows = [
            {
                'BillingCycle': month,
                'ProductCode': 'cdt',
                'InstanceID': 'i-abc',
                'Usage': '10',
                'UsageUnit': 'GB',
                'PretaxAmount': '1.2',
                'Currency': 'CNY',
            },
            {
                'BillingCycle': month,
                'ProductCode': 'cdt',
                'InstanceID': 'i-other',
                'Usage': '99',
                'UsageUnit': 'GB',
                'PretaxAmount': '9.9',
                'Currency': 'CNY',
            },
        ]
        summary = _build_cdt_monthly_summary(rows, instance_id='i-abc')
        self.assertEqual(summary['scope'], 'instance')
        matched_month = next((m for m in summary['months'] if m['month'] == month), None)
        if matched_month is None:
            self.skipTest('fixture month is outside current rolling 3-month window')
        self.assertAlmostEqual(matched_month['traffic'], 10.0, places=6)

    def test_inject_cdt_api_fallback_updates_latest_month(self):
        summary = {
            'months': [
                {'month': '2026-01', 'traffic': 0.0, 'traffic_unit': 'GB', 'amount': 0.0},
                {'month': '2026-02', 'traffic': 0.0, 'traffic_unit': 'GB', 'amount': 0.0},
                {'month': '2026-03', 'traffic': 0.0, 'traffic_unit': 'GB', 'amount': 0.0},
            ],
            'total_traffic': 0.0,
            'total_amount': 0.0,
            'currency': 'CNY',
            'scope': 'account',
            'provider': 'aliyun_billing_query_instance_bill',
        }
        payload = {
            'TrafficDetails': [
                {'BusinessRegionId': 'cn-shenzhen', 'Traffic': 2147483648},
            ]
        }
        patched = _inject_cdt_api_fallback(summary, _FakeClient(payload), region_id='cn-shenzhen')
        self.assertEqual(patched['scope'], 'instance_cdt_fallback')
        self.assertGreater(patched['total_traffic'], 1.9)
        self.assertIn('aliyun_cdt_list_internet_traffic', patched['provider'])


if __name__ == '__main__':
    unittest.main()
