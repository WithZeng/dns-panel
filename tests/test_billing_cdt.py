import unittest
from unittest.mock import patch

from monitor import _build_cdt_monthly_summary


class BillingCdtAggregationTests(unittest.TestCase):
    @patch('monitor._month_keys_for_recent_three', return_value=['2026-01', '2026-02', '2026-03'])
    def test_build_cdt_monthly_summary_account_scope(self, _mock_months):
        rows = [
            {
                'BillingCycle': '202601',
                'ProductCode': 'cdt',
                'BillItem': 'InternetTraffic',
                'Usage': 1073741824,
                'UsageUnit': 'Byte',
                'PretaxAmount': 1.25,
                'Currency': 'CNY',
            },
            {
                'BillingCycle': '202602',
                'ProductCode': 'cdt',
                'BillItem': 'Traffic',
                'Usage': 2,
                'UsageUnit': 'GB',
                'PretaxAmount': 2.5,
                'Currency': 'CNY',
            },
        ]
        summary = _build_cdt_monthly_summary(rows, instance_id='')
        self.assertEqual(summary['scope'], 'account')
        self.assertEqual(len(summary['months']), 3)
        self.assertEqual(summary['months'][0]['month'], '2026-01')
        self.assertAlmostEqual(summary['months'][0]['traffic'], 1.0, places=4)
        self.assertAlmostEqual(summary['months'][1]['traffic'], 2.0, places=4)
        self.assertAlmostEqual(summary['total_traffic'], 3.0, places=4)
        self.assertAlmostEqual(summary['total_amount'], 3.75, places=4)

    @patch('monitor._month_keys_for_recent_three', return_value=['2026-01', '2026-02', '2026-03'])
    def test_build_cdt_monthly_summary_instance_scope(self, _mock_months):
        rows = [
            {
                'BillingCycle': '202602',
                'ProductCode': 'cdt',
                'BillItem': 'Traffic',
                'InstanceID': 'i-abc',
                'Usage': 1,
                'UsageUnit': 'GB',
                'PretaxAmount': 1.1,
                'Currency': 'CNY',
            },
            {
                'BillingCycle': '202602',
                'ProductCode': 'cdt',
                'BillItem': 'Traffic',
                'InstanceID': 'i-other',
                'Usage': 8,
                'UsageUnit': 'GB',
                'PretaxAmount': 8.8,
                'Currency': 'CNY',
            },
        ]
        summary = _build_cdt_monthly_summary(rows, instance_id='i-abc')
        self.assertEqual(summary['scope'], 'instance')
        self.assertAlmostEqual(summary['total_traffic'], 1.0, places=4)
        self.assertAlmostEqual(summary['total_amount'], 1.1, places=4)

    @patch('monitor._month_keys_for_recent_three', return_value=['2026-01', '2026-02', '2026-03'])
    def test_build_cdt_monthly_summary_instance_fallback_to_account_scope(self, _mock_months):
        rows = [
            {
                'BillingCycle': '202603',
                'ProductCode': 'cdt',
                'BillItem': 'Traffic',
                'Usage': 3,
                'UsageUnit': 'GB',
                'PretaxAmount': 6.6,
                'Currency': 'CNY',
            },
        ]
        summary = _build_cdt_monthly_summary(rows, instance_id='i-abc')
        self.assertEqual(summary['scope'], 'account')
        self.assertAlmostEqual(summary['total_traffic'], 3.0, places=4)
        self.assertAlmostEqual(summary['total_amount'], 6.6, places=4)


if __name__ == '__main__':
    unittest.main()
