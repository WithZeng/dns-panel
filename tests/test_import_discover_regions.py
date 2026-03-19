import json
import sys
import types
import unittest
from unittest.mock import patch

sys.modules.setdefault('fcntl', types.SimpleNamespace(flock=lambda *args, **kwargs: None, LOCK_EX=1, LOCK_NB=2, LOCK_UN=8))

from routes import _discover_ecs_instances_all_regions


class DiscoverRegionsTests(unittest.TestCase):
    @patch('aliyunsdkecs.request.v20140526.DescribeInstancesRequest.DescribeInstancesRequest.set_PageNumber', lambda self, page: None)
    @patch('aliyunsdkecs.request.v20140526.DescribeInstancesRequest.DescribeInstancesRequest.set_PageSize', lambda self, size: None)
    @patch('aliyunsdkecs.request.v20140526.DescribeInstancesRequest.DescribeInstancesRequest.set_accept_format', lambda self, fmt: None)
    @patch('aliyunsdkecs.request.v20140526.DescribeRegionsRequest.DescribeRegionsRequest.set_accept_format', lambda self, fmt: None)
    @patch('aliyunsdkcore.client.AcsClient')
    def test_discover_all_regions_includes_hk(self, mock_client_cls):
        class FakeClient:
            def __init__(self, ak, sk, region_id):
                self.region_id = region_id

            def add_endpoint(self, *args, **kwargs):
                return None

            def do_action_with_exception(self, request):
                request_name = request.__class__.__name__
                if request_name == 'DescribeRegionsRequest':
                    return json.dumps({
                        'Regions': {
                            'Region': [
                                {'RegionId': 'cn-hangzhou'},
                                {'RegionId': 'cn-hongkong'},
                            ]
                        }
                    })
                return json.dumps({
                    'Instances': {
                        'Instance': [
                            {
                                'InstanceId': f'i-{self.region_id}',
                                'InstanceName': f'ecs-{self.region_id}',
                                'RegionId': self.region_id,
                                'Status': 'Running',
                                'PublicIpAddress': {'IpAddress': []},
                                'VpcAttributes': {
                                    'PrivateIpAddress': {'IpAddress': []},
                                    'Ipv6Addresses': {'Ipv6Address': []},
                                },
                            }
                        ]
                    }
                })

        mock_client_cls.side_effect = FakeClient

        discovered = _discover_ecs_instances_all_regions('ak', 'sk', 'cn-hangzhou', scan_all_regions=True)
        region_ids = {item['region_id'] for item in discovered}

        self.assertIn('cn-hangzhou', region_ids)
        self.assertIn('cn-hongkong', region_ids)


if __name__ == '__main__':
    unittest.main()
