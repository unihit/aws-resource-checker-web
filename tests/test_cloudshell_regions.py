import contextlib
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'collector'))
import cloudshell


class CloudShellRegions(unittest.TestCase):
    def test_current_region_prefers_cloudshell_region_over_sdk_default(self):
        self.assertEqual(cloudshell.current_region({'AWS_REGION':'eu-west-1','AWS_DEFAULT_REGION':'ap-northeast-2'}),'eu-west-1')

    def test_default_region_fallback(self):
        self.assertEqual(cloudshell.current_region({'AWS_DEFAULT_REGION':'us-west-2'}),'us-west-2')

    def test_missing_or_invalid_region_has_no_silent_seoul_fallback(self):
        for environ in ({},{'AWS_REGION':'all'},{'AWS_REGION':'x; bad'},{'AWS_REGION':'auto'},{'AWS_REGION':'bad','AWS_DEFAULT_REGION':'us-east-1'}):
            with self.subTest(environ=environ),self.assertRaises(ValueError):
                cloudshell.current_region(environ)

    def test_explicit_regions_override_environment(self):
        regions=cloudshell.parse_regions('ap-northeast-2,us-east-1,ap-northeast-2')
        self.assertEqual(cloudshell.resolve_regions(regions,{'AWS_REGION':'eu-west-1'}),['ap-northeast-2','us-east-1'])
        self.assertEqual(cloudshell.resolve_regions(['all'],{}),['all'])
        self.assertEqual(cloudshell.resolve_regions(['auto'],{'AWS_REGION':'eu-west-1'}),['eu-west-1'])

    def test_auto_and_all_are_exclusive(self):
        self.assertEqual(cloudshell.parse_regions('auto'),['auto'])
        for value in ('auto us-east-1','all auto','all us-east-1','', 'us-east-1; echo bad'):
            with self.subTest(value=value),self.assertRaises(ValueError):
                cloudshell.parse_regions(value)

    def invoke(self, argv, environment, reply=''):
        session=MagicMock()
        session.client.return_value.get_caller_identity.return_value={'Account':'000000000000','Arn':'arn:aws:iam::000000000000:role/demo'}
        observed_env={}
        def factory(**kwargs):
            observed_env.update(os.environ)
            return session
        stream=io.StringIO()
        with patch.dict(os.environ,environment,clear=True),patch.object(sys,'argv',['cloudshell.py',*argv]),\
             patch.object(cloudshell.Path,'home',return_value=Path('mock-home')),\
             patch('boto3.Session',side_effect=factory) as constructor,\
             patch('builtins.input',return_value=reply),patch.object(cloudshell.checker,'scan',return_value={'status':'COMPLETE'}) as scan,\
             patch.object(cloudshell.checker,'export_report',return_value=Path('mock-output/report')),\
             patch.object(cloudshell.zipfile,'ZipFile'),contextlib.redirect_stdout(stream):
            result=cloudshell.main()
        return result,constructor,scan,observed_env,stream.getvalue()

    def test_omitted_region_reaches_session_scan_and_confirmation(self):
        result,constructor,scan,_,output=self.invoke([],{'AWS_REGION':'eu-west-1'})
        self.assertEqual(result,0)
        constructor.assert_called_once_with(region_name='eu-west-1')
        self.assertEqual(scan.call_args.args[1],['eu-west-1'])
        self.assertIn('eu-west-1',output)
        self.assertIn('자동 감지',output)

    def test_manual_list_and_all_keep_their_meaning(self):
        _,constructor,scan,_,output=self.invoke(['--regions','us-west-2,ap-northeast-2'],{'AWS_REGION':'eu-west-1'})
        constructor.assert_called_once_with(region_name='us-west-2')
        self.assertEqual(scan.call_args.args[1],['us-west-2','ap-northeast-2'])
        self.assertIn('직접 지정',output)
        _,constructor,scan,_,_=self.invoke(['--regions','all'],{'AWS_REGION':'eu-west-1'})
        constructor.assert_called_once_with(region_name='eu-west-1')
        self.assertEqual(scan.call_args.args[1],['all'])

    def test_no_region_aborts_before_any_aws_call(self):
        with patch.dict(os.environ,{},clear=True),patch.object(sys,'argv',['cloudshell.py']),\
             patch.object(cloudshell.Path,'home',return_value=Path('mock-home')),\
             patch('boto3.Session') as constructor,contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as exc:
                cloudshell.main()
        self.assertEqual(exc.exception.code,2)
        constructor.assert_not_called()
        self.assertIn('현재 리전을 감지하지 못했습니다',stderr.getvalue())

    def test_account_confirmation_still_cancels_scan(self):
        result,_,scan,_,_=self.invoke([],{'AWS_REGION':'eu-west-1'},'n')
        self.assertEqual(result,0)
        scan.assert_not_called()

    def test_credential_isolation_and_forwarding_are_preserved(self):
        legacy={'AWS_ACCESS_KEY_ID':'dummy','AWS_SECRET_ACCESS_KEY':'dummy','AWS_SESSION_TOKEN':'dummy',
                'AWS_SECURITY_TOKEN':'dummy','AWS_PROFILE':'dummy','AWS_DEFAULT_PROFILE':'dummy',
                'AWS_ROLE_ARN':'dummy','AWS_WEB_IDENTITY_TOKEN_FILE':'dummy'}
        environment={**legacy,'AWS_REGION':'eu-west-1','AWS_DEFAULT_REGION':'ap-northeast-2',
                     'AWS_CONTAINER_CREDENTIALS_FULL_URI':'http://localhost/example',
                     'AWS_CONTAINER_AUTHORIZATION_TOKEN':'dummy-forwarded'}
        _,_,_,observed,_=self.invoke([],environment)
        self.assertTrue(all(key not in observed for key in legacy))
        self.assertEqual(observed['AWS_SHARED_CREDENTIALS_FILE'],os.devnull)
        self.assertEqual(observed['AWS_CONFIG_FILE'],os.devnull)
        self.assertEqual(observed['AWS_REGION'],'eu-west-1')
        self.assertEqual(observed['AWS_CONTAINER_AUTHORIZATION_TOKEN'],'dummy-forwarded')
        self.assertEqual(observed['AWS_CONTAINER_CREDENTIALS_FULL_URI'],'http://localhost/example')


if __name__=='__main__':
    unittest.main()
