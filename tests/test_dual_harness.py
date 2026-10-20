"""Contract checks for the local cross-harness coordinator."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import subprocess
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parents[1] / '.agents/skills/dual-harness/scripts/bridge.py'


class BridgeTests(unittest.TestCase):
    def setUp(self):
        # Exercise the library independently even when a worker runs this suite.
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop('DUAL_HARNESS_STAGE', None)
        self.assertTrue(SCRIPT.is_file(), 'The cross-harness bridge has not been implemented')
        spec = importlib.util.spec_from_file_location('dual_harness_bridge', SCRIPT)
        self.bridge = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.bridge)

    def config(self, **overrides):
        cfg = {
            'worker_model': 'opencode-go/deepseek-v4.1-flash',
            'complex_worker_model': 'opencode-go/kimi-k2.7-code',
            'max_repairs': 2,
            'timeout_seconds': 900,
        }
        cfg.update(overrides)
        return cfg

    def test_second_coordinator_cannot_enter_same_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.bridge.workspace_lock(root):
                with self.assertRaisesRegex(RuntimeError, 'already active'):
                    with self.bridge.workspace_lock(root):
                        self.fail('concurrent coordinator entered')
            self.assertFalse((root / '.orchestration/active.lock').exists())

    def test_unconfirmed_termination_keeps_a_blocking_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(self.bridge.TerminationUnconfirmed):
                with self.bridge.workspace_lock(root):
                    raise self.bridge.TerminationUnconfirmed('worker may still be active')
            lock = json.loads((root / '.orchestration/active.lock').read_text())
            self.assertTrue(lock['recovery_required'])
            with self.assertRaisesRegex(RuntimeError, 'already active'):
                with self.bridge.workspace_lock(root):
                    self.fail('unsafe restart')

    def test_windows_taskkill_failure_is_not_reported_as_termination(self):
        process = Mock(pid=123)
        with patch.object(self.bridge.os, 'name', 'nt'), patch.object(self.bridge.subprocess, 'run', return_value=Mock(returncode=1)):
            with self.assertRaises(self.bridge.TerminationUnconfirmed):
                self.bridge.stop_process(process)

    def test_worker_cannot_start_recursive_pipeline(self):
        with patch.dict('os.environ', {'DUAL_HARNESS_STAGE': 'implement'}):
            with self.assertRaisesRegex(RuntimeError, 'Recursive'):
                self.bridge.check_entry()

    def test_change_report_covers_added_modified_and_deleted_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'old.py').write_text('old\n')
            (root / 'gone.py').write_text('gone\n')
            before = self.bridge.snapshot(root)
            (root / 'old.py').write_text('new\n')
            (root / 'gone.py').unlink()
            (root / 'added.py').write_text('added\n')
            report = self.bridge.change_report(root, before)
            self.assertEqual(report['modified'], ['old.py'])
            self.assertEqual(report['deleted'], ['gone.py'])
            self.assertEqual(report['added'], ['added.py'])
            self.assertIn('-old', report['diff'])
            self.assertIn('+new', report['diff'])

    def test_review_rejects_unstructured_or_ambiguous_success(self):
        for value in ('Looks good!', '{"approved":true}', '{"approved":"yes","findings":[]}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.bridge.parse_review(value)
        self.assertTrue(self.bridge.parse_review('{"approved":true,"findings":[],"summary":"checked"}')['approved'])

    def test_worker_error_event_is_failure_even_with_zero_exit(self):
        with self.assertRaisesRegex(RuntimeError, 'OpenCode'):
            self.bridge.worker_text('{"type":"error","error":{"message":"quota exceeded"}}\n')

    def test_worker_must_return_a_final_text(self):
        with self.assertRaises(RuntimeError):
            self.bridge.worker_text('{"type":"step_start"}\n')
        self.assertEqual(self.bridge.worker_text('{"type":"text","part":{"text":"done"}}\n'), 'done')

    def test_commands_keep_saved_auth_and_use_explicit_go_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = {'opencode': 'opencode-cli.exe', 'codex': 'codex.exe', 'worker_model': 'opencode-go/kimi-k2.7-code'}
            command = self.bridge.worker_command(cfg, 'hello')
            self.assertIn('opencode-go/kimi-k2.7-code', command)
            self.assertNotIn('--standalone', command)
            self.assertNotIn('--auto', command)
            command = self.bridge.codex_command(cfg, root, root / 'result.txt')
            self.assertIn('read-only', command)
            self.assertNotIn('--dangerously-bypass-approvals-and-sandbox', command)
            self.assertNotIn('--ignore-rules', command)

    def test_live_session_url_targets_the_real_opencode_chat(self):
        self.assertEqual(
            self.bridge.session_url('http://127.0.0.1:45278', 'ses_example'),
            'http://127.0.0.1:45278/server/aHR0cDovLzEyNy4wLjAuMTo0NTI3OA/session/ses_example')

    def test_repairs_reuse_visible_worker_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            job = root / 'job'
            job.mkdir()
            cfg = {'opencode': 'opencode-cli.exe', 'worker_model': 'opencode-go/kimi-k2.7-code',
                   'timeout_seconds': 30, 'open_live_session': True}
            with patch.object(self.bridge, 'api_call', return_value={'data': {'id': 'ses_example'}}) as api, patch.object(self.bridge, 'service_url', return_value='http://127.0.0.1:45278'), patch.object(self.bridge.webbrowser, 'open', return_value=True) as browser, patch.object(self.bridge, 'execute', return_value='{"type":"text","part":{"text":"done"}}\n') as execute:
                self.bridge.run_worker(cfg, root, job, 'implement-0', 'assignment')
                self.bridge.run_worker(cfg, root, job, 'implement-1', 'repair')
            self.assertEqual(api.call_count, 1)
            self.assertEqual(api.call_args.args[3]['model'], {'providerID': 'opencode-go', 'id': 'kimi-k2.7-code'})
            self.assertEqual(browser.call_count, 1)
            self.assertEqual(execute.call_args_list[0].args[0][-4:-2], ['--session', 'ses_example'])
            self.assertTrue((job / 'opencode-session.json').is_file())

    def test_interrupt_refuses_to_confirm_a_still_active_shared_worker(self):
        with patch.object(self.bridge, 'api_call', side_effect=[{'interrupted': True}, {'data': [{'id': 'ses_example'}]}]):
            with self.assertRaises(self.bridge.TerminationUnconfirmed):
                self.bridge.interrupt_session({}, Path.cwd(), 'ses_example')

    def test_failed_review_never_becomes_success_at_repair_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = {'approved': False, 'findings': ['still wrong'], 'summary': 'fails acceptance'}
            with patch.object(self.bridge, 'run_codex', side_effect=['plan', json.dumps(bad), json.dumps(bad)]), patch.object(self.bridge, 'run_worker', return_value='done') as worker:
                result = self.bridge.pipeline(root, 'task', self.config(max_repairs=1))
            self.assertEqual(result['status'], 'needs_attention')
            self.assertEqual(worker.call_count, 2)

    def test_success_requires_independent_approved_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            approved = {'approved': True, 'findings': [], 'summary': 'acceptance verified'}
            with patch.object(self.bridge, 'run_codex', side_effect=['plan', json.dumps(approved)]), patch.object(self.bridge, 'run_worker', return_value='done'):
                result = self.bridge.pipeline(root, 'task', self.config())
            self.assertEqual(result['status'], 'approved')
            self.assertEqual(result['rounds'], 1)

    def test_pipeline_records_failure_and_releases_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(self.bridge, 'run_codex', side_effect=RuntimeError('provider unavailable')):
                result = self.bridge.pipeline(root, 'task', self.config(max_repairs=0))
            self.assertEqual(result['status'], 'failed')
            self.assertFalse((root / '.orchestration/active.lock').exists())
            saved = json.loads(Path(result['job_dir'], 'result.json').read_text())
            self.assertEqual(saved['status'], 'failed')

    def test_settings_select_routine_flash_and_complex_kimi(self):
        settings = json.loads((self.bridge.SKILL / 'settings.json').read_text(encoding='utf-8'))
        self.assertEqual(settings['worker_model'], 'opencode-go/deepseek-v4.1-flash')
        self.assertEqual(settings['complex_worker_model'], 'opencode-go/kimi-k2.7-code')
        cfg = self.config()
        self.assertEqual(self.bridge.select_worker_model(cfg, 'routine'), 'opencode-go/deepseek-v4.1-flash')
        self.assertEqual(self.bridge.select_worker_model(cfg, 'complex'), 'opencode-go/kimi-k2.7-code')
        with self.assertRaises(ValueError):
            self.bridge.select_worker_model(cfg, 'difficult')
        with self.assertRaises(ValueError):
            self.bridge.select_worker_model(
                {'worker_model': 'anthropic/claude', 'complex_worker_model': 'opencode-go/kimi-k2.7-code'}, 'routine')
        with self.assertRaises(ValueError):
            self.bridge.select_worker_model(
                {'worker_model': 'opencode-go/deepseek-v4.1-flash', 'complex_worker_model': 'openai/gpt'}, 'complex')

    def test_load_config_requires_go_provider_models(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = Path(tmp)
            settings = skill / 'settings.json'
            base = {'max_repairs': 2, 'timeout_seconds': 900}
            with patch.object(self.bridge, 'SKILL', skill), patch.object(
                    self.bridge, 'discover_opencode', return_value='opencode-cli.exe'), patch.object(
                    self.bridge.shutil, 'which', return_value='codex.exe'):
                settings.write_text(json.dumps({**base, 'worker_model': 'anthropic/claude',
                                                'complex_worker_model': 'opencode-go/kimi-k2.7-code'}), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'worker_model'):
                    self.bridge.load_config()
                settings.write_text(json.dumps({**base, 'worker_model': 'opencode-go/deepseek-v4.1-flash',
                                                'complex_worker_model': 'openai/gpt'}), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'complex_worker_model'):
                    self.bridge.load_config()
                settings.write_text(json.dumps({**base, 'worker_model': 'opencode-go/deepseek-v4.1-flash'}),
                                    encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'complex_worker_model'):
                    self.bridge.load_config()
                settings.write_text(json.dumps({**base, 'worker_model': 'opencode-go/deepseek-v4.1-flash',
                                                'complex_worker_model': 'opencode-go/kimi-k2.7-code'}), encoding='utf-8')
                cfg = self.bridge.load_config()
            self.assertEqual(cfg['worker_model'], 'opencode-go/deepseek-v4.1-flash')
            self.assertEqual(cfg['complex_worker_model'], 'opencode-go/kimi-k2.7-code')

    def test_explicit_task_class_selects_model_and_is_recorded(self):
        for task_class, expected in (
                ('routine', 'opencode-go/deepseek-v4.1-flash'),
                ('complex', 'opencode-go/kimi-k2.7-code')):
            with self.subTest(task_class=task_class), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with patch.object(self.bridge, 'run_worker', return_value='done') as worker:
                    result = self.bridge.pipeline(root, 'task', self.config(), plan='brief',
                                                  review_mode='caller', task_class=task_class)
                self.assertEqual(result['status'], 'awaiting_review')
                self.assertEqual(result['task_class'], task_class)
                self.assertEqual(result['worker_model'], expected)
                self.assertEqual(worker.call_args.args[0]['worker_model'], expected)

    def test_caller_mode_with_supplied_plan_makes_no_codex_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def fake_worker(cfg, project, job, stage, prompt):
                (job / f'{stage}.txt').write_text('done', encoding='utf-8')
                return 'done'

            with patch.object(self.bridge, 'run_codex') as codex, patch.object(
                    self.bridge, 'run_worker', side_effect=fake_worker) as worker:
                result = self.bridge.pipeline(
                    root, 'same task text', self.config(), plan='same task text', review_mode='caller')
            codex.assert_not_called()
            self.assertEqual(worker.call_count, 1)
            self.assertEqual(result['status'], 'awaiting_review')
            self.assertNotEqual(result['status'], 'approved')
            self.assertIn('job_dir', result)
            self.assertTrue(Path(result['worker_report']).is_file())
            self.assertEqual(worker.call_args.args[4].count('same task text'), 1)
            saved = json.loads(Path(result['job_dir'], 'result.json').read_text(encoding='utf-8'))
            self.assertEqual(saved['status'], 'awaiting_review')
            self.assertEqual(saved['review_mode'], 'caller')

    def test_caller_mode_without_brief_keeps_legacy_codex_planning_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(self.bridge, 'run_codex', return_value='plan text') as codex, patch.object(
                    self.bridge, 'run_worker', return_value='done'):
                result = self.bridge.pipeline(root, 'task', self.config(), review_mode='caller')
            self.assertEqual(codex.call_count, 1)
            self.assertEqual(codex.call_args.args[3], 'plan')
            self.assertEqual(result['status'], 'awaiting_review')

    def test_empty_supplied_brief_is_rejected_without_harness_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(self.bridge, 'run_codex') as codex, patch.object(
                    self.bridge, 'run_worker') as worker:
                with self.assertRaisesRegex(ValueError, 'Plan brief is empty'):
                    self.bridge.pipeline(Path(tmp), 'task', self.config(), plan='   ')
            codex.assert_not_called()
            worker.assert_not_called()

    def test_cli_passes_supplied_plan_and_explicit_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.opencode/agents').mkdir(parents=True)
            (root / '.opencode/agents/bridge-worker.md').write_text('worker', encoding='utf-8')
            task = root / 'task.md'
            task.write_text('task brief', encoding='utf-8')
            plan = root / 'plan.md'
            plan.write_text('plan brief', encoding='utf-8')
            argv = ['bridge.py', 'run', '--project', str(root), '--task-file', str(task),
                    '--plan-file', str(plan), '--review-mode', 'caller', '--task-class', 'complex']
            with patch.object(self.bridge, 'load_config', return_value=self.config()), patch.object(
                    self.bridge, 'pipeline', return_value={'status': 'awaiting_review'}) as pipeline, patch.object(
                    self.bridge.sys, 'argv', argv):
                code = self.bridge.main()
            self.assertEqual(code, 0)
            pipeline.assert_called_once()
            self.assertEqual(pipeline.call_args.args[1], 'task brief')
            self.assertEqual(pipeline.call_args.kwargs['plan'], 'plan brief')
            self.assertEqual(pipeline.call_args.kwargs['task_class'], 'complex')
            self.assertEqual(pipeline.call_args.kwargs['review_mode'], 'caller')

    def test_supplied_plan_skips_codex_planning_but_keeps_codex_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            approved = {'approved': True, 'findings': [], 'summary': 'acceptance verified'}
            with patch.object(self.bridge, 'run_codex', return_value=json.dumps(approved)) as codex, patch.object(
                    self.bridge, 'run_worker', return_value='done'):
                result = self.bridge.pipeline(root, 'task', self.config(), plan='brief with acceptance criteria',
                                              review_mode='codex')
            self.assertEqual(result['status'], 'approved')
            self.assertEqual(codex.call_count, 1)
            self.assertEqual(codex.call_args.args[3], 'review-0')
            self.assertIn('brief with acceptance criteria', codex.call_args.args[4])
            self.assertEqual((Path(result['job_dir']) / 'plan.txt').read_text(encoding='utf-8'),
                             'brief with acceptance criteria')
            self.assertEqual(result['plan_source'], 'supplied')

    def test_supplied_pipeline_plan_keeps_bounded_repair_and_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = {'approved': False, 'findings': ['still wrong'], 'summary': 'fails acceptance'}
            good = {'approved': True, 'findings': [], 'summary': 'acceptance verified'}
            with patch.object(self.bridge, 'run_codex', side_effect=[json.dumps(bad), json.dumps(good)]), patch.object(
                    self.bridge, 'run_worker', return_value='done') as worker:
                result = self.bridge.pipeline(root, 'task', self.config(max_repairs=2),
                                              plan='brief', review_mode='codex')
            self.assertEqual(result['status'], 'approved')
            self.assertEqual(result['rounds'], 2)
            self.assertEqual(worker.call_count, 2)
            self.assertEqual(result['plan_source'], 'supplied')


if __name__ == '__main__':
    unittest.main()
