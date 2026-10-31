"""Offline presentation checks. No ENET/SSH calls or vehicle writes."""
import ast
import json
from pathlib import Path
import queue
import re
import string
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from i18n import Translator
import gui


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tr = Translator()

    def test_default_english_and_unknown_fallback(self):
        self.assertEqual(self.tr.language, 'en')
        raw = '[12:34:56] SSH OK as root: uid=0(root)\n'
        self.assertEqual(self.tr.log(raw), raw)
        self.tr.select('zh-CN')
        self.assertEqual(self.tr.t('Uncatalogued error'), 'Uncatalogued error')
        self.assertEqual(self.tr.log('RAW 31 02 A0 FD\n'), 'RAW 31 02 A0 FD\n')

    def test_logs_preserve_raw_data_and_timestamp(self):
        self.tr.select('zh-CN')
        for raw, expected in [
            ('[12:34:56] Found gateway 169.254.1.2 | VIN: TESTVIN1234567890\n', '找到网关 169.254.1.2 | VIN：TESTVIN1234567890'),
            ('[12:34:56] SSH connection failed: C:\\keys\\my.key\n', 'SSH 连接失败：C:\\keys\\my.key'),
            ('[12:34:56] MGU SSH port 22 is not open (25 ms).\n', 'MGU SSH 22 端口未开放（25 毫秒）。'),
            ('[12:34:56] Status: debug/SSH-open state is ON\n', '调试/SSH 开启状态：开启'),
        ]:
            translated = self.tr.log(raw)
            self.assertIn(expected, translated)
            self.assertIn('[12:34:56] [EN] ' + raw[len('[12:34:56] '):], translated)
        self.assertEqual(self.tr.log('C:\\keys\\ON\\id_rsa\n'), 'C:\\keys\\ON\\id_rsa\n')

    def test_placeholders_and_all_log_templates(self):
        self.tr.select('zh-CN')
        data = self.tr.catalogs['zh-CN']
        formatter = string.Formatter()
        for source, translated in data['strings'].items():
            self.assertEqual(re.findall(r'%[sd]', source), re.findall(r'%[sd]', translated), source)
        for item in data['logs']:
            fields = [field for _, field, _, _ in formatter.parse(item['source']) if field is not None]
            targets = [field for _, field, _, _ in formatter.parse(item['translation']) if field is not None]
            self.assertEqual(fields, [str(i) for i in range(len(fields))])
            self.assertEqual(sorted(fields), sorted(targets))
            values = ['VALUE' + f for f in fields]
            raw = item['source'].format(*values)
            rendered = self.tr.log(raw + '\n')
            self.assertIn(item['translation'].format(*values), rendered)
            self.assertIn('[EN] ' + raw + '\n', rendered)

    def test_future_language_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'xx.json').write_text(json.dumps({'name': 'Example', 'strings': {'Enable':'Example enable'}}))
            tr = Translator(directory)
            self.assertEqual(tr.language, 'en')
            tr.select('xx')
            self.assertEqual(tr.t('Enable'), 'Example enable')
            with self.assertRaises(ValueError): tr.select('unknown')

    def test_fragmented_prints(self):
        q = queue.Queue()
        writer = gui._QueueWriter(q)
        writer.write('SSH OK as root:')
        writer.write(' ')
        writer.write('uid=0(root)')
        self.assertTrue(q.empty())
        writer.write('\npartial')
        self.assertEqual(q.get_nowait(), 'SSH OK as root: uid=0(root)\n')
        writer.flush()
        self.assertEqual(q.get_nowait(), 'partial')


class GuiTests(unittest.TestCase):
    def setUp(self):
        self.root = gui.tk.Tk()
        self.root.withdraw()
        self.app = gui.App(self.root)

    def tearDown(self):
        self.root.destroy()

    def select(self, name):
        self.app.language.set(name)
        self.app._change_language()
        self.root.update_idletasks()

    def test_switch_preserves_inputs_busy_state_and_history(self):
        app = self.app
        app.vin.set('TESTVIN1234567890')
        app.gateway.set('169.254.1.2')
        app.mgu_ip.set('169.254.2.3')
        app.arch.set('id8-bcp')
        app.disable_debug.set(False)
        app.unique_key.set(True)
        args = app._common_args() + app._persist_args()
        app._append('Checking debug/SSH state...\n')
        app._busy(True)
        self.select('简体中文')
        self.assertEqual(app.btn_enable.cget('text'), '启用 SSH')
        self.assertEqual(self.root.title(), 'MGU iDrive SSH Tool')
        text = app.out.get('1.0', 'end-1c')
        self.assertIn('正在检查调试/SSH 状态', text)
        self.assertEqual(text, app.i18n.log('Checking debug/SSH state...\n'))
        self.assertEqual(app.status.cget('text'), '正在处理…')
        self.assertIn('disabled', app.btn_enable.state())
        self.assertEqual(args, app._common_args() + app._persist_args())
        self.select('English')
        self.assertEqual(app.btn_enable.cget('text'), 'Enable')
        self.assertEqual(self.root.title(), 'MGU iDrive SSH Tool')
        self.assertEqual(app.out.get('1.0', 'end').strip(), 'Checking debug/SSH state...')

    def test_catalog_credits_never_render(self):
        marker = 'TRANSLATOR_CREDIT_MUST_STAY_IN_README'
        for catalog in self.app.i18n.catalogs.values():
            catalog['translator'] = marker
            catalog['title_credit'] = marker
            catalog.setdefault('strings', {})['MGU iDrive SSH Tool'] = marker
        self.assertEqual(self.app.out.get('1.0', 'end-1c'), '')
        for language in ('简体中文', 'English', '简体中文'):
            self.select(language)
            self.assertEqual(self.root.title(), 'MGU iDrive SSH Tool')
            self.assertEqual(self.app.out.get('1.0', 'end-1c'), '')
            pending = [self.root]
            while pending:
                widget = pending.pop()
                pending.extend(widget.winfo_children())
                if 'text' in widget.keys():
                    self.assertNotIn(marker, str(widget.cget('text')))

    def test_buttons_send_identical_actions_in_both_languages(self):
        for language in ('English', '简体中文'):
            self.select(language)
            self.app.vin.set('TESTVIN1234567890')
            with patch.object(self.app, '_run') as run, patch.object(gui.messagebox, 'askyesno', return_value=True) as confirm:
                self.app.do_enable()
                self.assertEqual(run.call_args.args[0], ['enable','--persist','--no-unique-key','--yes','--vin','TESTVIN1234567890','--gateway','auto','--arch','id7'])
                self.app.do_flash()
                self.assertEqual(run.call_args.args[0][0], 'flash')
                self.assertIn('TESTVIN1234567890', confirm.call_args.args[1])
                self.app.do_disable()
                self.assertEqual(run.call_args.args[0][0], 'disable')
            self.app.vin.set('')
            with patch.object(gui.messagebox,'showerror') as error, patch.object(self.app,'_run') as run:
                self.app.do_flash()
                error.assert_called_once()
                run.assert_not_called()

    def test_ui_catalog_coverage(self):
        catalog = self.app.i18n.catalogs['zh-CN']['strings']
        for _, source in self.app._labels:
            self.assertIn(source, catalog)
        tree = ast.parse(Path(gui.__file__).read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Attribute) and node.func.attr == 't':
                if node.args and isinstance(node.args[0], ast.Constant):
                    self.assertIn(node.args[0].value, catalog)


if __name__ == '__main__':
    unittest.main()
