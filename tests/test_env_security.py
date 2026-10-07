"""环境敏感变量与环境对比的安全测试。

覆盖：
- 变量结构归一化（兼容旧的扁平写法）；
- 对外视图 / 导出 / 对比结果中敏感值一律掩码；
- 更新时掩码占位符保留旧真实值；
- 执行注入仍拿到真实值，但执行日志 / 步骤 / 断言中的敏感值被擦除；
- HTTP 层：环境接口、环境导出、环境对比及其导出均不回显明文。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import EnvironmentManager, TestExecutor
from engine.environments import (flat_variables, mask_variables,
                                 normalize_variables, sensitive_values)
from engine.models import SENSITIVE_MASK
from storage import StoreRegistry


def _make_mgr(tmpdir):
    registry = StoreRegistry(os.path.join(tmpdir, "store"))
    return EnvironmentManager(registry, tmpdir)


def _create_env(mgr, **overrides):
    payload = {
        "name": "dev",
        "variables": {
            "REGION": "dev",
            "DB_PASSWORD": {"value": "s3cret-pass", "sensitive": True},
        },
        "config": {"base_url": "http://mock.local", "latency_ms": 0, "fail_rate": 0.0},
    }
    payload.update(overrides)
    return mgr.create("p1", payload)


class TestNormalizeVariables(unittest.TestCase):
    def test_legacy_flat_becomes_non_sensitive(self):
        norm = normalize_variables({"A": "1", "B": 2})
        self.assertEqual(norm["A"], {"value": "1", "sensitive": False})
        self.assertEqual(norm["B"], {"value": 2, "sensitive": False})

    def test_marked_shape_kept(self):
        norm = normalize_variables({"P": {"value": "x", "sensitive": True}})
        self.assertEqual(norm["P"], {"value": "x", "sensitive": True})

    def test_flat_and_mask_helpers(self):
        raw = {"A": "1", "P": {"value": "pw", "sensitive": True}}
        self.assertEqual(flat_variables(raw), {"A": "1", "P": "pw"})
        self.assertEqual(sensitive_values(raw), ["pw"])
        masked = mask_variables(raw)
        self.assertEqual(masked["P"]["value"], SENSITIVE_MASK)
        self.assertEqual(masked["A"]["value"], "1")

    def test_non_dict_input(self):
        self.assertEqual(normalize_variables(None), {})
        self.assertEqual(normalize_variables(["x"]), {})


class TestSensitiveEnvManager(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mgr = _make_mgr(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_public_view_masks_but_storage_keeps_real_value(self):
        env = _create_env(self.mgr)
        public = self.mgr.public_view(self.mgr.get(env["id"]))
        self.assertEqual(public["variables"]["DB_PASSWORD"]["value"], SENSITIVE_MASK)
        self.assertTrue(public["variables"]["DB_PASSWORD"]["sensitive"])
        self.assertEqual(public["variables"]["REGION"]["value"], "dev")
        # 存储里仍是真实值（执行注入要用）
        stored = self.mgr.get(env["id"])
        self.assertEqual(stored["variables"]["DB_PASSWORD"]["value"], "s3cret-pass")

    def test_legacy_env_variables_normalized_on_read(self):
        # 直接往存储里塞旧格式（扁平 variables），模拟历史数据
        store = self.mgr._store
        store.insert({"id": "env_legacy", "project_id": "p1", "name": "legacy",
                      "variables": {"TOKEN": "abc"}})
        public = self.mgr.public_view(self.mgr.get("env_legacy"))
        self.assertEqual(public["variables"]["TOKEN"],
                         {"value": "abc", "sensitive": False})
        snap = self.mgr.snapshot("env_legacy")
        self.assertEqual(snap["variables"]["TOKEN"], "abc")

    def test_update_with_mask_placeholder_keeps_old_value(self):
        env = _create_env(self.mgr)
        self.mgr.update(env["id"], {"variables": {
            "REGION": {"value": "dev2", "sensitive": False},
            "DB_PASSWORD": {"value": SENSITIVE_MASK, "sensitive": True},
        }})
        stored = self.mgr.get(env["id"])
        self.assertEqual(stored["variables"]["DB_PASSWORD"]["value"], "s3cret-pass")
        self.assertEqual(stored["variables"]["REGION"]["value"], "dev2")

    def test_update_with_new_value_replaces(self):
        env = _create_env(self.mgr)
        self.mgr.update(env["id"], {"variables": {
            "DB_PASSWORD": {"value": "new-pass-9", "sensitive": True},
        }})
        stored = self.mgr.get(env["id"])
        self.assertEqual(stored["variables"]["DB_PASSWORD"]["value"], "new-pass-9")
        # 未提交的变量被移除（整体替换语义）
        self.assertNotIn("REGION", stored["variables"])

    def test_update_unmark_sensitive_keeps_value(self):
        env = _create_env(self.mgr)
        self.mgr.update(env["id"], {"variables": {
            "DB_PASSWORD": {"value": SENSITIVE_MASK, "sensitive": False},
        }})
        stored = self.mgr.get(env["id"])
        self.assertEqual(stored["variables"]["DB_PASSWORD"],
                         {"value": "s3cret-pass", "sensitive": False})

    def test_executor_config_has_real_values_and_secrets(self):
        env = _create_env(self.mgr)
        cfg = self.mgr.to_executor_config(env["id"])
        self.assertEqual(cfg["variables"]["DB_PASSWORD"], "s3cret-pass")
        self.assertEqual(cfg["sensitive_values"], ["s3cret-pass"])

    def test_export_masks_sensitive(self):
        env = _create_env(self.mgr)
        doc = self.mgr.export(env["id"])
        text = json.dumps(doc, ensure_ascii=False)
        self.assertNotIn("s3cret-pass", text)
        self.assertIn(SENSITIVE_MASK, text)
        self.assertEqual(doc["environment"]["variables"]["REGION"]["value"], "dev")


class TestExecutorScrubbing(unittest.TestCase):
    def test_sensitive_values_masked_in_logs_steps_assertions(self):
        case = {
            "id": "c1", "name": "用密钥登录",
            "steps": [
                {"action": "set", "key": "pwd", "value": "${DB_PASSWORD}",
                 "name": "取口令"},
                {"action": "assert", "type": "equals", "actual": "${pwd}",
                 "expected": "s3cret-pass", "name": "口令正确"},
                {"action": "assert", "type": "equals", "actual": "${pwd}",
                 "expected": "wrong", "name": "故意失败"},
            ],
        }
        env_config = {
            "latency_ms": 0,
            "variables": {"DB_PASSWORD": "s3cret-pass"},
            "sensitive_values": ["s3cret-pass"],
        }
        result = TestExecutor().execute_case(case, env_config)
        # 注入正常：第二、三步都基于真实值求值，第三步故意失败说明比较用的是真值
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["assertions"][0]["ok"])
        # 但输出的任何地方都不含明文
        blob = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("s3cret-pass", blob)
        self.assertIn(SENSITIVE_MASK, blob)
        self.assertEqual(result["assertions"][0]["actual"], SENSITIVE_MASK)
        self.assertEqual(result["assertions"][0]["expected"], SENSITIVE_MASK)

    def test_no_secrets_no_scrubbing(self):
        case = {"id": "c2", "name": "普通", "steps": [
            {"action": "set", "key": "x", "value": "hello"},
            {"action": "assert", "type": "equals", "actual": "${x}", "expected": "hello"},
        ]}
        result = TestExecutor().execute_case(case, {"latency_ms": 0})
        self.assertEqual(result["status"], "passed")
        self.assertIn("hello", json.dumps(result, ensure_ascii=False))


class TestEnvironmentDiff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mgr = _make_mgr(self.tmp.name)
        self.a = self.mgr.create("p1", {
            "name": "dev",
            "python_version": "3.11",
            "variables": {
                "REGION": "dev",
                "DB_PASSWORD": {"value": "pass-a", "sensitive": True},
                "ONLY_A": "x",
                "SAME_SECRET": {"value": "same-secret", "sensitive": True},
            },
            "dependencies": [{"name": "requests", "constraint": ">=2.28"}],
            "config": {"base_url": "http://a", "latency_ms": 10, "fail_rate": 0.0},
        })
        self.b = self.mgr.create("p1", {
            "name": "staging",
            "python_version": "3.12",
            "variables": {
                "REGION": "staging",
                "DB_PASSWORD": {"value": "pass-b", "sensitive": True},
                "ONLY_B": "y",
                "SAME_SECRET": {"value": "same-secret", "sensitive": True},
            },
            "dependencies": [{"name": "requests", "constraint": ">=2.30"},
                             {"name": "numpy", "constraint": "*"}],
            "config": {"base_url": "http://b", "latency_ms": 10, "fail_rate": 0.2},
        })

    def tearDown(self):
        self.tmp.cleanup()

    def test_diff_detects_all_change_kinds(self):
        diff = self.mgr.diff(self.a["id"], self.b["id"])
        self.assertFalse(diff["identical"])
        rows = {r["key"]: r for r in diff["variables"]}
        self.assertEqual(rows["REGION"]["status"], "changed")
        self.assertEqual(rows["ONLY_A"]["status"], "removed")
        self.assertEqual(rows["ONLY_B"]["status"], "added")
        # 真实值相同 → 判定为一致，即便两边都是敏感项
        self.assertEqual(rows["SAME_SECRET"]["status"], "same")

        deps = {d["name"]: d for d in diff["dependencies"]}
        self.assertEqual(deps["requests"]["status"], "changed")
        self.assertEqual(deps["numpy"]["status"], "added")

        cfg = {c["key"]: c for c in diff["config"]}
        self.assertEqual(cfg["base_url"]["status"], "changed")
        self.assertEqual(cfg["latency_ms"]["status"], "same")

        runtime = {r["key"]: r for r in diff["runtime"]}
        self.assertEqual(runtime["python_version"]["status"], "changed")

    def test_diff_masks_sensitive_values(self):
        diff = self.mgr.diff(self.a["id"], self.b["id"])
        text = json.dumps(diff, ensure_ascii=False)
        self.assertNotIn("pass-a", text)
        self.assertNotIn("pass-b", text)
        self.assertNotIn("same-secret", text)
        rows = {r["key"]: r for r in diff["variables"]}
        # 敏感项有差异：能看出来「不一样」，但看不到明文
        self.assertEqual(rows["DB_PASSWORD"]["status"], "changed")
        self.assertEqual(rows["DB_PASSWORD"]["a"], SENSITIVE_MASK)
        self.assertEqual(rows["DB_PASSWORD"]["b"], SENSITIVE_MASK)
        self.assertTrue(rows["DB_PASSWORD"]["a_sensitive"])
        # 非敏感项正常显示明文
        self.assertEqual(rows["REGION"]["a"], "dev")

    def test_diff_identical_envs(self):
        diff = self.mgr.diff(self.a["id"], self.a["id"])
        self.assertTrue(diff["identical"])
        self.assertEqual(diff["summary"]["variables"]["different"], 0)

    def test_diff_missing_env(self):
        self.assertIn("error", self.mgr.diff(self.a["id"], "env_nope"))


class TestEnvironmentAPI(unittest.TestCase):
    """HTTP 层：所有出口都不回显敏感明文。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # 预置一个项目，避免 create_app 自动播种并在后台触发构建（测试不需要，
        # 也防止后台构建与临时目录清理竞争）
        pre = StoreRegistry(os.path.join(self.tmp.name, "store"))
        pre.store("projects").insert({"id": "p1", "name": "测试项目"})
        from app import create_app
        self.app = create_app(self.tmp.name)
        self.client = self.app.test_client()
        self.mgr = self.app.config["ENV_MANAGER"]
        self.env = _create_env(self.mgr)
        self.other = self.mgr.create("p1", {
            "name": "staging",
            "variables": {"DB_PASSWORD": {"value": "other-pass", "sensitive": True}},
        })

    def tearDown(self):
        self.app.config["SCHEDULER"].shutdown()
        self.tmp.cleanup()

    def test_list_and_get_mask_sensitive(self):
        for path in ("/api/projects/p1/environments",
                     f"/api/environments/{self.env['id']}"):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200)
            body = resp.get_data(as_text=True)
            self.assertNotIn("s3cret-pass", body)
            self.assertIn(SENSITIVE_MASK, body)

    def test_create_returns_masked_and_stores_real(self):
        resp = self.client.post("/api/projects/p1/environments", json={
            "name": "prod",
            "variables": {"API_KEY": {"value": "key-12345", "sensitive": True}},
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["variables"]["API_KEY"]["value"], SENSITIVE_MASK)
        stored = self.mgr.get(data["id"])
        self.assertEqual(stored["variables"]["API_KEY"]["value"], "key-12345")

    def test_update_via_api_keeps_secret_on_mask(self):
        resp = self.client.put(f"/api/environments/{self.env['id']}", json={
            "variables": {"DB_PASSWORD": {"value": SENSITIVE_MASK, "sensitive": True}},
        })
        self.assertEqual(resp.status_code, 200)
        stored = self.mgr.get(self.env["id"])
        self.assertEqual(stored["variables"]["DB_PASSWORD"]["value"], "s3cret-pass")

    def test_export_endpoint_masks(self):
        resp = self.client.get(f"/api/environments/{self.env['id']}/export")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
        body = resp.get_data(as_text=True)
        self.assertNotIn("s3cret-pass", body)
        self.assertIn(SENSITIVE_MASK, body)

    def test_diff_endpoint_masks(self):
        resp = self.client.get(
            f"/api/environments/diff?a={self.env['id']}&b={self.other['id']}")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertNotIn("s3cret-pass", body)
        self.assertNotIn("other-pass", body)
        data = resp.get_json()
        self.assertFalse(data["identical"])

    def test_diff_export_endpoint_masks(self):
        resp = self.client.get(
            f"/api/environments/diff/export?a={self.env['id']}&b={self.other['id']}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
        body = resp.get_data(as_text=True)
        self.assertNotIn("s3cret-pass", body)
        self.assertNotIn("other-pass", body)

    def test_diff_requires_two_envs(self):
        resp = self.client.get("/api/environments/diff")
        self.assertEqual(resp.status_code, 400)

    def test_diff_route_not_swallowed_by_env_id(self):
        # /api/environments/diff 必须命中对比接口，而不是 get_environment("diff")
        resp = self.client.get("/api/environments/diff?a=x&b=y")
        self.assertEqual(resp.status_code, 404)  # 环境不存在，而非返回某个环境
        self.assertEqual(resp.get_json()["error"], "环境不存在")

    def test_single_case_run_scrubs_logs(self):
        case_store = self.app.config["STORE_REGISTRY"].store("cases")
        case_id = case_store.insert({
            "project_id": "p1", "name": "试跑", "steps": [
                {"action": "set", "key": "p", "value": "${DB_PASSWORD}"},
            ],
        })
        resp = self.client.post(f"/api/cases/{case_id}/run",
                                json={"env_id": self.env["id"]})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertNotIn("s3cret-pass", body)
        self.assertIn(SENSITIVE_MASK, body)


if __name__ == "__main__":
    unittest.main()
