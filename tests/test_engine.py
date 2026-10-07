"""引擎层单元测试。

覆盖：测试执行器（步骤/断言/超时/取消）、cron、环境依赖解析、
覆盖率、报告生成、缺陷、通知。
"""

from __future__ import annotations

import datetime
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import (CoverageAnalyzer, CronSchedule, DefectManager,
                    EnvironmentManager, NotificationManager, ReportGenerator,
                    TestExecutor, cron_matches, parse_cron)
from engine.executor import evaluate_assertion, resolve_expr, safe_eval
from storage import BuildStoreRegistry, StoreRegistry


class TestResolveExpr(unittest.TestCase):
    def test_pure_reference_returns_value(self):
        self.assertEqual(resolve_expr("${a.b}", {"a": {"b": 42}}), 42)

    def test_partial_substitution(self):
        self.assertEqual(resolve_expr("x=${a}", {"a": "hi"}), "x=hi")

    def test_missing_path_returns_none(self):
        self.assertIsNone(resolve_expr("${a.b.c}", {"a": {}}))

    def test_list_index(self):
        self.assertEqual(resolve_expr("${items.0}", {"items": ["x", "y"]}), "x")


class TestSafeEval(unittest.TestCase):
    def test_arithmetic(self):
        self.assertEqual(safe_eval("2 + 3 * 4", {}), 14)

    def test_forbidden_import(self):
        with self.assertRaises(Exception):
            safe_eval("__import__('os')", {})

    def test_forbidden_attribute(self):
        with self.assertRaises(Exception):
            safe_eval("().__class__", {})


class TestEvaluateAssertion(unittest.TestCase):
    def test_equals_with_string_number(self):
        ok, _ = evaluate_assertion("equals", 14, "14")
        self.assertTrue(ok)

    def test_between(self):
        ok, _ = evaluate_assertion("between", 14, [10, 20])
        self.assertTrue(ok)
        ok, _ = evaluate_assertion("between", 5, [10, 20])
        self.assertFalse(ok)

    def test_regex(self):
        ok, _ = evaluate_assertion("regex", "release-2.31.0", r"^\d+\.\d+")
        # 注意：regex 比较的是 str(actual)
        ok, _ = evaluate_assertion("regex", "2.31.0-x", r"^\d+\.\d+")
        self.assertTrue(ok)

    def test_contains(self):
        ok, _ = evaluate_assertion("contains", {"ok": True}, "ok")
        self.assertTrue(ok)


class TestExecutorRun(unittest.TestCase):
    def test_passing_case(self):
        case = {
            "id": "c1", "name": "健康检查",
            "steps": [
                {"action": "request", "method": "GET", "url": "/api/health"},
                {"action": "assert", "type": "status", "actual": "${resp.status}", "expected": 200},
                {"action": "assert", "type": "truthy", "actual": "${resp.body.ok}", "expected": True},
            ],
        }
        result = TestExecutor().execute_case(case, {"latency_ms": 0})
        self.assertEqual(result["status"], "passed")

    def test_failing_case(self):
        case = {
            "id": "c2", "name": "失败",
            "steps": [
                {"action": "request", "method": "GET", "url": "/api/error"},
                {"action": "assert", "type": "status", "actual": "${resp.status}", "expected": 200},
            ],
        }
        result = TestExecutor().execute_case(case, {"latency_ms": 0})
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(result["assertions"]), 1)
        self.assertFalse(result["assertions"][0]["ok"])

    def test_script_and_between(self):
        case = {
            "id": "c3", "name": "脚本",
            "steps": [
                {"action": "script", "expr": "2 + 3 * 4", "save_as": "r"},
                {"action": "assert", "type": "equals", "actual": "${r}", "expected": 14},
                {"action": "assert", "type": "between", "actual": "${r}", "expected": [10, 20]},
            ],
        }
        result = TestExecutor().execute_case(case, {})
        self.assertEqual(result["status"], "passed")

    def test_timeout(self):
        case = {
            "id": "c4", "name": "超时", "timeout": 0.1,
            "steps": [
                {"action": "sleep", "seconds": 0.05},
                {"action": "sleep", "seconds": 0.05},
                {"action": "sleep", "seconds": 0.05},
            ],
        }
        result = TestExecutor().execute_case(case, {})
        self.assertEqual(result["status"], "timeout")

    def test_disabled_skipped(self):
        case = {"id": "c5", "name": "禁用", "enabled": False, "steps": []}
        result = TestExecutor().execute_case(case, {})
        self.assertEqual(result["status"], "skipped")

    def test_env_isolation_changes_result(self):
        """同一用例，高失败率环境与零失败率环境结果不同（环境隔离）。"""
        case = {
            "id": "c6", "name": "接口",
            "steps": [
                {"action": "request", "method": "GET", "url": "/api/health"},
                {"action": "assert", "type": "status", "actual": "${resp.status}", "expected": 200},
            ],
        }
        # 稳定环境：一定通过
        r1 = TestExecutor().execute_case(case, {"latency_ms": 0, "fail_rate": 0.0})
        self.assertEqual(r1["status"], "passed")
        # 失败率 1.0 的环境：一定失败
        r2 = TestExecutor().execute_case(case, {"latency_ms": 0, "fail_rate": 1.0})
        self.assertEqual(r2["status"], "failed")


class TestCron(unittest.TestCase):
    def test_parse_and_match(self):
        sched = parse_cron("*/10 * * * *")
        self.assertEqual(sched.minute, [0, 10, 20, 30, 40, 50])
        self.assertTrue(cron_matches("0 9 * * 1", datetime.datetime(2026, 10, 5, 9, 0)))
        self.assertFalse(cron_matches("0 9 * * 1", datetime.datetime(2026, 10, 6, 9, 0)))

    def test_invalid(self):
        with self.assertRaises(ValueError):
            parse_cron("* * *")


class TestEnvironments(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.registry = StoreRegistry(os.path.join(self.tmp.name, "store"))
        self.mgr = EnvironmentManager(self.registry, self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_resolve_dependencies(self):
        env = self.mgr.create("p1", {
            "name": "dev",
            "dependencies": [
                {"name": "requests", "constraint": ">=2.28"},
                {"name": "flask", "constraint": ">=3.0"},
                {"name": "numpy", "constraint": ">=99.0"},
            ],
        })
        resolved = self.mgr.resolve(env["id"])
        self.assertEqual(resolved["resolved_count"], 2)
        self.assertEqual(resolved["conflict_count"], 1)
        statuses = {d["name"]: d["status"] for d in resolved["dependencies"]}
        self.assertEqual(statuses["numpy"], "conflict")

    def test_workspace_isolation(self):
        e1 = self.mgr.create("p1", {"name": "a"})
        e2 = self.mgr.create("p1", {"name": "b"})
        self.assertNotEqual(self.mgr.workspace_dir(e1["id"]), self.mgr.workspace_dir(e2["id"]))
        self.assertTrue(os.path.isdir(self.mgr.workspace_dir(e1["id"])))

    def test_snapshot(self):
        env = self.mgr.create("p1", {"name": "dev", "variables": {"X": "1"}})
        snap = self.mgr.snapshot(env["id"])
        self.assertEqual(snap["variables"]["X"], "1")


class TestSensitiveVariables(unittest.TestCase):
    """敏感变量：明文照常执行注入，但所有对外出口都是掩码。"""

    SECRET = "db-password-123"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.registry = StoreRegistry(os.path.join(self.tmp.name, "store"))
        self.mgr = EnvironmentManager(self.registry, self.tmp.name)
        self.env = self.mgr.create("p1", {
            "name": "dev",
            "variables": {"REGION": "dev", "DB_PASSWORD": self.SECRET},
            "sensitive_variables": ["DB_PASSWORD"],
        })

    def tearDown(self):
        self.tmp.cleanup()

    def test_public_view_masks_sensitive(self):
        view = self.mgr.public_view(self.mgr.get(self.env["id"]))
        self.assertEqual(view["variables"]["DB_PASSWORD"], "******")
        self.assertEqual(view["variables"]["REGION"], "dev")
        # 列表接口同样掩码
        self.assertEqual(self.mgr.list_public("p1")[0]["variables"]["DB_PASSWORD"], "******")

    def test_snapshot_and_executor_config_keep_plaintext(self):
        snap = self.mgr.snapshot(self.env["id"])
        self.assertEqual(snap["variables"]["DB_PASSWORD"], self.SECRET)
        self.assertEqual(snap["sensitive_variables"], ["DB_PASSWORD"])
        cfg = self.mgr.to_executor_config(self.env["id"])
        self.assertEqual(cfg["variables"]["DB_PASSWORD"], self.SECRET)
        self.assertEqual(cfg["_sensitive_variables"], ["DB_PASSWORD"])

    def test_export_masks_sensitive(self):
        doc = self.mgr.export(self.env["id"])
        self.assertEqual(doc["environment"]["variables"]["DB_PASSWORD"], "******")
        self.assertIn("DB_PASSWORD", doc["environment"]["sensitive_variables"])
        self.assertNotIn(self.SECRET, repr(doc))

    def test_update_with_mask_keeps_original(self):
        # 前端编辑时把敏感值留成掩码哨兵提交 -> 原明文保留
        updated = self.mgr.update(self.env["id"], {
            "variables": {"REGION": "dev2", "DB_PASSWORD": "******"},
            "sensitive_variables": ["DB_PASSWORD"],
        })
        self.assertEqual(updated["variables"]["DB_PASSWORD"], self.SECRET)
        self.assertEqual(updated["variables"]["REGION"], "dev2")

    def test_update_sensitive_value(self):
        # 输入新值则覆盖
        updated = self.mgr.update(self.env["id"], {
            "variables": {"REGION": "dev", "DB_PASSWORD": "new-secret"},
            "sensitive_variables": ["DB_PASSWORD"],
        })
        self.assertEqual(updated["variables"]["DB_PASSWORD"], "new-secret")

    def test_unmark_sensitive(self):
        updated = self.mgr.update(self.env["id"], {
            "variables": {"REGION": "dev", "DB_PASSWORD": "visible-now"},
            "sensitive_variables": [],
        })
        self.assertEqual(updated["sensitive_variables"], [])
        self.assertEqual(self.mgr.public_view(updated)["variables"]["DB_PASSWORD"], "visible-now")


class TestLogRedaction(unittest.TestCase):
    """执行日志 / 结果中的敏感原值必须被掩码。"""

    SECRET = "s3cr3t-token"

    def _env_config(self):
        return {"latency_ms": 0, "variables": {"TOKEN": self.SECRET},
                "_sensitive_variables": ["TOKEN"]}

    def test_set_step_message_redacted(self):
        case = {"id": "c", "name": "设置口令", "steps": [
            {"action": "set", "key": "t", "value": "${TOKEN}", "name": "写入令牌"},
        ]}
        result = TestExecutor().execute_case(case, self._env_config())
        flat = repr(result)
        self.assertNotIn(self.SECRET, flat)
        self.assertIn("******", result["logs"][-1])

    def test_failed_assertion_actual_redacted(self):
        case = {"id": "c2", "name": "断言口令", "steps": [
            {"action": "assert", "type": "equals",
             "actual": "${TOKEN}", "expected": "other", "name": "口令应匹配"},
        ]}
        result = TestExecutor().execute_case(case, self._env_config())
        self.assertNotIn(self.SECRET, repr(result["assertions"]))
        self.assertNotIn(self.SECRET, "\n".join(result["logs"]))
        self.assertEqual(result["assertions"][0]["actual"], "******")

    def test_numeric_secret_redacted(self):
        case = {"id": "c3", "name": "数字口令", "steps": [
            {"action": "set", "key": "pin", "value": "${PIN}", "name": "写入 PIN"},
        ]}
        cfg = {"latency_ms": 0, "variables": {"PIN": 1234567},
               "_sensitive_variables": ["PIN"]}
        result = TestExecutor().execute_case(case, cfg)
        self.assertNotIn("1234567", repr(result))


class TestEnvironmentDiff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.registry = StoreRegistry(os.path.join(self.tmp.name, "store"))
        self.mgr = EnvironmentManager(self.registry, self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _map(self, rows, key_field="key"):
        return {r[key_field]: r for r in rows}

    def test_diff_variables_deps_config(self):
        a = self.mgr.create("p1", {
            "name": "dev", "python_version": "3.11",
            "variables": {"REGION": "dev", "ONLY_A": "x", "DB_PASSWORD": "p-dev"},
            "sensitive_variables": ["DB_PASSWORD"],
            "dependencies": [{"name": "requests", "constraint": ">=2.0"},
                             {"name": "flask", "constraint": ">=3.0"}],
            "config": {"base_url": "http://a", "latency_ms": 10, "fail_rate": 0.0},
        })
        b = self.mgr.create("p1", {
            "name": "staging", "python_version": "3.12",
            "variables": {"REGION": "staging", "ONLY_B": "y", "DB_PASSWORD": "p-stg"},
            "sensitive_variables": ["DB_PASSWORD"],
            "dependencies": [{"name": "requests", "constraint": ">=2.30"},
                             {"name": "django", "constraint": ">=4.2"}],
            "config": {"base_url": "http://b", "latency_ms": 10, "fail_rate": 0.2},
        })
        d = self.mgr.diff(a["id"], b["id"])
        vars_ = self._map(d["variables"])
        self.assertEqual(vars_["REGION"]["status"], "changed")
        self.assertEqual(vars_["ONLY_A"]["status"], "removed")
        self.assertEqual(vars_["ONLY_B"]["status"], "added")
        # 敏感项：明文不同 -> changed，但两侧值都只回掩码
        self.assertEqual(vars_["DB_PASSWORD"]["status"], "changed")
        self.assertTrue(vars_["DB_PASSWORD"]["sensitive"])
        self.assertEqual(vars_["DB_PASSWORD"]["base_value"], "******")
        self.assertEqual(vars_["DB_PASSWORD"]["target_value"], "******")
        self.assertNotIn("p-dev", repr(d))
        self.assertNotIn("p-stg", repr(d))

        deps = self._map(d["dependencies"], "name")
        self.assertEqual(deps["requests"]["status"], "changed")
        self.assertEqual(deps["flask"]["status"], "removed")
        self.assertEqual(deps["django"]["status"], "added")

        cfg = self._map(d["config"])
        self.assertEqual(cfg["base_url"]["status"], "changed")
        self.assertEqual(cfg["latency_ms"]["status"], "same")
        self.assertEqual(cfg["fail_rate"]["status"], "changed")

    def test_diff_identical_envs(self):
        payload = {"name": "x", "variables": {"A": "1"},
                   "dependencies": [{"name": "requests", "constraint": "*"}],
                   "config": {"base_url": "u", "latency_ms": 1, "fail_rate": 0}}
        a = self.mgr.create("p1", payload)
        b = self.mgr.create("p1", payload)
        d = self.mgr.diff(a["id"], b["id"])
        for section in ("variables", "dependencies", "config", "meta"):
            self.assertTrue(all(r["status"] == "same" for r in d[section]))

    def test_diff_missing_env(self):
        a = self.mgr.create("p1", {"name": "x"})
        self.assertIn("error", self.mgr.diff(a["id"], "env_nonexistent"))


class TestCoverage(unittest.TestCase):
    def test_stable_per_build(self):
        with tempfile.TemporaryDirectory() as d:
            reg = BuildStoreRegistry(os.path.join(d, "builds"))
            reg.for_project("p1").create("b1")
            cov = CoverageAnalyzer(reg)
            c1 = cov.generate("p1", "b1", 0.8)
            c2 = cov.generate("p1", "b1", 0.8)
            self.assertEqual(c1["percent"], c2["percent"])  # 确定性
            self.assertGreaterEqual(c1["percent"], 0)
            self.assertLessEqual(c1["percent"], 100)

    def test_trend(self):
        with tempfile.TemporaryDirectory() as d:
            reg = BuildStoreRegistry(os.path.join(d, "builds"))
            cov = CoverageAnalyzer(reg)
            for bid in ("b1", "b2"):
                reg.for_project("p1").create(bid)
                cov.generate("p1", bid, 0.5)
            self.assertEqual(len(cov.trend("p1")["points"]), 2)


class TestReport(unittest.TestCase):
    def test_report_metrics(self):
        with tempfile.TemporaryDirectory() as d:
            reg = BuildStoreRegistry(os.path.join(d, "builds"))
            store = reg.for_project("p1")
            store.create("b1")
            store.set_total("b1", 4)
            for i in range(4):
                store.record_result("b1", {"case_id": f"c{i}", "case_name": f"c{i}",
                                           "group": "g", "priority": "P1",
                                           "status": "passed" if i < 3 else "failed",
                                           "duration": 0.1 + i * 0.1, "logs": []})
            store.finish("b1", "failed")
            rep = ReportGenerator(reg).build_report("p1", "b1")
            self.assertEqual(rep["summary"]["passed"], 3)
            self.assertEqual(rep["summary"]["pass_rate"], 75.0)
            self.assertEqual(len(rep["failures"]), 1)
            self.assertAlmostEqual(rep["durations"]["max"], 0.4, places=3)


class TestDefects(unittest.TestCase):
    def test_create_from_case(self):
        with tempfile.TemporaryDirectory() as d:
            reg = StoreRegistry(os.path.join(d, "store"))
            mgr = DefectManager(reg)
            defect = mgr.create_from_case("p1", {
                "case_id": "c1", "case_name": "登录", "priority": "P0", "status": "failed",
                "assertions": [{"ok": False, "message": "期望 == 200"}], "steps": [],
            }, "b1")
            self.assertIsNotNone(defect)
            self.assertEqual(defect["source_case_id"], "c1")
            self.assertEqual(mgr.stats("p1")["total"], 1)


class TestNotify(unittest.TestCase):
    def test_fire_and_events(self):
        with tempfile.TemporaryDirectory() as d:
            reg = StoreRegistry(os.path.join(d, "store"))
            mgr = NotificationManager(reg)
            integration = mgr.create("p1", {"type": "webhook", "config": {"url": "http://x"},
                                            "events": ["build.failed"]})
            fired = mgr.fire("p1", "build.passed", {"build_id": "b1"})
            self.assertEqual(fired, [])  # 未订阅 build.passed
            fired = mgr.fire("p1", "build.failed", {"build_id": "b1"})
            self.assertEqual(len(fired), 1)
            self.assertEqual(fired[0]["status"], "delivered")
            self.assertEqual(len(mgr.events("p1")), 1)

    def test_test_delivery_without_target(self):
        with tempfile.TemporaryDirectory() as d:
            reg = StoreRegistry(os.path.join(d, "store"))
            mgr = NotificationManager(reg)
            integration = mgr.create("p1", {"type": "webhook", "config": {}})
            result = mgr.send_test(integration["id"])
            self.assertEqual(result["status"], "failed")


if __name__ == "__main__":
    unittest.main()
