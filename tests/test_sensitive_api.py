"""敏感变量与环境对比的 HTTP 端到端测试。

验证所有「会把变量带出去」的接口出口都拿不到敏感明文：
环境列表 / 详情、环境导出、环境差异（含下载）、执行日志、用例结果、报告；
同时确认执行时明文照常注入（用例引用敏感变量能正常参与断言）。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402

SECRET_DEV = "dev-db-pass-9F3k"
SECRET_STG = "stg-db-pass-7QaZ"


class SensitiveApiFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app(data_root=self.tmp.name)
        self.client = self.app.test_client()
        self._seed_envs()

    def tearDown(self):
        scheduler = self.app.config.get("SCHEDULER")
        if scheduler is not None:
            # 等待启动时自动 seed 触发的在途构建收尾，避免后台线程仍在
            # 临时目录写文件时清理目录（与既有调度器测试相同的竞态）。
            deadline = time.time() + 20
            while time.time() < deadline:
                if not scheduler.running():
                    break
                time.sleep(0.05)
            scheduler.shutdown()
        self.tmp.cleanup()

    def _post(self, path, body):
        return self.client.post(path, data=json.dumps(body),
                                content_type="application/json")

    def _seed_envs(self):
        resp = self.client.get("/api/projects")
        pid = resp.get_json()["projects"][0]["id"]
        self.pid = pid

        def mk(name, secret, region, latency):
            r = self._post(f"/api/projects/{pid}/environments", {
                "name": name,
                "variables": {"REGION": region, "DB_PASSWORD": secret},
                "sensitive_variables": ["DB_PASSWORD"],
                "config": {"base_url": f"http://{region}.mock.local",
                           "latency_ms": latency, "fail_rate": 0.0},
                "dependencies": [{"name": "requests", "constraint": ">=2.28"}],
            })
            return r.get_json()

        self.env_dev = mk("dev-敏感测试", SECRET_DEV, "dev", 0)
        self.env_stg = mk("staging-敏感测试", SECRET_STG, "staging", 0)

    # -- 页面接口 ---------------------------------------------------------
    def test_list_and_detail_mask_secret(self):
        data = self.client.get(f"/api/projects/{self.pid}/environments").get_json()
        for env in data["environments"]:
            self.assertEqual(env["variables"]["DB_PASSWORD"], "******")
        detail = self.client.get(f"/api/environments/{self.env_dev['id']}").get_json()
        self.assertEqual(detail["variables"]["DB_PASSWORD"], "******")
        self.assertNotIn(SECRET_DEV, json.dumps(data, ensure_ascii=False))

    def test_export_masks_and_downloads(self):
        resp = self.client.get(f"/api/environments/{self.env_dev['id']}/export")
        self.assertEqual(resp.status_code, 200)
        doc = resp.get_json()
        self.assertEqual(doc["environment"]["variables"]["DB_PASSWORD"], "******")
        self.assertNotIn(SECRET_DEV, json.dumps(doc, ensure_ascii=False))

        resp = self.client.get(f"/api/environments/{self.env_dev['id']}/export?download=1")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
        self.assertNotIn(SECRET_DEV, resp.get_data(as_text=True))

    def test_diff_masks_but_reports_real_change(self):
        url = (f"/api/envs/diff?base={self.env_dev['id']}"
               f"&target={self.env_stg['id']}")
        d = self.client.get(url).get_json()
        vars_ = {r["key"]: r for r in d["variables"]}
        row = vars_["DB_PASSWORD"]
        self.assertEqual(row["status"], "changed")      # 明文不同 -> 真差异
        self.assertEqual(row["base_value"], "******")   # 但值只回掩码
        self.assertEqual(row["target_value"], "******")
        self.assertNotIn(SECRET_DEV, json.dumps(d, ensure_ascii=False))
        self.assertNotIn(SECRET_STG, json.dumps(d, ensure_ascii=False))

        resp = self.client.get(url + "&download=1")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
        self.assertNotIn(SECRET_DEV, resp.get_data(as_text=True))
        self.assertNotIn(SECRET_STG, resp.get_data(as_text=True))

    # -- 执行链路 ---------------------------------------------------------
    def _make_case_and_run_single(self, secret):
        """单条用例试跑：引用敏感变量做断言，验证明文注入 + 日志掩码。"""
        case = self._post(f"/api/projects/{self.pid}/cases", {
            "name": f"敏感变量用例 {secret[:4]}",
            "priority": "P1",
            "steps": [
                {"action": "set", "key": "pw", "value": "${DB_PASSWORD}",
                 "name": "注入数据库口令"},
                {"action": "assert", "type": "equals",
                 "actual": "${pw}", "expected": secret, "name": "口令注入正确"},
            ],
        }).get_json()
        resp = self._post(f"/api/cases/{case['id']}/run",
                          {"env_id": self.env_dev["id"]}).get_json()
        return case, resp

    def test_execution_injects_plaintext_but_logs_are_masked(self):
        case, result = self._make_case_and_run_single(SECRET_DEV)
        # 明文照常注入：断言按真实值比较，用例通过
        self.assertEqual(result["status"], "passed")
        # 日志 / 步骤 / 断言里没有明文
        flat = json.dumps(result, ensure_ascii=False)
        self.assertNotIn(SECRET_DEV, flat)
        self.assertIn("******", flat)

    def test_full_build_logs_and_results_masked(self):
        """跑一场构建，检查构建日志、用例日志、结果、报告四个出口。"""
        case = self._post(f"/api/projects/{self.pid}/cases", {
            "name": "构建日志敏感检查",
            "priority": "P1",
            "steps": [
                {"action": "set", "key": "pw", "value": "${DB_PASSWORD}"},
                {"action": "assert", "type": "equals",
                 "actual": "${pw}", "expected": SECRET_DEV},
            ],
        }).get_json()
        suites = self.client.get(
            f"/api/projects/{self.pid}/suites").get_json()["suites"]
        suite_id = suites[0]["id"]
        # 把套件指向 dev 环境与该用例
        self.client.put(f"/api/suites/{suite_id}",
                        data=json.dumps({"env_id": self.env_dev["id"],
                                         "case_ids": [case["id"]]}),
                        content_type="application/json")
        build = self._post(f"/api/suites/{suite_id}/run",
                           {"env_id": self.env_dev["id"]}).get_json()
        build_id = build["id"]

        deadline = time.time() + 20
        while time.time() < deadline:
            b = self.client.get(f"/api/builds/{build_id}").get_json()
            if b["status"] in ("passed", "failed", "error", "cancelled"):
                break
            time.sleep(0.1)
        self.assertEqual(b["status"], "passed")

        logs = self.client.get(f"/api/builds/{build_id}/logs").get_data(as_text=True)
        results = self.client.get(
            f"/api/builds/{build_id}/results").get_data(as_text=True)
        case_log = self.client.get(
            f"/api/builds/{build_id}/cases/{case['id']}/log").get_data(as_text=True)
        report = self.client.get(
            f"/api/builds/{build_id}/report").get_data(as_text=True)
        for label, text in (("build logs", logs), ("results", results),
                            ("case log", case_log), ("report", report)):
            self.assertNotIn(SECRET_DEV, text, f"敏感明文泄漏到 {label}")


if __name__ == "__main__":
    unittest.main()
