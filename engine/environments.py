"""环境管理：配置、依赖解析、工作区隔离。

平台支持一个项目维护多套测试环境（如 dev / staging / prod），每套环境有：

- ``variables``     环境变量（执行时注入用例变量表），支持「敏感」标记：
                    敏感变量在页面 / 日志 / 导出 / 环境对比中只显示掩码，
                    但执行时仍注入真实值
- ``dependencies``  依赖清单（名称 + 版本约束），可一键「解析 / 刷新」
- ``config``        运行参数（base_url、latency_ms、fail_rate 等），
                    直接决定 :class:`~engine.executor.MockTarget` 的行为
- 独立工作区目录 ``data/envs/<env_id>/workspace``，环境之间互不污染

「环境隔离」的落地方式
----------------------
1. 每个环境有独立的磁盘工作区，临时产物、依赖快照分开存放；
2. 执行时把该环境的 ``variables`` + ``config`` 作为一份**快照**传给执行器，
   同一用例在不同环境跑，变量与行为参数完全不同；
3. 依赖解析是纯函数式的「快照解析」，不修改全局状态，并发刷新也安全。

敏感变量的落地方式
----------------------
变量统一存为 ``{KEY: {"value": ..., "sensitive": bool}}`` 结构（兼容旧的
扁平 ``{KEY: value}`` 写法，读取时自动归一化）。所有对外出口——
:meth:`EnvironmentManager.public_view`（页面展示）、
:meth:`EnvironmentManager.export`（环境导出）、
:meth:`EnvironmentManager.diff`（环境差异对比及其导出）——敏感值一律
替换为 ``SENSITIVE_MASK``；只有 :meth:`snapshot` / :meth:`to_executor_config`
（执行器注入）能拿到真实值，同时把敏感值列表一并交给执行器，
由执行器在日志落盘前做文本擦除（见 :mod:`engine.executor`）。

依赖解析为模拟实现：内置一个常见包的最新版本表，按语义化版本约束做简单
匹配（支持 ``>=`` / ``==`` / ``<`` / 无约束取最新）。
"""

from __future__ import annotations

import os
import re
import time
from typing import Any, Optional

from .models import SENSITIVE_MASK, new_id


# 内置「包仓库」：名称 -> 可用版本列表（从旧到新）
_PACKAGE_VERSIONS: dict[str, list[str]] = {
    "requests": ["2.20.0", "2.25.1", "2.28.2", "2.31.0"],
    "pytest": ["6.2.5", "7.4.0", "8.1.1"],
    "flask": ["2.2.5", "3.0.3"],
    "numpy": ["1.21.6", "1.24.4", "2.0.0"],
    "django": ["4.2.11", "5.0.6"],
    "selenium": ["4.9.1", "4.18.1"],
    "jinja2": ["3.1.4"],
    "httpx": ["0.24.1", "0.27.0"],
}


def _version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def _satisfies(version: str, constraint: str) -> bool:
    """判断版本是否满足 ``>=x`` / ``==x`` / ``<x`` / ``>x`` 这类简单约束。"""
    constraint = constraint.strip()
    if not constraint or constraint == "*":
        return True
    m = re.match(r"^(>=|<=|==|>|<)\s*(.+)$", constraint)
    if not m:
        # 视为精确版本
        return version == constraint
    op, target = m.group(1), m.group(2)
    a, b = _version_tuple(version), _version_tuple(target)
    if op == ">=":
        return a >= b
    if op == "<=":
        return a <= b
    if op == "==":
        return a == b
    if op == ">":
        return a > b
    if op == "<":
        return a < b
    return False


def _latest(versions: list[str]) -> str:
    return sorted(versions, key=_version_tuple)[-1]


# ---------------------------------------------------------------------------
# 变量结构：归一化 / 打平 / 掩码
# ---------------------------------------------------------------------------

def normalize_variables(raw: Any) -> dict:
    """把变量表统一成 ``{KEY: {"value": ..., "sensitive": bool}}`` 结构。

    兼容两种历史 / 外部写法：
    - 扁平写法 ``{"A": "1"}``               → 非敏感；
    - 带标记写法 ``{"A": {"value": "1", "sensitive": True}}``。
    """
    out: dict[str, dict] = {}
    if not isinstance(raw, dict):
        return out
    for key, val in raw.items():
        if isinstance(val, dict) and "value" in val:
            out[key] = {"value": val.get("value"),
                        "sensitive": bool(val.get("sensitive", False))}
        else:
            out[key] = {"value": val, "sensitive": False}
    return out


def flat_variables(variables: Any) -> dict:
    """取出真实值的扁平表 ``{KEY: value}``（仅执行注入等内部用途）。"""
    return {k: spec.get("value") for k, spec in normalize_variables(variables).items()}


def sensitive_values(variables: Any) -> list:
    """收集所有敏感变量的真实值（供执行器擦除日志）。"""
    values = []
    for spec in normalize_variables(variables).values():
        if spec.get("sensitive"):
            value = spec.get("value")
            if value is not None and str(value) != "":
                values.append(value)
    return values


def mask_variables(variables: Any) -> dict:
    """返回掩码后的变量表：敏感项的值替换为 ``SENSITIVE_MASK``。

    输出结构与归一化结构一致（``value`` + ``sensitive``），前端据此渲染
    掩码与「敏感」标记，且永远拿不到敏感项明文。
    """
    masked = {}
    for key, spec in normalize_variables(variables).items():
        masked[key] = {
            "value": SENSITIVE_MASK if spec.get("sensitive") else spec.get("value"),
            "sensitive": bool(spec.get("sensitive")),
        }
    return masked


def resolve_dependency(name: str, constraint: str) -> Optional[dict]:
    """解析单个依赖，返回 {name, constraint, resolved, latest, status}。"""
    versions = _PACKAGE_VERSIONS.get(name)
    if versions is None:
        return {"name": name, "constraint": constraint, "resolved": None,
                "latest": None, "status": "unknown",
                "message": "未知包（模拟仓库中不存在）"}
    latest = _latest(versions)
    candidates = [v for v in versions if _satisfies(v, constraint)]
    if not candidates:
        return {"name": name, "constraint": constraint, "resolved": None,
                "latest": latest, "status": "conflict",
                "message": f"没有满足 {constraint} 的版本"}
    return {"name": name, "constraint": constraint,
            "resolved": _latest(candidates), "latest": latest,
            "status": "resolved",
            "message": f"解析到 {_latest(candidates)}"}


class EnvironmentManager:
    """环境管理：包裹环境实体存储，提供依赖解析与工作区隔离。"""

    def __init__(self, registry, data_root: str):
        self.registry = registry
        self.data_root = data_root
        self._store = registry.store("environments")

    # -- CRUD -------------------------------------------------------------
    def create(self, project_id: str, payload: dict) -> dict:
        env = {
            "id": new_id("env"),
            "project_id": project_id,
            "name": payload.get("name", "未命名环境"),
            "description": payload.get("description", ""),
            "python_version": payload.get("python_version", "3.11"),
            "base_image": payload.get("base_image", "python:3.11-slim"),
            "variables": normalize_variables(payload.get("variables")),
            "dependencies": payload.get("dependencies") or [],
            "config": payload.get("config") or {
                "base_url": "http://mock.local",
                "latency_ms": 20,
                "fail_rate": 0.0,
            },
        }
        self._store.insert(env)
        self.ensure_workspace(env["id"])
        return env

    def list(self, project_id: str) -> list[dict]:
        return self._store.query(where=[("project_id", "eq", project_id)],
                                 order_by="created_at", order="asc")

    def get(self, env_id: str) -> Optional[dict]:
        return self._store.get(env_id)

    def update(self, env_id: str, patch: dict) -> Optional[dict]:
        patch = dict(patch)
        if "variables" in patch:
            existing = self.get(env_id)
            if existing is None:
                return None
            patch["variables"] = self._merge_variables(
                existing.get("variables"), patch["variables"])
        return self._store.update(env_id, patch)

    @staticmethod
    def _merge_variables(old_raw: Any, new_raw: Any) -> dict:
        """合并变量更新：值为掩码占位符表示「保留旧值，只改标记」。

        前端编辑敏感变量时输入框里只有掩码，若用户没有重新输入，提交回来
        的仍是掩码——这时必须保留库里原有的真实值，否则一次普通保存就会
        把口令覆盖成 ``******``。新变量或用户显式重输的值则按提交内容落库。
        """
        old = normalize_variables(old_raw)
        merged = {}
        for key, spec in normalize_variables(new_raw).items():
            if spec["value"] == SENSITIVE_MASK and key in old:
                merged[key] = {"value": old[key]["value"],
                               "sensitive": spec["sensitive"]}
            else:
                merged[key] = spec
        return merged

    def delete(self, env_id: str) -> bool:
        return self._store.delete(env_id)

    # -- 对外视图（敏感值掩码） --------------------------------------------
    def public_view(self, env: Optional[dict]) -> Optional[dict]:
        """环境的安全展示视图：敏感变量值替换为掩码，绝不回显明文。"""
        if env is None:
            return None
        out = dict(env)
        out["variables"] = mask_variables(env.get("variables"))
        return out

    def export(self, env_id: str) -> Optional[dict]:
        """导出环境定义（JSON 文档）。敏感变量值同样只输出掩码。"""
        env = self.get(env_id)
        if env is None:
            return None
        return {
            "type": "environment-export",
            "version": 1,
            "exported_at": time.time(),
            "environment": {
                "id": env.get("id"),
                "project_id": env.get("project_id"),
                "name": env.get("name"),
                "description": env.get("description", ""),
                "python_version": env.get("python_version"),
                "base_image": env.get("base_image"),
                "variables": mask_variables(env.get("variables")),
                "dependencies": env.get("dependencies") or [],
                "config": env.get("config") or {},
            },
        }

    # -- 环境差异对比 ------------------------------------------------------
    def diff(self, env_a_id: str, env_b_id: str) -> dict:
        """逐项对比两个环境的变量、依赖与运行参数。

        返回的对比结果可直接展示 / 导出留档：敏感变量只出现掩码，但
        「是否一致」的判断基于真实值，因此「以为一致其实不一致」的敏感项
        也能被标出来（显示为有差异，但看不到明文）。
        """
        env_a = self.get(env_a_id)
        env_b = self.get(env_b_id)
        if env_a is None or env_b is None:
            return {"error": "环境不存在"}

        sections = {
            "variables": _diff_variables(env_a, env_b),
            "dependencies": _diff_dependencies(env_a, env_b),
            "config": _diff_mapping(env_a.get("config") or {},
                                    env_b.get("config") or {}),
            "runtime": _diff_mapping(
                {"python_version": env_a.get("python_version"),
                 "base_image": env_a.get("base_image")},
                {"python_version": env_b.get("python_version"),
                 "base_image": env_b.get("base_image")}),
        }
        summary: dict[str, dict] = {}
        identical = True
        for name, items in sections.items():
            counts = {"added": 0, "removed": 0, "changed": 0, "same": 0}
            for item in items:
                counts[item["status"]] = counts.get(item["status"], 0) + 1
            counts["different"] = counts["added"] + counts["removed"] + counts["changed"]
            if counts["different"]:
                identical = False
            summary[name] = counts

        return {
            "a": {"id": env_a.get("id"), "name": env_a.get("name")},
            "b": {"id": env_b.get("id"), "name": env_b.get("name")},
            "identical": identical,
            "summary": summary,
            "variables": sections["variables"],
            "dependencies": sections["dependencies"],
            "config": sections["config"],
            "runtime": sections["runtime"],
            "compared_at": time.time(),
        }

    # -- 依赖解析 ---------------------------------------------------------
    def resolve(self, env_id: str) -> dict:
        env = self.get(env_id)
        if env is None:
            return {"error": "环境不存在"}
        resolved = [resolve_dependency(d["name"], d.get("constraint", "*"))
                    for d in env.get("dependencies", [])]
        ok_count = sum(1 for r in resolved if r["status"] == "resolved")
        conflict_count = sum(1 for r in resolved if r["status"] == "conflict")
        return {
            "env_id": env_id,
            "dependencies": resolved,
            "ok": conflict_count == 0,
            "resolved_count": ok_count,
            "conflict_count": conflict_count,
        }

    # -- 工作区隔离 -------------------------------------------------------
    def workspace_dir(self, env_id: str) -> str:
        return os.path.join(self.data_root, "envs", env_id, "workspace")

    def ensure_workspace(self, env_id: str) -> str:
        d = self.workspace_dir(env_id)
        os.makedirs(d, exist_ok=True)
        return d

    # -- 执行快照 ---------------------------------------------------------
    def snapshot(self, env_id: str) -> dict:
        """取环境执行快照：变量（真实值）+ 运行配置（供执行器使用）。

        这是唯一能看到敏感变量明文的出口，仅供执行器注入；同时附上
        ``sensitive_values``（敏感值列表），执行器用它擦除日志中的明文。
        """
        env = self.get(env_id)
        if env is None:
            return {"variables": {}, "config": {}, "sensitive_values": []}
        variables = normalize_variables(env.get("variables"))
        return {
            "variables": flat_variables(variables),
            "config": dict(env.get("config") or {}),
            "sensitive_values": sensitive_values(variables),
        }

    def to_executor_config(self, env_id: str) -> dict:
        snap = self.snapshot(env_id)
        cfg = dict(snap["config"])
        cfg["variables"] = snap["variables"]
        cfg["sensitive_values"] = snap["sensitive_values"]
        return cfg


# ---------------------------------------------------------------------------
# 差异对比（模块级纯函数，便于测试）
# ---------------------------------------------------------------------------

def _display_value(spec: Optional[dict]) -> Any:
    """对比结果里展示的变量值：敏感项给掩码，缺失给 None。"""
    if spec is None:
        return None
    return SENSITIVE_MASK if spec.get("sensitive") else spec.get("value")


def _diff_variables(env_a: dict, env_b: dict) -> list[dict]:
    """变量逐项对比。状态判定用真实值，输出值按各自敏感标记掩码。"""
    va = normalize_variables(env_a.get("variables"))
    vb = normalize_variables(env_b.get("variables"))
    rows = []
    for key in sorted(set(va) | set(vb)):
        sa, sb = va.get(key), vb.get(key)
        if sa is None:
            status = "added"      # 仅 B 有
        elif sb is None:
            status = "removed"    # 仅 A 有
        elif (sa.get("value") == sb.get("value")
              and bool(sa.get("sensitive")) == bool(sb.get("sensitive"))):
            status = "same"
        else:
            status = "changed"
        rows.append({
            "key": key,
            "status": status,
            "a": _display_value(sa),
            "b": _display_value(sb),
            "a_sensitive": bool(sa and sa.get("sensitive")),
            "b_sensitive": bool(sb and sb.get("sensitive")),
        })
    return rows


def _diff_dependencies(env_a: dict, env_b: dict) -> list[dict]:
    """依赖逐项对比（按包名对齐，比较版本约束）。"""
    da = {d.get("name"): d.get("constraint", "*")
          for d in env_a.get("dependencies") or []}
    db = {d.get("name"): d.get("constraint", "*")
          for d in env_b.get("dependencies") or []}
    rows = []
    for name in sorted(set(da) | set(db)):
        ca, cb = da.get(name), db.get(name)
        if ca is None:
            status = "added"
        elif cb is None:
            status = "removed"
        elif ca == cb:
            status = "same"
        else:
            status = "changed"
        rows.append({"name": name, "status": status, "a": ca, "b": cb})
    return rows


def _diff_mapping(ma: dict, mb: dict) -> list[dict]:
    """通用键值对比（运行参数 / 运行时信息）。"""
    rows = []
    for key in sorted(set(ma) | set(mb)):
        if key not in ma:
            status = "added"
        elif key not in mb:
            status = "removed"
        elif ma.get(key) == mb.get(key):
            status = "same"
        else:
            status = "changed"
        rows.append({"key": key, "status": status,
                     "a": ma.get(key), "b": mb.get(key)})
    return rows
