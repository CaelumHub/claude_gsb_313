"""环境管理：配置、依赖解析、工作区隔离。

平台支持一个项目维护多套测试环境（如 dev / staging / prod），每套环境有：

- ``variables``     环境变量（执行时注入用例变量表）。可通过
                    ``sensitive_variables`` 把其中一部分（如数据库口令）
                    标记为**敏感项**：页面 / 导出 / 差异对比只显示掩码，
                    执行日志与结果落盘前也会按原值脱敏，但执行时照常注入明文
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

依赖解析为模拟实现：内置一个常见包的最新版本表，按语义化版本约束做简单
匹配（支持 ``>=`` / ``==`` / ``<`` / 无约束取最新）。
"""

from __future__ import annotations

import os
import re
import time
from typing import Any, Callable, Optional

from .models import new_id

# 敏感变量在任何「对外出口」（页面 / 导出 / 差异对比 / 日志）中的统一掩码。
# 该常量同时是编辑回写时的「保持原值」哨兵：前端把敏感值留成掩码原样提交，
# 后端识别后不落盘掩码，而是保留数据库里的原明文。
SENSITIVE_MASK = "******"


# ---------------------------------------------------------------------------
# 敏感值脱敏（执行日志 / 结果 / 导出等所有「带出去」的出口共用）
# ---------------------------------------------------------------------------

def _redact_string(text: str, secrets: list) -> str:
    """把字符串中出现的敏感原值整体替换为掩码（长的先替，避免前缀遮蔽）。"""
    out = str(text)
    for secret in sorted(secrets, key=lambda s: len(str(s)), reverse=True):
        token = str(secret)
        if token and token in out:
            out = out.replace(token, SENSITIVE_MASK)
    return out


def make_redactor(secrets: Any) -> Callable[[Any], Any]:
    """根据一组敏感原值构造脱敏函数。

    递归处理 dict / list；标量按原始类型比较相等（数字、布尔、None 也能
    命中），字符串做子串替换，确保敏感值无论是整条出现还是混在日志文本里
    都不会漏出去。空串不作为敏感值（会误伤一切）。
    """
    tokens = []
    for s in secrets or []:
        if s is None or s == "":
            continue
        if s not in tokens:
            tokens.append(s)

    def _redact(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: _redact(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_redact(v) for v in value]
        if isinstance(value, tuple):
            return tuple(_redact(v) for v in value)
        if isinstance(value, str):
            return _redact_string(value, tokens)
        for token in tokens:
            if type(token) is not str and value == token:
                return SENSITIVE_MASK
        return value

    return _redact


def redact_secrets(value: Any, secrets: Any) -> Any:
    """便捷封装：用一组敏感原值脱敏任意结构。"""
    return make_redactor(secrets)(value)


def sensitive_secret_map(variables: dict, sensitive_keys: Any) -> dict:
    """从变量表里取出敏感项的 键 -> 明文原值（供执行期脱敏日志使用）。"""
    keys = set(sensitive_keys or [])
    return {k: variables[k] for k in keys if k in variables}


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
        variables = payload.get("variables") or {}
        env = {
            "id": new_id("env"),
            "project_id": project_id,
            "name": payload.get("name", "未命名环境"),
            "description": payload.get("description", ""),
            "python_version": payload.get("python_version", "3.11"),
            "base_image": payload.get("base_image", "python:3.11-slim"),
            "variables": variables,
            # 敏感变量名清单：值本身仍存在 variables 里（执行时照常注入），
            # 但任何对外出口都只显示掩码。
            "sensitive_variables": self._normalize_sensitive(
                payload.get("sensitive_variables"), variables),
            "dependencies": payload.get("dependencies") or [],
            "config": payload.get("config") or {
                "base_url": "http://mock.local",
                "latency_ms": 20,
                "fail_rate": 0.0,
            },
            "created_at": time.time(),
        }
        self._store.insert(env)
        self.ensure_workspace(env["id"])
        return env

    @staticmethod
    def _sensitive_keys(env: dict) -> list[str]:
        keys = env.get("sensitive_variables") or []
        return [k for k in keys if k in (env.get("variables") or {})]

    @staticmethod
    def _normalize_sensitive(keys: Any, variables: dict) -> list[str]:
        """规整敏感键清单：去重、保序、只保留变量表里实际存在的键。"""
        if not isinstance(keys, list):
            return []
        out: list[str] = []
        for k in keys:
            k = str(k)
            if k in variables and k not in out:
                out.append(k)
        return out

    def public_view(self, env: Optional[dict]) -> Optional[dict]:
        """返回环境的对外视图：敏感变量值替换为掩码，绝不回显明文。

        页面列表 / 详情、环境导出、差异对比的取值都走这里（或其批量版本），
        保证不会换个接口就把明文翻出来。
        """
        if env is None:
            return None
        view = dict(env)
        variables = dict(env.get("variables") or {})
        for key in self._sensitive_keys(env):
            variables[key] = SENSITIVE_MASK
        view["variables"] = variables
        return view

    def list_public(self, project_id: str) -> list[dict]:
        return [self.public_view(e) for e in self.list(project_id)]

    def list(self, project_id: str) -> list[dict]:
        return self._store.query(where=[("project_id", "eq", project_id)],
                                 order_by="created_at", order="asc")

    def get(self, env_id: str) -> Optional[dict]:
        return self._store.get(env_id)

    def update(self, env_id: str, patch: dict) -> Optional[dict]:
        env = self._store.get(env_id)
        if env is None:
            return None
        patch = dict(patch)

        # 敏感标记可以随 variables 一起改，也可以单独改
        sensitive_present = "sensitive_variables" in patch
        variables_present = "variables" in patch
        if variables_present:
            new_variables = dict(patch["variables"] or {})
            if sensitive_present:
                new_sensitive = self._normalize_sensitive(
                    patch["sensitive_variables"], new_variables)
            else:
                new_sensitive = self._normalize_sensitive(
                    env.get("sensitive_variables"), new_variables)
            # 仍被标记为敏感的项，前端若提交的是掩码哨兵（用户没改），
            # 保留库里的原明文，避免把掩码当真值存进去。
            old_variables = env.get("variables") or {}
            for key in new_sensitive:
                if new_variables.get(key) == SENSITIVE_MASK and key in old_variables:
                    new_variables[key] = old_variables[key]
            patch["variables"] = new_variables
            patch["sensitive_variables"] = new_sensitive
        elif sensitive_present:
            patch["sensitive_variables"] = self._normalize_sensitive(
                patch["sensitive_variables"], env.get("variables") or {})

        return self._store.update(env_id, patch)

    def delete(self, env_id: str) -> bool:
        return self._store.delete(env_id)

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
        """取环境执行快照：变量 + 运行配置（供执行器使用，含明文）。

        .. note::
            本方法返回**真实明文**，仅供引擎内部执行注入，禁止直接对外暴露。
            ``_sensitive_variables`` 随快照下发，执行器据此脱敏日志。
        """
        env = self.get(env_id)
        if env is None:
            return {"variables": {}, "config": {}}
        return {
            "variables": dict(env.get("variables") or {}),
            "config": dict(env.get("config") or {}),
            "sensitive_variables": self._sensitive_keys(env),
        }

    def to_executor_config(self, env_id: str) -> dict:
        snap = self.snapshot(env_id)
        cfg = dict(snap["config"])
        cfg["variables"] = snap["variables"]
        # 以下划线前缀挂内部字段，执行器逻辑与模拟目标均不消费它
        cfg["_sensitive_variables"] = snap.get("sensitive_variables", [])
        return cfg

    # -- 导出（敏感值掩码） -----------------------------------------------
    _EXPORT_FIELDS = ("name", "description", "python_version", "base_image",
                      "variables", "sensitive_variables", "dependencies", "config")

    def export(self, env_id: str) -> Optional[dict]:
        """导出环境为可留档的 JSON 结构。

        敏感变量的值一律是掩码，只保留键名与「该变量敏感」这一事实，
        导出件可安全外发 / 存档，不能被用来还原口令。
        """
        env = self.get(env_id)
        if env is None:
            return None
        view = self.public_view(env)
        return {
            "format": "test-platform/environment@1",
            "exported_at": time.time(),
            "environment": {k: view.get(k) for k in self._EXPORT_FIELDS},
            "note": "敏感变量已掩码（******），导出件不含明文",
        }

    # -- 环境差异对比 -----------------------------------------------------
    def diff(self, base_id: str, target_id: str) -> dict:
        """逐项对比两个环境：元信息 / 变量 / 依赖 / 运行参数。

        差异状态用明文比较（保证「值其实不同」不会因为两边都显示掩码而被
        误判为一致），但返回给前端的值全部走掩码视图。
        """
        base, target = self.get(base_id), self.get(target_id)
        if base is None or target is None:
            missing = base_id if base is None else target_id
            return {"error": f"环境不存在: {missing}"}

        return {
            "base": {"id": base["id"], "name": base.get("name", "")},
            "target": {"id": target["id"], "name": target.get("name", "")},
            "generated_at": time.time(),
            "variables": self._diff_variables(base, target),
            "dependencies": self._diff_dependencies(base, target),
            "config": self._diff_config(base, target),
            "meta": self._diff_meta(base, target),
            "sensitive_masked": True,
        }

    def _diff_variables(self, base: dict, target: dict) -> list[dict]:
        sensitive = set((base.get("sensitive_variables") or []) +
                        (target.get("sensitive_variables") or []))
        bv, tv = base.get("variables") or {}, target.get("variables") or {}
        rows = []
        for key in sorted(set(bv) | set(tv)):
            in_b, in_t = key in bv, key in tv
            if in_b and in_t:
                status = "same" if bv[key] == tv[key] else "changed"
            elif in_b:
                status = "removed"
            else:
                status = "added"
            is_sensitive = key in sensitive
            rows.append({
                "key": key,
                # 敏感项只给掩码；非敏感项给真实值（对比本来就是要看差异）
                "base_value": SENSITIVE_MASK if is_sensitive else bv.get(key),
                "target_value": SENSITIVE_MASK if is_sensitive else tv.get(key),
                "status": status,
                "sensitive": is_sensitive,
            })
        return rows

    @staticmethod
    def _dep_map(env: dict) -> dict[str, dict]:
        return {d.get("name"): d for d in (env.get("dependencies") or [])
                if d.get("name")}

    def _diff_dependencies(self, base: dict, target: dict) -> list[dict]:
        bd, td = self._dep_map(base), self._dep_map(target)
        rows = []
        for name in sorted(set(bd) | set(td)):
            in_b, in_t = name in bd, name in td
            if in_b and in_t:
                cb, ct = bd[name].get("constraint", "*"), td[name].get("constraint", "*")
                status = "same" if cb == ct else "changed"
                base_c, target_c = cb, ct
            elif in_b:
                status, base_c, target_c = "removed", bd[name].get("constraint", "*"), None
            else:
                status, base_c, target_c = "added", None, td[name].get("constraint", "*")
            rows.append({"name": name, "base_constraint": base_c,
                         "target_constraint": target_c, "status": status})
        return rows

    def _diff_config(self, base: dict, target: dict) -> list[dict]:
        bc, tc = base.get("config") or {}, target.get("config") or {}
        rows = []
        for key in sorted(set(bc) | set(tc)):
            in_b, in_t = key in bc, key in tc
            if in_b and in_t:
                status = "same" if bc[key] == tc[key] else "changed"
            elif in_b:
                status = "removed"
            else:
                status = "added"
            rows.append({"key": key, "base_value": bc.get(key),
                         "target_value": tc.get(key), "status": status})
        return rows

    def _diff_meta(self, base: dict, target: dict) -> list[dict]:
        rows = []
        for label, key in (("Python 版本", "python_version"), ("基础镜像", "base_image"),
                           ("描述", "description")):
            bv, tv = base.get(key, ""), target.get(key, "")
            rows.append({"label": label, "key": key, "base_value": bv,
                         "target_value": tv, "status": "same" if bv == tv else "changed"})
        return rows
