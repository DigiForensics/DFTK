# Copyright 2026 DyNooob @ DigiForensics
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Public API for Digital Forensics Toolkit."""
from __future__ import annotations

from typing import Any

from .catalog import load_builtin_tools
from .core.registry import ToolRegistry, registry
from .core.safety import SafetyPolicy

__version__ = "3.3.0"


def get_registry() -> ToolRegistry:
    """Load built-ins and return the process-wide registry.

    This is the stable integration entry point for Agent runtimes. Callers do
    not need to import internal primitive modules for registration side effects.
    """
    load_builtin_tools()
    return registry


def run_tool(name: str, params: dict[str, Any], *, policy: SafetyPolicy | None = None):
    """Run a registered tool through the standard safety/Observation boundary."""
    return get_registry().run(name, params, policy)


__all__ = [
    "__version__",
    "get_registry",
    "load_builtin_tools",
    "registry",
    "run_tool",
    "SafetyPolicy",
    "ToolRegistry",
]
