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

from dataclasses import dataclass
from .models import SafetyLevel

class SafetyViolation(RuntimeError):
    pass

@dataclass
class SafetyPolicy:
    max_level: SafetyLevel = SafetyLevel.READ_ONLY
    allow_network: bool = False

    def check(self, *, level: SafetyLevel, network: bool = False) -> None:
        if level > self.max_level:
            raise SafetyViolation(
                f"tool safety level {level.name} exceeds allowed {self.max_level.name}"
            )
        if network and not self.allow_network:
            raise SafetyViolation("network access is disabled by policy")
