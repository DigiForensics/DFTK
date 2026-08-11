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
