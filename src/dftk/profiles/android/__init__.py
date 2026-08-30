# Android application profiles — DFTK 3.5.0.
#
# 3.5.0 ships only the generic messaging demo profile, used to validate the
# ArtifactProfile model end-to-end. Vendor-specific IM parsers (WeChat, QQ,
# WeCom, DingTalk, Lark) are planned for 3.6 and will be added as profile *data*
# rather than bespoke parser code.

from .generic_messaging import PROFILE  # noqa: F401

__all__ = ["PROFILE"]
