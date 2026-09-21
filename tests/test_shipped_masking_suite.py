"""Run the shipped MaskingTestsMixin against a real ecsctx setup.

Consumers inherit this suite, so CI has to run it here: a break in
ecsctx.contrib.django.testing would otherwise ship green.

The class builds the same setup a project has — get_logging_config() applied
with dictConfig, setup_logging(), then the install_maskers() sweep an
AppConfig.ready() would do — on an isolated logging tree that is restored
afterwards, since logging is process-wide and nothing else resets it.
"""

import logging

from django.test import SimpleTestCase, override_settings

from ecsctx.contrib.django import get_logging_config, setup_logging
from ecsctx.contrib.django.testing import MaskingTestsMixin
from ecsctx.masking import install_maskers

PROJECT_LOGGING = get_logging_config(use_cid_filter=False)


@override_settings(
    LOGGING=PROJECT_LOGGING,
    ECSCTX_SKIP_MASKING_CHECK=False,
    ECSCTX_MASKING_CHECK_SKIP_ENVS=[],
)
class TestShippedMaskingSuite(MaskingTestsMixin, SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import logging.config

        manager = logging.Logger.manager
        cls._saved_loggers = dict(manager.loggerDict)
        cls._saved_root = (list(logging.root.handlers), logging.root.level)

        manager.loggerDict.clear()
        logging.root.handlers = []
        logging.config.dictConfig(PROJECT_LOGGING)
        setup_logging(capture_warnings=False)
        install_maskers(PROJECT_LOGGING)

    @classmethod
    def tearDownClass(cls):
        import structlog

        manager = logging.Logger.manager
        manager.loggerDict.clear()
        manager.loggerDict.update(cls._saved_loggers)
        logging.root.handlers, logging.root.level = cls._saved_root
        structlog.reset_defaults()
        super().tearDownClass()
