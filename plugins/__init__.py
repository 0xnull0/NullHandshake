#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NullHandshake - Plugins Package

This package contains all available plugins for the framework.
"""

# Import plugins to make them available
from core.plugin_manager import PluginInterface

# Import all plugins - using the renamed plugin files to avoid import conflicts
from plugins.credential_harvester_plugin import CredentialHarvester
from plugins.wifi_recon_plugin import WiFiRecon
from plugins.evil_twin_plugin import EvilTwin
from plugins.wpa_handshake_plugin import WPAHandshake

__all__ = [
    'PluginInterface',
    'CredentialHarvester',
    'WiFiRecon',
    'EvilTwin',
    'WPAHandshake'
]
