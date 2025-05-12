#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NullHandshake - Logging Module

This module handles logging for the framework.
"""

import os
import logging
import datetime
from rich.logging import RichHandler
from typing import Optional

def setup_logger(debug: bool = False) -> logging.Logger:
    """
    Set up and configure the logger.
    
    Args:
        debug (bool): Enable debug logging if True
        
    Returns:
        logging.Logger: Configured logger
    """
    # Set up log directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_dir = os.path.join(base_dir, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Generate log filename with timestamp
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    log_file = os.path.join(log_dir, f'nullhandshake_{timestamp}.log')
    
    # Set log level
    log_level = logging.DEBUG if debug else logging.INFO
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            RichHandler(rich_tracebacks=True),
            logging.FileHandler(log_file)
        ]
    )
    
    # Create logger
    logger = logging.getLogger('nullhandshake')
    
    if debug:
        logger.debug("Debug logging enabled")
    
    logger.info(f"Log file: {log_file}")
    
    return logger
