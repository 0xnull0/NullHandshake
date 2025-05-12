#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import subprocess
import json
import threading
import time
from flask import Flask, render_template, request, jsonify, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24).hex())
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Class to run NullHandshake commands
class NullHandshakeRunner:
    @staticmethod
    def run_command(command):
        """Run a command in NullHandshake and capture the output."""
        process = subprocess.Popen(
            ['python', 'run.py', command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate()
        
        # Filter out the banner and prompt
        output_lines = stdout.split('\n')
        # Keep only relevant output (remove banner, welcome message, and prompts)
        filtered_output = '\n'.join([line for line in output_lines if 
                                    not line.strip().startswith('[nullhandshake]') and
                                    'NullHandshake - Wireless Network Post-Exploitation Framework' not in line])
        
        return filtered_output
    
    @staticmethod
    def get_plugins():
        """Get a list of available plugins with their descriptions."""
        plugins_raw = NullHandshakeRunner.run_command('plugins')
        
        # Parse the plugins output to extract plugin information
        plugin_info = []
        
        # Define plugin details with icons and descriptions
        plugin_details = {
            'wifirecon': {
                'name': 'WiFi Recon',
                'description': 'Scan for wireless networks, monitor traffic, and analyze WiFi data.',
                'icon': 'fas fa-broadcast-tower',
                'color': 'text-info',
                'background': 'linear-gradient(135deg, #0396FF 0%, #0D47A1 100%)'
            },
            'credentialharvester': {
                'name': 'Credential Harvester',
                'description': 'Extract stored WiFi credentials from various operating systems.',
                'icon': 'fas fa-key',
                'color': 'text-success',
                'background': 'linear-gradient(135deg, #26D0CE 0%, #1A2980 100%)'
            },
            'eviltwin': {
                'name': 'Evil Twin',
                'description': 'Deploy rogue access points that mimic legitimate networks.',
                'icon': 'fas fa-clone',
                'color': 'text-danger',
                'background': 'linear-gradient(135deg, #FF4E50 0%, #F9D423 100%)'
            },
            'wpahandshake': {
                'name': 'WPA Handshake',
                'description': 'Automate deauthentication attacks and capture WPA handshakes.',
                'icon': 'fas fa-lock',
                'color': 'text-warning',
                'background': 'linear-gradient(135deg, #B24592 0%, #F15F79 100%)'
            }
        }
        
        # Add each plugin to the list
        for key, details in plugin_details.items():
            plugin_info.append({
                'id': key,
                'name': details['name'],
                'description': details['description'],
                'icon': details['icon'],
                'color': details['color'],
                'background': details['background']
            })
            
        return plugin_info

# Routes
@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    # Get available plugins
    plugins = NullHandshakeRunner.get_plugins()
    
    return render_template('dashboard.html', plugins=plugins)

@app.route('/command', methods=['POST'])
def run_command():
    command = request.form.get('command')
    if not command:
        return jsonify({'error': 'No command provided'}), 400
    
    output = NullHandshakeRunner.run_command(command)
    return jsonify({'output': output})

@app.route('/plugin/<plugin_id>')
def plugin_view(plugin_id):
    # Get available plugins to find the current one
    plugins = NullHandshakeRunner.get_plugins()
    current_plugin = next((p for p in plugins if p['id'] == plugin_id), None)
    
    if not current_plugin:
        return redirect(url_for('dashboard'))
    
    # Get plugin help information
    NullHandshakeRunner.run_command(f'load {plugin_id}')
    help_output = NullHandshakeRunner.run_command('plugin_help')
    
    return render_template('plugin.html', 
                           plugin=current_plugin, 
                           plugins=plugins,
                           help_output=help_output)

@app.route('/scan')
def scan_view():
    # Run the WiFi scan command and return the results
    # This is a placeholder that would normally use the WiFi recon plugin
    scan_output = NullHandshakeRunner.run_command('load wifirecon') + '\n' + \
                 NullHandshakeRunner.run_command('scan') + '\n' + \
                 NullHandshakeRunner.run_command('show_networks')
    
    plugins = NullHandshakeRunner.get_plugins()
    
    return render_template('scan.html', 
                           plugins=plugins,
                           scan_output=scan_output)

@app.route('/help')
def help_page():
    help_output = NullHandshakeRunner.run_command('help')
    plugins = NullHandshakeRunner.get_plugins()
    
    return render_template('help.html', 
                          help_output=help_output,
                          plugins=plugins)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)