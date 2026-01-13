from flask import Blueprint, render_template, request, jsonify, send_file, send_from_directory
from flask_socketio import emit
import os
import json
import uuid
from datetime import datetime
from .subarg import SubARG  # CHANGED: Use relative import
import threading
from app import socketio

main = Blueprint('main', __name__)

# Store active scans
active_scans = {}

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    
    scan_id = str(uuid.uuid4())
    target = data.get('target')
    target_list = data.get('target_list')
    output_format = data.get('output_format', 'txt')
    custom_filename = data.get('filename')
    
    # Create scan job
    scan_info = {
        'id': scan_id,
        'target': target,
        'status': 'initializing',
        'progress': 0,
        'results': [],
        'output_file': None,
        'start_time': datetime.now().isoformat(),
        'end_time': None
    }
    
    active_scans[scan_id] = scan_info
    
    # Start scan in background
    thread = threading.Thread(target=run_scan, args=(scan_id, target, target_list, output_format, custom_filename))
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id, 'message': 'Scan started'})

def run_scan(scan_id, target, target_list, output_format, custom_filename):
    try:
        active_scans[scan_id]['status'] = 'running'
        socketio.emit('scan_update', {'scan_id': scan_id, 'status': 'running', 'progress': 0})
        
        # Initialize SubARG
        subarg = SubARG()
        
        # Set parameters
        if target_list:
            subarg.set_target_list(target_list)
        else:
            subarg.set_target(target)
        
        subarg.set_output_format(output_format)
        if custom_filename:
            subarg.set_output_file(custom_filename)
        
        # Run scan with progress callbacks
        def progress_callback(tool, percentage):
            active_scans[scan_id]['progress'] = percentage
            socketio.emit('scan_update', {
                'scan_id': scan_id,
                'status': 'running',
                'progress': percentage,
                'current_tool': tool
            })
        
        def result_callback(subdomain, tool):
            active_scans[scan_id]['results'].append({'subdomain': subdomain, 'tool': tool})
            socketio.emit('new_result', {
                'scan_id': scan_id,
                'subdomain': subdomain,
                'tool': tool
            })
        
        results = subarg.run(progress_callback=progress_callback, result_callback=result_callback)
        
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['end_time'] = datetime.now().isoformat()
        active_scans[scan_id]['output_file'] = results.get('output_file')
        active_scans[scan_id]['total_subdomains'] = len(results.get('subdomains', []))
        
        socketio.emit('scan_complete', {
            'scan_id': scan_id,
            'status': 'completed',
            'output_file': results.get('output_file'),
            'total_subdomains': len(results.get('subdomains', []))
        })
        
    except Exception as e:
        active_scans[scan_id]['status'] = 'failed'
        active_scans[scan_id]['error'] = str(e)
        socketio.emit('scan_error', {
            'scan_id': scan_id,
            'error': str(e),
            'status': 'failed'
        })

@main.route('/api/scan/<scan_id>')
def get_scan_status(scan_id):
    if scan_id in active_scans:
        return jsonify(active_scans[scan_id])
    return jsonify({'error': 'Scan not found'}), 404

@main.route('/api/scans')
def get_all_scans():
    return jsonify(list(active_scans.values()))

@main.route('/api/results')
def get_recent_results():
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
    results = []
    
    for filename in os.listdir(results_dir)[-10:]:  # Get last 10 results
        filepath = os.path.join(results_dir, filename)
        if os.path.isfile(filepath):
            stats = os.stat(filepath)
            results.append({
                'filename': filename,
                'path': f'/api/download/{filename}',
                'size': stats.st_size,
                'created': datetime.fromtimestamp(stats.st_ctime).isoformat()
            })
    
    return jsonify(results)

@main.route('/api/download/<filename>')
def download_file(filename):
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
    return send_from_directory(results_dir, filename, as_attachment=True)

@main.route('/api/installed_tools')
def get_installed_tools():
    tools = SubARG().check_installed_tools()
    return jsonify(tools)

@socketio.on('connect')
def handle_connect():
    emit('connected', {'message': 'Connected to SubARG WebSocket'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')
