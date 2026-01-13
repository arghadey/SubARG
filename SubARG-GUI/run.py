#!/usr/bin/env python3
"""
SubARG GUI - Main Application Entry Point
"""

from app import create_app, socketio

app = create_app()

if __name__ == '__main__':
    print("""
    ███████╗██╗   ██╗██████╗  █████╗ ██████╗  ██████╗ 
    ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝ 
    ███████╗██║   ██║██████╔╝███████║██████╔╝██║  ███╗
    ╚════██║██║   ██║██╔══██╗██╔══██║██╔══██╗██║   ██║
    ███████║╚██████╔╝██████╔╝██║  ██║██║  ██║╚██████╔╝
    ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  
    
    SubARG GUI v1.0
    Author: Argha Dey (Mr. Ghost)
    
    Starting web server on http://0.0.0.0:5000
    """)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
